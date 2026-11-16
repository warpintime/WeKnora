package googledrive

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
)

type recorder struct {
	items                    []types.FetchedItem
	checkpoints              []*types.SyncCursor
	failEmit, failCheckpoint bool
}

func (h *recorder) Emit(_ context.Context, item types.FetchedItem) error {
	if h.failEmit {
		return errors.New("ingest failed")
	}
	h.items = append(h.items, item)
	return nil
}

func (h *recorder) Checkpoint(_ context.Context, cur *types.SyncCursor) error {
	if h.failCheckpoint {
		return errors.New("checkpoint failed")
	}
	h.checkpoints = append(h.checkpoints, cur)
	return nil
}

func byID(items []types.FetchedItem) map[string]types.FetchedItem {
	out := make(map[string]types.FetchedItem, len(items))
	for _, item := range items {
		out[strings.TrimPrefix(item.ExternalID, "google_drive:")] = item
	}
	return out
}

func TestFirstSyncMirrorsFoldersExportsDocsAndSkipsUnsupported(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.folder("sub", "Sub: 2026", "docs")
	f.add("pdf", "说明.pdf", "docs", "pdf body")
	f.doc("gdoc", "Plan", "sub", "# Plan")
	f.add("zip", "archive.zip", "docs", "zip")
	f.put("form", &fakeFile{name: "Form", mime: "application/vnd.google-apps.form", parent: "docs"})
	f.put("link", &fakeFile{name: "Shortcut.pdf", mime: mimeShortcut, parent: "docs"})
	f.put("bin", &fakeFile{name: "trashed.pdf", mime: "application/pdf", parent: "docs", trashed: true})
	f.pageSize = 1

	items, cur, err := f.connector().FetchIncremental(t.Context(), f.config("docs"), nil)
	if err != nil || len(items) != 2 {
		t.Fatalf("first sync = %+v, %v", items, err)
	}
	got := byID(items)
	if pdf := got["pdf"]; pdf.FileName != "Google Drive/Docs/说明.pdf" || string(pdf.Content) != "pdf body" ||
		pdf.Metadata["channel"] != types.ChannelGoogleDrive || pdf.SourceResourceID != "docs" {
		t.Fatalf("binary item = %+v", pdf)
	}
	if doc := got["gdoc"]; doc.FileName != "Google Drive/Docs/Sub_ 2026/Plan.md" ||
		doc.ContentType != "text/markdown" || string(doc.Content) != "# Plan" {
		t.Fatalf("exported item = %+v", doc)
	}
	state, err := decodeCursor(cur)
	if err != nil || len(state.Files) != 2 || state.Scope == "" || state.FullSync {
		t.Fatalf("cursor = %+v, %v", state, err)
	}
}

func TestIncrementalDetectsEditsMovesRenamesAndDeletions(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.folder("archive", "Archive", "docs")
	f.add("a", "a.pdf", "docs", "a")
	f.add("b", "b.pdf", "docs", "b")
	f.add("c", "c.pdf", "docs", "c")
	f.doc("d", "Notes", "docs", "v1")
	c, cfg := f.connector(), f.config("docs")
	_, cur, err := c.FetchIncremental(t.Context(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// A touch that leaves the bytes alone is not a new version of a binary file.
	f.edit("a", func(file *fakeFile) { file.modified = "2026-11-01T00:00:00Z" })
	items, next, err := c.FetchIncremental(t.Context(), cfg, cur)
	if err != nil || len(items) != 0 || f.count("download:a") != 1 {
		t.Fatalf("unchanged = %+v, %v", items, err)
	}

	f.edit("a", func(file *fakeFile) { file.body = []byte("a2") })
	f.edit("b", func(file *fakeFile) { file.parent = "archive" })
	f.edit("d", func(file *fakeFile) { file.modified, file.body = "2026-11-02T00:00:00Z", []byte("v2") })
	f.remove("c")
	items, _, err = c.FetchIncremental(t.Context(), cfg, next)
	if err != nil || len(items) != 4 {
		t.Fatalf("changes = %+v, %v", items, err)
	}
	got := byID(items)
	if string(got["a"].Content) != "a2" || got["b"].FileName != "Google Drive/Docs/Archive/b.pdf" ||
		string(got["d"].Content) != "v2" || !got["c"].IsDeleted || got["a"].IsDeleted || got["b"].IsDeleted {
		t.Fatalf("changes = %+v", got)
	}
	if last := items[len(items)-1]; !last.IsDeleted {
		t.Fatalf("deletions must follow additions: %+v", items)
	}
}

func TestDeletedSelectedRootDoesNotAbortTheSync(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("keep", "Keep", testMyDriveID)
	f.folder("gone", "Gone", testMyDriveID)
	f.folder("binned", "Binned", testMyDriveID)
	f.add("k", "k.pdf", "keep", "k")
	f.add("g", "g.pdf", "gone", "g")
	f.add("t", "t.pdf", "binned", "t")
	f.add("single", "single.pdf", testMyDriveID, "s")
	c, cfg := f.connector(), f.config("keep", "gone", "binned", "single")
	items, cur, err := c.FetchIncremental(t.Context(), cfg, nil)
	if err != nil || len(items) != 4 || byID(items)["single"].FileName != "Google Drive/single.pdf" {
		t.Fatalf("first sync = %+v, %v", items, err)
	}
	f.remove("gone")
	f.remove("g")
	f.remove("single")
	f.edit("binned", func(file *fakeFile) { file.trashed = true })
	f.add("k2", "k2.pdf", "keep", "k2")
	items, next, err := c.FetchIncremental(t.Context(), cfg, cur)
	if err != nil || len(items) != 4 {
		t.Fatalf("after root deletion = %+v, %v", items, err)
	}
	got := byID(items)
	if got["k2"].IsDeleted || !got["g"].IsDeleted || !got["t"].IsDeleted || !got["single"].IsDeleted {
		t.Fatalf("after root deletion = %+v", got)
	}
	if state, _ := decodeCursor(next); len(state.Files) != 2 {
		t.Fatalf("cursor after deletion = %+v", state.Files)
	}
}

func TestIncompleteTraversalNeverDeletesAndFailedDownloadsRetry(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.folder("sub", "Sub", "docs")
	f.add("a", "a.pdf", "docs", "a")
	f.add("b", "b.pdf", "sub", "b")
	c, cfg := f.connector(), f.config("docs")
	_, cur, err := c.FetchIncremental(t.Context(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	f.remove("a")
	f.fail("list:sub", 403, "insufficientFilePermissions", 0)
	h := &recorder{}
	if _, err = c.FetchStream(t.Context(), cfg, cur, h); !errors.Is(err, datasource.ErrFetchFailed) ||
		strings.Contains(err.Error(), testRefreshToken) {
		t.Fatalf("partial scan error = %v", err)
	}
	for _, item := range h.items {
		if item.IsDeleted {
			t.Fatal("deletion after an incomplete traversal")
		}
	}

	f.clear("list:sub")
	f.edit("b", func(file *fakeFile) { file.body = []byte("b2") })
	f.fail("download:b", 403, "cannotDownloadAbusiveFile", 0)
	items, next, err := c.FetchIncremental(t.Context(), cfg, cur)
	if err != nil || len(items) != 2 {
		t.Fatalf("per-file failure = %+v, %v", items, err)
	}
	failed := byID(items)["b"]
	if len(failed.Content) != 0 || failed.URL != "" || failed.Metadata["error_reason_code"] != reasonPermissionDenied ||
		failed.Metadata["error_reason_code_value"] != "403" || strings.Contains(failed.Metadata["error"], "secret") {
		t.Fatalf("error item = %+v", failed)
	}
	if state, _ := decodeCursor(next); state.Files["b"] != "" {
		t.Fatalf("failed file must be retried: %+v", state.Files)
	}
	f.clear("download:b")
	items, _, err = c.FetchIncremental(t.Context(), cfg, next)
	if err != nil || len(items) != 1 || string(items[0].Content) != "b2" {
		t.Fatalf("retry = %+v, %v", items, err)
	}
}

func TestFullSyncCheckpointsResumesAndKeepsTheDeletionBaseline(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	for i := 0; i < 55; i++ {
		f.add(fmt.Sprintf("f%02d", i), fmt.Sprintf("%02d.pdf", i), "docs", fmt.Sprint(i))
	}
	c, cfg := f.connector(), f.config("docs")
	_, cur, err := c.FetchIncremental(t.Context(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.remove("f00")
	// Interrupt the forced run before it has listed anything.
	f.fail("list:docs", 500, "backendError", 0)
	h := &recorder{}
	if _, err = c.FetchFullStream(t.Context(), cfg, cur, h); err == nil {
		t.Fatal("interrupted full sync succeeded")
	}
	if len(h.checkpoints) != 1 {
		t.Fatalf("an aborted run must save its state once: %d", len(h.checkpoints))
	}
	resumed, err := decodeCursor(h.checkpoints[0])
	if err != nil || !resumed.FullSync || len(resumed.FullSyncBaseline) != 55 || len(resumed.Files) != 0 {
		t.Fatalf("resume state = %+v, %v", resumed, err)
	}

	f.clear("list:docs")
	checkpoint := h.checkpoints[0]
	h = &recorder{}
	final, err := c.FetchFullStream(t.Context(), cfg, checkpoint, h)
	if err != nil || len(h.items) != 55 || !h.items[54].IsDeleted || h.items[54].ExternalID != "google_drive:f00" {
		t.Fatalf("resumed full sync = %d items, %v", len(h.items), err)
	}
	if len(h.checkpoints) < 3 {
		t.Fatalf("checkpoints = %d", len(h.checkpoints))
	}
	state, err := decodeCursor(final)
	if err != nil || state.FullSync || state.FullSyncBaseline != nil || len(state.Files) != 54 {
		t.Fatalf("final cursor = %+v, %v", state, err)
	}
}

func TestHandlerFailuresCancellationAndCredentialErrorsAbort(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.add("a", "a.pdf", "docs", "a")
	c, cfg := f.connector(), f.config("docs")

	if _, err := c.FetchStream(t.Context(), cfg, nil, &recorder{failEmit: true}); err == nil {
		t.Fatal("emit failure ignored")
	}
	if _, err := c.FetchStream(t.Context(), cfg, nil, &recorder{failCheckpoint: true}); err == nil {
		t.Fatal("checkpoint failure ignored")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.FetchStream(ctx, cfg, nil, &recorder{}); !errors.Is(err, datasource.ErrSyncCanceled) {
		t.Fatalf("canceled sync = %v", err)
	}

	before := f.count("download:a")
	f.fail("download:a", 403, "userRateLimitExceeded", 0)
	h := &recorder{}
	if _, err := c.FetchStream(t.Context(), cfg, nil, h); !isRateLimited(err) || len(h.items) != 0 {
		t.Fatalf("exhausted rate limit = %v, %+v", err, h.items)
	}
	if f.count("download:a")-before != maxAttempts {
		t.Fatalf("rate limit attempts = %d", f.count("download:a"))
	}
	f.clear("download:a")

	f.mu.Lock()
	f.tokenError = "invalid_grant"
	f.mu.Unlock()
	fresh := f.connector() // no cached access token
	_, err := fresh.FetchStream(t.Context(), cfg, nil, &recorder{})
	if !errors.Is(err, datasource.ErrInvalidCredentials) || strings.Contains(err.Error(), testClientSecret) {
		t.Fatalf("revoked grant = %v", err)
	}
}

func TestTransientErrorsRetryAndRevokedAccessTokensRefresh(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.add("a", "a.pdf", "docs", "a")
	c, cfg := f.connector(), f.config("docs")
	f.fail("list:docs", 429, "rateLimitExceeded", 2)
	f.fail("download:a", 503, "backendError", 1)
	items, cur, err := c.FetchIncremental(t.Context(), cfg, nil)
	if err != nil || len(items) != 1 || f.count("list:docs") != 3 || f.count("download:a") != 2 {
		t.Fatalf("retries = %+v, %v", items, err)
	}

	// Google invalidates the cached access token before its advertised expiry.
	f.mu.Lock()
	f.accessToken = "rotated-elsewhere"
	f.mu.Unlock()
	f.edit("a", func(file *fakeFile) { file.body = []byte("a2") })
	items, _, err = c.FetchIncremental(t.Context(), cfg, cur)
	if err != nil || len(items) != 1 || string(items[0].Content) != "a2" || f.count("unauthorized") != 1 {
		t.Fatalf("after token revocation = %+v, %v", items, err)
	}
}

func TestSizeLimitsEmptyFilesAndUndownloadableFiles(t *testing.T) {
	t.Setenv("MAX_FILE_SIZE_MB", "1")
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.add("big", "big.pdf", "docs", strings.Repeat("x", 1<<20+1))
	f.add("empty", "empty.pdf", "docs", "")
	f.doc("huge", "Huge", "docs", "x")
	f.add("locked", "locked.pdf", "docs", "l")
	f.edit("locked", func(file *fakeFile) { file.noDownload = true })
	f.fail("download:huge", 403, "exportSizeLimitExceeded", 0)
	items, cur, err := f.connector().FetchIncremental(t.Context(), f.config("docs"), nil)
	if err != nil || len(items) != 4 {
		t.Fatalf("items = %+v, %v", items, err)
	}
	want := map[string]string{
		"big": reasonFileTooLarge, "empty": reasonEmptyFile,
		"huge": reasonExportTooLarge, "locked": reasonPermissionDenied,
	}
	for id, item := range byID(items) {
		if item.Metadata["error_reason_code"] != want[id] || len(item.Content) != 0 {
			t.Fatalf("%s = %+v", id, item)
		}
	}
	if f.count("download:big") != 0 || f.count("download:locked") != 0 {
		t.Fatal("oversized or locked files must not be requested")
	}
	if state, _ := decodeCursor(cur); len(state.Files) != 0 {
		t.Fatalf("failed files must not be acknowledged: %+v", state.Files)
	}
}

func TestSharedDrivesSharedWithMeAndOverlappingSelections(t *testing.T) {
	f := newFakeDrive(t)
	f.put("team", &fakeFile{name: "Team", mime: mimeFolder, driveID: "team"})
	f.folder("specs", "Specs", "team")
	f.add("spec", "spec.pdf", "specs", "spec")
	f.put("gift", &fakeFile{name: "Gift", mime: mimeFolder, shared: true})
	f.add("inner", "inner.pdf", "gift", "inner")
	f.put("loose", &fakeFile{name: "loose.pdf", mime: "application/pdf", body: []byte("loose"), shared: true})

	// "specs" is selected twice: on its own and through its shared drive.
	items, _, err := f.connector().FetchIncremental(t.Context(), f.config("team", "specs", sharedWithMeID), nil)
	if err != nil || len(items) != 3 {
		t.Fatalf("items = %+v, %v", items, err)
	}
	got := byID(items)
	if got["inner"].FileName != "Google Drive/Shared with me/Gift/inner.pdf" ||
		got["loose"].FileName != "Google Drive/Shared with me/loose.pdf" || string(got["spec"].Content) != "spec" {
		t.Fatalf("items = %+v", got)
	}
	if f.count("download:spec") != 1 || f.count("list:specs") != 1 {
		t.Fatal("an overlapping selection must be traversed once")
	}
}

func TestSelectionCursorAndAuthorizationAreRequired(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	c := f.connector()
	if _, _, err := c.FetchIncremental(t.Context(), f.config(), nil); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("empty selection = %v", err)
	}
	injected := f.config("a' or '1")
	if _, _, err := c.FetchIncremental(t.Context(), injected, nil); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("query injection = %v", err)
	}
	unauthorized := f.config("docs")
	delete(unauthorized.Credentials, credRefreshToken)
	_, _, err := c.FetchIncremental(t.Context(), unauthorized, nil)
	if !errors.Is(err, datasource.ErrInvalidCredentials) {
		t.Fatalf("unauthorized sync = %v", err)
	}
	_, cur, err := c.FetchIncremental(t.Context(), f.config("docs"), nil)
	if err != nil {
		t.Fatal(err)
	}
	other := f.config("docs")
	other.Credentials[credAccountID] = "perm-2"
	if _, _, err := c.FetchIncremental(t.Context(), other, cur); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("account change = %v", err)
	}
	cur.ConnectorCursor["schema_version"] = 99
	_, _, err = c.FetchIncremental(t.Context(), f.config("docs"), cur)
	if !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("unknown cursor schema = %v", err)
	}
}
