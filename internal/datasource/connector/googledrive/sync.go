package googledrive

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/utils"
)

const (
	checkpointEvery     = 50
	maxTraversalEntries = 1000000
	maxTraversalDepth   = 256
)

var (
	errNotDownloadable = errors.New("google drive file cannot be downloaded by this account")
	errTraversalLimit  = errors.New("google drive traversal limit exceeded")
)

// folderRef is a folder waiting to be listed. dir is the chain of folder names
// from the selected root down to and including this folder.
type folderRef struct {
	id, driveID string
	dir         []string
}

type syncRun struct {
	ctx              context.Context
	client           *client
	h                datasource.StreamHandler
	cur              cursor
	seen, listed     map[string]bool
	limit            int64
	unsaved, scanned int
}

func (c *Connector) runSync(
	ctx context.Context, ds *types.DataSourceConfig, old *types.SyncCursor, h datasource.StreamHandler, full bool,
) (*types.SyncCursor, error) {
	cfg, err := parseAuthorizedConfig(ds)
	if err != nil {
		return nil, err
	}
	roots, err := selectedRoots(ds.ResourceIDs)
	if err != nil {
		return nil, err
	}
	cur, err := prepareCursor(old, cfg.scope(), full)
	if err != nil {
		return nil, err
	}
	r := &syncRun{
		ctx: ctx, client: c.newClient(cfg), h: h, cur: cur,
		seen: make(map[string]bool), listed: make(map[string]bool), limit: utils.GetMaxFileSize(), unsaved: 1,
	}
	defer r.client.close()
	for _, root := range roots {
		if err := r.scanRoot(root); err != nil {
			return nil, err
		}
	}
	if err := r.reconcile(); err != nil {
		return nil, err
	}
	return r.cur.toSyncCursor(), nil
}

func (r *syncRun) canceledOr(err error) error {
	if r.ctx.Err() != nil {
		return errors.Join(datasource.ErrSyncCanceled, r.ctx.Err())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(datasource.ErrSyncCanceled, err)
	}
	return err
}

func (r *syncRun) checkpoint() error {
	if err := r.canceledOr(nil); err != nil {
		return err
	}
	if err := r.h.Checkpoint(r.ctx, r.cur.toSyncCursor()); err != nil {
		return r.canceledOr(err)
	}
	r.unsaved = 0
	return nil
}

func (r *syncRun) mutated() error {
	r.unsaved++
	if r.unsaved >= checkpointEvery {
		return r.checkpoint()
	}
	return nil
}

// Source failures save successfully emitted progress. Handler failures return
// directly and never advance the cursor past the unsuccessful operation.
func (r *syncRun) abort(err error) error {
	if canceled := r.canceledOr(err); errors.Is(canceled, datasource.ErrSyncCanceled) {
		return canceled
	}
	if r.unsaved > 0 {
		if checkpointErr := r.checkpoint(); checkpointErr != nil {
			return errors.Join(err, checkpointErr)
		}
	}
	return err
}

func (r *syncRun) emit(item types.FetchedItem) error {
	if err := r.canceledOr(nil); err != nil {
		return err
	}
	return r.canceledOr(r.h.Emit(r.ctx, item))
}

// scanRoot syncs one selected resource. A selection that no longer exists, or
// sits in the trash, contributes nothing: the run continues and reconciliation
// removes the documents that came from it. Any other failure aborts, because
// an incomplete traversal must never be mistaken for deletions.
func (r *syncRun) scanRoot(root string) error {
	if err := r.canceledOr(nil); err != nil {
		return err
	}
	if root == sharedWithMeID {
		return r.walk(nil, root, sharedWithMeQuery, []string{"Shared with me"})
	}
	f, err := r.client.getFile(r.ctx, root)
	if err != nil {
		if statusOf(err) == http.StatusNotFound {
			return nil
		}
		return r.abort(mapListingError(err))
	}
	switch {
	case f.Trashed:
		return nil
	case !f.isFolder():
		return r.syncFile(f, nil, root)
	}
	return r.walk([]folderRef{{id: f.ID, driveID: f.DriveID, dir: []string{f.Name}}}, root, "", nil)
}

// walk lists folders depth-first. firstQuery, when set, seeds the traversal
// with a search that is not a folder listing (the "Shared with me" view).
func (r *syncRun) walk(stack []folderRef, root, firstQuery string, firstDir []string) error {
	if firstQuery != "" {
		children, err := r.listAll(firstQuery, "")
		if err != nil {
			return err
		}
		if stack, err = r.visit(children, firstDir, root, stack); err != nil {
			return err
		}
	}
	for len(stack) > 0 {
		folder := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if r.listed[folder.id] {
			continue // Reached through another selection, or a cyclic shortcut.
		}
		r.listed[folder.id] = true
		if len(folder.dir) > maxTraversalDepth {
			return r.abort(fmt.Errorf("%w: %w", datasource.ErrFetchFailed, errTraversalLimit))
		}
		children, err := r.listAll(childrenQuery(folder.id), folder.driveID)
		if err != nil {
			return err
		}
		if stack, err = r.visit(children, folder.dir, root, stack); err != nil {
			return err
		}
	}
	return nil
}

// listAll reads every page of a listing before any child is processed, so a
// page token never has to outlive the downloads of the previous page. A folder
// deleted between its parent's listing and its own is simply empty.
func (r *syncRun) listAll(query, driveID string) ([]file, error) {
	var out []file
	for pageToken := ""; ; {
		if err := r.canceledOr(nil); err != nil {
			return nil, err
		}
		files, next, err := r.client.list(r.ctx, query, driveID, pageToken)
		if err != nil {
			if statusOf(err) == http.StatusNotFound {
				return nil, nil
			}
			return nil, r.abort(mapListingError(err))
		}
		r.scanned += len(files)
		if r.scanned > maxTraversalEntries {
			return nil, r.abort(fmt.Errorf("%w: %w", datasource.ErrFetchFailed, errTraversalLimit))
		}
		out = append(out, files...)
		if next == "" {
			return out, nil
		}
		pageToken = next
	}
}

func (r *syncRun) visit(children []file, dir []string, root string, stack []folderRef) ([]folderRef, error) {
	for _, child := range children {
		if child.Trashed || child.isFolder() {
			continue
		}
		if err := r.syncFile(child, dir, root); err != nil {
			return nil, err
		}
	}
	for i := len(children) - 1; i >= 0; i-- {
		if child := children[i]; child.isFolder() && !child.Trashed {
			childDir := append(append(make([]string, 0, len(dir)+1), dir...), child.Name)
			stack = append(stack, folderRef{id: child.ID, driveID: child.DriveID, dir: childDir})
		}
	}
	return stack, nil
}

func (r *syncRun) syncFile(f file, dir []string, root string) error {
	if err := r.canceledOr(nil); err != nil {
		return err
	}
	name, ok := f.syncName()
	if !ok || r.seen[f.ID] {
		return nil
	}
	r.seen[f.ID] = true
	fileName := knowledgeFileName(dir, name)
	fp := fingerprint(f, fileName)
	if r.cur.Files[f.ID] == fp {
		return nil
	}
	body, err := []byte(nil), errNotDownloadable
	if f.downloadable() {
		body, err = r.client.content(r.ctx, f, r.limit)
	}
	item := r.identity(f, fileName, root)
	if err != nil {
		// Credentials, cancellation and quota affect every remaining file:
		// stop and keep the progress made so far.
		fatal := errors.Is(err, datasource.ErrInvalidCredentials) || isRateLimited(err) ||
			errors.Is(r.canceledOr(err), datasource.ErrSyncCanceled)
		if fatal {
			return r.abort(err)
		}
		code := fetchReason(err)
		item.Metadata["error"] = reasonText[code]
		item.Metadata["error_reason"] = reasonText[code]
		item.Metadata["error_reason_code"] = code
		if status := statusOf(err); status > 0 {
			item.Metadata["error_reason_code_value"] = strconv.Itoa(status)
		}
		if err := r.emit(item); err != nil {
			return err
		}
		_, known := r.cur.Files[f.ID]
		_, baseline := r.cur.FullSyncBaseline[f.ID]
		if known || baseline {
			r.cur.Files[f.ID] = ""
			return r.mutated()
		}
		return nil
	}
	item.Content = body
	if exportMime, _, exported := f.exportAs(); exported {
		item.ContentType = exportMime
	} else {
		item.ContentType = http.DetectContentType(body)
	}
	if err := r.emit(item); err != nil {
		return err
	}
	r.cur.Files[f.ID] = fp
	return r.mutated()
}

func fetchReason(err error) string {
	switch {
	case errors.Is(err, errTooLarge):
		return reasonFileTooLarge
	case errors.Is(err, errEmptyFile):
		return reasonEmptyFile
	case reasonOf(err) == "exportSizeLimitExceeded":
		return reasonExportTooLarge
	case errors.Is(err, errNotDownloadable), statusOf(err) == http.StatusForbidden:
		return reasonPermissionDenied
	case statusOf(err) == http.StatusNotFound:
		return reasonNotFound
	default:
		return reasonFetchFailed
	}
}

func (r *syncRun) identity(f file, fileName, root string) types.FetchedItem {
	return types.FetchedItem{
		ExternalID: externalID(f.ID), Title: f.Name, FileName: fileName,
		UpdatedAt: parseTime(f.ModifiedTime), CreatedAt: parseTime(f.CreatedTime), SourceResourceID: root,
		Metadata: map[string]string{
			"channel": types.ChannelGoogleDrive, "source_type": types.ConnectorTypeGoogleDrive,
			"google_drive_file_id": f.ID, "google_drive_mime_type": f.MimeType, "google_drive_url": f.WebViewLink,
		},
	}
}

// Only a complete traversal can establish absence. Persist additions before
// emitting any deletions, then checkpoint each batch of acknowledged removals.
func (r *syncRun) reconcile() error {
	missing := map[string]bool{}
	for _, files := range []map[string]string{r.cur.Files, r.cur.FullSyncBaseline} {
		for id := range files {
			if !r.seen[id] {
				missing[id] = true
			}
		}
	}
	ids := make([]string, 0, len(missing))
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > 0 && r.unsaved > 0 {
		if err := r.checkpoint(); err != nil {
			return err
		}
	}
	for _, id := range ids {
		item := types.FetchedItem{
			ExternalID: externalID(id), Title: id, IsDeleted: true,
			Metadata: map[string]string{"channel": types.ChannelGoogleDrive, "google_drive_file_id": id},
		}
		if err := r.emit(item); err != nil {
			return err
		}
		delete(r.cur.Files, id)
		delete(r.cur.FullSyncBaseline, id)
		if err := r.mutated(); err != nil {
			return err
		}
	}
	r.cur.FullSync, r.cur.FullSyncBaseline = false, nil
	return r.checkpoint()
}
