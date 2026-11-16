package googledrive

import (
	"crypto/md5" //nolint:gosec // mirrors the checksum Drive publishes.
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/utils"
)

const (
	testClientID     = "client-id.apps.example"
	testClientSecret = "client-secret-for-tests"
	testRefreshToken = "refresh-token-for-tests"
	testAuthCode     = "auth-code-for-tests"
	testMyDriveID    = "my-drive-root"
	mimeDoc          = "application/vnd.google-apps.document"
)

type fakeFile struct {
	name, mime, parent, driveID, modified string
	body                                  []byte
	trashed, shared, noDownload           bool
}

// fakeDrive implements the subset of the Drive v3 and OAuth token endpoints
// the connector calls, including shared-drive corpora and pagination.
type fakeDrive struct {
	server *httptest.Server
	mu     sync.Mutex
	files  map[string]*fakeFile
	drives []sharedDrive
	// status and reason force an error for "<operation>:<file id>".
	status   map[string]int
	reason   map[string]string
	failures map[string]int // remaining forced failures; absent means forever
	counts   map[string]int
	pageSize int

	accessToken  string
	tokenSerial  int
	refreshToken string
	tokenError   string
	grantedScope string
	tokenForms   []map[string]string
	revoked      []string
}

func newFakeDrive(t *testing.T) *fakeDrive {
	t.Helper()
	t.Setenv("SSRF_WHITELIST", "127.0.0.1")
	t.Setenv("SSRF_WHITELIST_EXTRA", "")
	utils.ResetSSRFWhitelistForTest()
	t.Cleanup(utils.ResetSSRFWhitelistForTest)
	f := &fakeDrive{
		files:  map[string]*fakeFile{testMyDriveID: {name: "My Drive", mime: mimeFolder}},
		status: map[string]int{}, reason: map[string]string{}, failures: map[string]int{}, counts: map[string]int{},
		refreshToken: testRefreshToken, grantedScope: driveScope,
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeDrive) connector() *Connector {
	c := NewConnector()
	c.ep = endpoints{
		api: f.server.URL + "/drive/v3", auth: f.server.URL + "/auth",
		token: f.server.URL + "/token", revoke: f.server.URL + "/revoke",
	}
	c.backoff = time.Millisecond
	return c
}

func (f *fakeDrive) config(roots ...string) *types.DataSourceConfig {
	return &types.DataSourceConfig{Type: types.ConnectorTypeGoogleDrive, Credentials: map[string]any{
		credClientID: testClientID, credClientSecret: testClientSecret, credRefreshToken: testRefreshToken,
		credAccountEmail: "alice@example.com", credAccountID: "perm-1",
	}, ResourceIDs: roots}
}

func (f *fakeDrive) folder(id, name, parent string) {
	f.put(id, &fakeFile{name: name, mime: mimeFolder, parent: parent})
}

func (f *fakeDrive) add(id, name, parent, body string) {
	f.put(id, &fakeFile{name: name, mime: "application/octet-stream", parent: parent, body: []byte(body)})
}

func (f *fakeDrive) doc(id, name, parent, body string) {
	f.put(id, &fakeFile{name: name, mime: mimeDoc, parent: parent, body: []byte(body)})
}

func (f *fakeDrive) put(id string, file *fakeFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if file.modified == "" {
		file.modified = "2026-10-21T07:28:00Z"
	}
	if parent := f.files[file.parent]; parent != nil && file.driveID == "" {
		file.driveID = parent.driveID
	}
	f.files[id] = file
}

func (f *fakeDrive) edit(id string, change func(*fakeFile)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change(f.files[id])
}

func (f *fakeDrive) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.files, id)
}

func (f *fakeDrive) fail(key string, status int, reason string, times int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[key], f.reason[key] = status, reason
	if times > 0 {
		f.failures[key] = times
	} else {
		delete(f.failures, key)
	}
}

func (f *fakeDrive) clear(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.status, key)
}

func (f *fakeDrive) count(key string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[key]
}

func (f *fakeDrive) resource(id string, file *fakeFile) map[string]any {
	out := map[string]any{
		"id": id, "name": file.name, "mimeType": file.mime, "modifiedTime": file.modified,
		"createdTime": "2026-01-01T00:00:00Z", "trashed": file.trashed,
		"webViewLink": "https://drive.example/" + id, "capabilities": map[string]any{"canDownload": !file.noDownload},
	}
	if file.parent != "" {
		out["parents"] = []string{file.parent}
	}
	if file.driveID != "" {
		out["driveId"] = file.driveID
	}
	if !strings.HasPrefix(file.mime, mimeNative) {
		sum := md5.Sum(file.body) //nolint:gosec // test fixture checksum.
		out["size"], out["md5Checksum"] = strconv.Itoa(len(file.body)), hex.EncodeToString(sum[:])
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *fakeDrive) forced(w http.ResponseWriter, key string) bool {
	f.counts[key]++
	status, ok := f.status[key]
	if !ok {
		return false
	}
	if left, limited := f.failures[key]; limited {
		if left <= 1 {
			delete(f.status, key)
			delete(f.failures, key)
		} else {
			f.failures[key] = left - 1
		}
	}
	writeJSON(w, status, map[string]any{"error": map[string]any{
		"code": status, "message": "secret detail " + testRefreshToken,
		"errors": []map[string]string{{"reason": f.reason[key], "message": "secret detail"}},
	}})
	return true
}

func (f *fakeDrive) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/token":
		f.serveToken(w, r)
		return
	case "/revoke":
		_ = r.ParseForm()
		f.revoked = append(f.revoked, r.PostForm.Get("token"))
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	if f.accessToken == "" || r.Header.Get("Authorization") != "Bearer "+f.accessToken {
		f.counts["unauthorized"]++
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]any{
			"errors": []map[string]string{{"reason": "authError"}},
		}})
		return
	}
	resource := strings.TrimPrefix(r.URL.Path, "/drive/v3")
	query := r.URL.Query()
	switch {
	case resource == "/about":
		if f.forced(w, "about") {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": map[string]string{
			"emailAddress": "alice@example.com", "permissionId": "perm-1",
		}})
	case resource == "/drives":
		writeJSON(w, http.StatusOK, map[string]any{"drives": f.drives})
	case resource == "/files":
		f.serveList(w, query.Get("q"), query.Get("corpora"), query.Get("driveId"), query.Get("pageToken"))
	case strings.HasPrefix(resource, "/files/"):
		id, export := strings.CutSuffix(strings.TrimPrefix(resource, "/files/"), "/export")
		if id == rootID {
			id = testMyDriveID
		}
		operation := "get"
		if export || query.Get("alt") == "media" {
			operation = "download"
		}
		if f.forced(w, operation+":"+id) {
			return
		}
		file := f.files[id]
		if file == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{
				"errors": []map[string]string{{"reason": "notFound"}},
			}})
			return
		}
		if operation == "download" {
			_, _ = w.Write(file.body)
			return
		}
		writeJSON(w, http.StatusOK, f.resource(id, file))
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeDrive) serveToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := map[string]string{}
	for key := range r.PostForm {
		form[key] = r.PostForm.Get(key)
	}
	f.tokenForms = append(f.tokenForms, form)
	valid := form["client_id"] == testClientID && form["client_secret"] == testClientSecret
	switch form["grant_type"] {
	case "refresh_token":
		valid = valid && form["refresh_token"] == f.refreshToken
	case "authorization_code":
		valid = valid && form["code"] == testAuthCode && form["code_verifier"] != "" && form["redirect_uri"] != ""
	default:
		valid = false
	}
	if f.tokenError != "" || !valid {
		code := f.tokenError
		if code == "" {
			code = "invalid_grant"
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": testClientSecret})
		return
	}
	f.tokenSerial++
	f.accessToken = fmt.Sprintf("access-%d", f.tokenSerial)
	out := map[string]any{"access_token": f.accessToken, "expires_in": 3600, "scope": f.grantedScope}
	if form["grant_type"] == "authorization_code" {
		out["refresh_token"] = f.refreshToken
	}
	writeJSON(w, http.StatusOK, out)
}

// serveList answers the two searches the connector issues. A folder inside a
// shared drive is only visible when that drive's corpus is searched.
func (f *fakeDrive) serveList(w http.ResponseWriter, q, corpora, driveID, pageToken string) {
	parent, isChildren := "", false
	if rest, ok := strings.CutPrefix(q, "'"); ok {
		parent, _, isChildren = strings.Cut(rest, "' in parents and trashed = false")
	}
	if !isChildren && q != sharedWithMeQuery {
		writeJSON(w, http.StatusBadRequest, map[string]any{})
		return
	}
	if f.forced(w, "list:"+parent) {
		return
	}
	var ids []string
	if container := f.files[parent]; !isChildren || container != nil {
		visible := !isChildren || container.driveID == "" || (corpora == "drive" && driveID == container.driveID)
		for id, file := range f.files {
			match := file.parent == parent
			if !isChildren {
				match = file.shared
			}
			if match && visible && !file.trashed {
				ids = append(ids, id)
			}
		}
	} else {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]any{
			"errors": []map[string]string{{"reason": "notFound"}},
		}})
		return
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := f.files[ids[i]], f.files[ids[j]]
		if (a.mime == mimeFolder) != (b.mime == mimeFolder) {
			return a.mime == mimeFolder
		}
		return a.name < b.name
	})
	start, _ := strconv.Atoi(pageToken)
	end := len(ids)
	out := map[string]any{}
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
		out["nextPageToken"] = strconv.Itoa(end)
	}
	files := make([]map[string]any, 0, end-start)
	for _, id := range ids[start:end] {
		files = append(files, f.resource(id, f.files[id]))
	}
	out["files"] = files
	writeJSON(w, http.StatusOK, out)
}
