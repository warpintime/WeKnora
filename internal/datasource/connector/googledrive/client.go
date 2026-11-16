package googledrive

import (
	"context"
	"crypto/md5" //nolint:gosec // Drive publishes MD5 checksums; used for integrity, not security.
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/utils"
)

// endpoints are replaced by tests; production always talks to Google.
type endpoints struct{ api, auth, token, revoke string }

var googleEndpoints = endpoints{
	api:    "https://www.googleapis.com/drive/v3",
	auth:   "https://accounts.google.com/o/oauth2/v2/auth",
	token:  "https://oauth2.googleapis.com/token",
	revoke: "https://oauth2.googleapis.com/revoke",
}

const (
	requestTimeout  = 120 * time.Second
	maxAttempts     = 5
	maxRetryWait    = 60 * time.Second
	tokenExpirySkew = 60 * time.Second
	errorBodyLimit  = int64(64 << 10)
	jsonBodyLimit   = int64(32 << 20)
	listPageSize    = "1000"
	drivesPageSize  = "100"
	fileFields      = "id,name,mimeType,size,md5Checksum,modifiedTime,createdTime,trashed,driveId,parents," +
		"webViewLink,capabilities(canDownload)"
)

var (
	errTooLarge      = errors.New("google drive file exceeds the size limit")
	errEmptyFile     = errors.New("google drive file is empty")
	errSourceChanged = errors.New("google drive file changed while being fetched")
)

// apiError exposes only an operation, a status and Google's machine-readable
// reason. Response bodies and messages can quote file names or tokens and must
// never reach sync logs or the API.
type apiError struct {
	op, reason string
	status     int
}

func (e *apiError) Error() string {
	if e.reason != "" {
		return fmt.Sprintf("Google Drive %s: HTTP %d (%s)", e.op, e.status, e.reason)
	}
	return fmt.Sprintf("Google Drive %s: HTTP %d", e.op, e.status)
}

func (e *apiError) Unwrap() error {
	if e.status == http.StatusUnauthorized {
		return datasource.ErrInvalidCredentials
	}
	return datasource.ErrFetchFailed
}

func (e *apiError) rateLimited() bool {
	if e.status == http.StatusTooManyRequests {
		return true
	}
	if e.status != http.StatusForbidden {
		return false
	}
	switch e.reason {
	case "rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded":
		return true
	}
	return false
}

func (e *apiError) retryable() bool {
	if e.reason == "dailyLimitExceeded" {
		return false
	}
	return e.rateLimited() || e.status >= http.StatusInternalServerError
}

func statusOf(err error) int {
	var e *apiError
	if errors.As(err, &e) {
		return e.status
	}
	return 0
}

func reasonOf(err error) string {
	var e *apiError
	if errors.As(err, &e) {
		return e.reason
	}
	return ""
}

func isRateLimited(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.rateLimited()
}

// machineCode keeps only the identifier alphabet of an upstream error code.
func machineCode(code string) string {
	if len(code) > 64 {
		code = code[:64]
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return ""
		}
	}
	return code
}

func readAPIError(op string, resp *http.Response) *apiError {
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	var payload struct {
		Error struct {
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	e := &apiError{op: op, status: resp.StatusCode}
	if json.Unmarshal(body, &payload) == nil && len(payload.Error.Errors) > 0 {
		e.reason = machineCode(payload.Error.Errors[0].Reason)
	}
	return e
}

// tokenCache keeps access tokens for their lifetime so that browsing the
// picker does not refresh on every request. Keys are derived, not stored,
// credentials; the cache holds nothing that outlives the process.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]cachedToken
}

type cachedToken struct {
	value     string
	expiresAt time.Time
}

func newTokenCache() *tokenCache { return &tokenCache{entries: make(map[string]cachedToken)} }

func (t *tokenCache) get(key string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		delete(t.entries, key)
		return "", false
	}
	return entry.value, true
}

func (t *tokenCache) put(key, value string, lifetime time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	for k, entry := range t.entries {
		if now.After(entry.expiresAt) {
			delete(t.entries, k)
		}
	}
	if lifetime > tokenExpirySkew {
		t.entries[key] = cachedToken{value: value, expiresAt: now.Add(lifetime - tokenExpirySkew)}
	}
}

func (t *tokenCache) drop(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, key)
}

type client struct {
	http    *http.Client
	ep      endpoints
	cfg     config
	tokens  *tokenCache
	backoff time.Duration
	// token is used when the cache declines an entry (very short lifetimes).
	token string
}

func (c *Connector) newClient(cfg config) *client {
	policy := utils.DefaultSSRFSafeHTTPClientConfig()
	policy.Timeout = requestTimeout
	return &client{
		http: utils.NewSSRFSafeHTTPClient(policy), ep: c.ep, cfg: cfg, tokens: c.tokens, backoff: c.backoff,
	}
}

func (c *client) close() { c.http.CloseIdleConnections() }

func (c *client) cacheKey() string {
	sum := sha256.Sum256([]byte(c.cfg.clientID + "\x00" + c.cfg.refreshToken))
	return hex.EncodeToString(sum[:])
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

// tokenRequest posts to the token endpoint. A rejected grant or client is a
// credential problem the user must fix, so it is reported as such.
func (c *client) tokenRequest(ctx context.Context, form url.Values) (tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.token, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, fmt.Errorf("%w: Google token request failed", datasource.ErrFetchFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return tokenResponse{}, ctx.Err()
		}
		return tokenResponse{}, fmt.Errorf("%w: Google token request failed", datasource.ErrFetchFailed)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if resp.StatusCode != http.StatusOK {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &payload)
		if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
			code := machineCode(payload.Error)
			if code == "" {
				code = "rejected"
			}
			return tokenResponse{}, fmt.Errorf("%w: Google rejected the authorization (%s)",
				datasource.ErrInvalidCredentials, code)
		}
		return tokenResponse{}, &apiError{op: "token", status: resp.StatusCode}
	}
	var token tokenResponse
	if err := json.Unmarshal(body, &token); err != nil || token.AccessToken == "" {
		return tokenResponse{}, fmt.Errorf("%w: Google returned an invalid token response", datasource.ErrFetchFailed)
	}
	return token, nil
}

func (c *client) remember(token tokenResponse) {
	c.token = token.AccessToken
	c.tokens.put(c.cacheKey(), token.AccessToken, time.Duration(token.ExpiresIn)*time.Second)
}

func (c *client) accessToken(ctx context.Context, refresh bool) (string, error) {
	if !refresh {
		if token, ok := c.tokens.get(c.cacheKey()); ok {
			return token, nil
		}
		if c.token != "" {
			return c.token, nil
		}
	}
	c.tokens.drop(c.cacheKey())
	token, err := c.tokenRequest(ctx, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {c.cfg.refreshToken},
		"client_id": {c.cfg.clientID}, "client_secret": {c.cfg.clientSecret},
	})
	if err != nil {
		return "", err
	}
	c.remember(token)
	return token.AccessToken, nil
}

func (c *client) wait(ctx context.Context, attempt int, retryAfter string) error {
	delay := c.backoff << attempt
	if seconds, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && seconds > 0 {
		delay = time.Duration(seconds) * time.Second
	}
	delay = min(delay, maxRetryWait)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// get issues an authorized GET. Rate limits and server errors are retried with
// exponential backoff; one 401 triggers a token refresh, because an access
// token can be revoked before its advertised expiry.
func (c *client) get(ctx context.Context, op, rawURL string) (*http.Response, error) {
	refresh, refreshed := false, false
	for attempt := 0; ; attempt++ {
		token, err := c.accessToken(ctx, refresh)
		if err != nil {
			return nil, err
		}
		refresh = false
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("%w: Google Drive %s request failed", datasource.ErrFetchFailed, op)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "WeKnora-Google-Drive-Connector/1.0")
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt < maxAttempts-1 {
				if err := c.wait(ctx, attempt, ""); err != nil {
					return nil, err
				}
				continue
			}
			return nil, fmt.Errorf("%w: Google Drive %s request failed", datasource.ErrFetchFailed, op)
		}
		if resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices {
			return resp, nil
		}
		retryAfter := resp.Header.Get("Retry-After")
		apiErr := readAPIError(op, resp)
		switch {
		case apiErr.status == http.StatusUnauthorized && !refreshed:
			refresh, refreshed = true, true
			attempt--
			continue
		case apiErr.retryable() && attempt < maxAttempts-1:
			if err := c.wait(ctx, attempt, retryAfter); err != nil {
				return nil, err
			}
			continue
		}
		return nil, apiErr
	}
}

func (c *client) getJSON(ctx context.Context, op, resource string, query url.Values, out any) error {
	resp, err := c.get(ctx, op, c.ep.api+resource+"?"+query.Encode())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, jsonBodyLimit+1))
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("%w: Google Drive %s response interrupted", datasource.ErrFetchFailed, op)
	}
	if int64(len(body)) > jsonBodyLimit || json.Unmarshal(body, out) != nil {
		return fmt.Errorf("%w: Google Drive returned an invalid %s response", datasource.ErrFetchFailed, op)
	}
	return nil
}

// about identifies the authorized account.
func (c *client) about(ctx context.Context) (email, id string, err error) {
	var out struct {
		User struct {
			EmailAddress string `json:"emailAddress"`
			PermissionID string `json:"permissionId"`
		} `json:"user"`
	}
	err = c.getJSON(ctx, "about", "/about", url.Values{"fields": {"user(emailAddress,permissionId)"}}, &out)
	return out.User.EmailAddress, out.User.PermissionID, err
}

func (c *client) getFile(ctx context.Context, id string) (file, error) {
	var f file
	err := c.getJSON(ctx, "files.get", "/files/"+url.PathEscape(id),
		url.Values{"fields": {fileFields}, "supportsAllDrives": {"true"}}, &f)
	return f, err
}

// list returns one page of a search. Items inside a shared drive are searched
// in that drive's corpus, which is the documented way to reach them.
func (c *client) list(ctx context.Context, query, driveID, pageToken string) ([]file, string, error) {
	params := url.Values{
		"q": {query}, "fields": {"nextPageToken,files(" + fileFields + ")"}, "pageSize": {listPageSize},
		"orderBy": {"folder,name_natural"}, "supportsAllDrives": {"true"}, "includeItemsFromAllDrives": {"true"},
	}
	if driveID != "" {
		params.Set("corpora", "drive")
		params.Set("driveId", driveID)
	}
	if pageToken != "" {
		params.Set("pageToken", pageToken)
	}
	var out struct {
		NextPageToken string `json:"nextPageToken"`
		Files         []file `json:"files"`
	}
	if err := c.getJSON(ctx, "files.list", "/files", params, &out); err != nil {
		return nil, "", err
	}
	return out.Files, out.NextPageToken, nil
}

func childrenQuery(folderID string) string {
	return "'" + folderID + "' in parents and trashed = false"
}

const sharedWithMeQuery = "sharedWithMe = true and trashed = false"

type sharedDrive struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (c *client) drives(ctx context.Context, pageToken string) ([]sharedDrive, string, error) {
	params := url.Values{"fields": {"nextPageToken,drives(id,name)"}, "pageSize": {drivesPageSize}}
	if pageToken != "" {
		params.Set("pageToken", pageToken)
	}
	var out struct {
		NextPageToken string        `json:"nextPageToken"`
		Drives        []sharedDrive `json:"drives"`
	}
	if err := c.getJSON(ctx, "drives.list", "/drives", params, &out); err != nil {
		return nil, "", err
	}
	return out.Drives, out.NextPageToken, nil
}

// content buffers one file, reading at most limit+1 bytes. Editor files are
// exported; everything else is downloaded and checked against the size and
// checksum Drive listed, so a truncated or concurrently replaced file is
// retried instead of ingested.
func (c *client) content(ctx context.Context, f file, limit int64) ([]byte, error) {
	target := c.ep.api + "/files/" + url.PathEscape(f.ID)
	exportMime, _, exported := f.exportAs()
	if exported {
		target += "/export?" + url.Values{"mimeType": {exportMime}}.Encode()
	} else {
		if f.Size > limit {
			return nil, errTooLarge
		}
		target += "?" + url.Values{"alt": {"media"}, "supportsAllDrives": {"true"}}.Encode()
	}
	resp, err := c.get(ctx, "download", target)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: Google Drive download interrupted", datasource.ErrFetchFailed)
	}
	switch {
	case int64(len(body)) > limit:
		return nil, errTooLarge
	case len(body) == 0:
		return nil, errEmptyFile
	case exported:
		return body, nil
	case f.Size > 0 && int64(len(body)) != f.Size:
		return nil, errSourceChanged
	}
	if f.MD5 != "" {
		sum := md5.Sum(body) //nolint:gosec // integrity check against Drive's published checksum.
		if !strings.EqualFold(hex.EncodeToString(sum[:]), f.MD5) {
			return nil, errSourceChanged
		}
	}
	return body, nil
}
