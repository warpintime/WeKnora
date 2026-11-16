// Package googledrive synchronizes files from a Google Drive account.
//
// Resource IDs are Drive file IDs. Two aliases complete the picker's top level:
// "root" (the account's My Drive) and "shared-with-me" (a virtual folder listing
// items shared with the account). A shared drive is selected by its drive ID,
// which is also the ID of its top-level folder.
package googledrive

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/utils"
)

const (
	rootID         = "root"
	sharedWithMeID = "shared-with-me"

	mimeFolder   = "application/vnd.google-apps.folder"
	mimeShortcut = "application/vnd.google-apps.shortcut"
	mimeNative   = "application/vnd.google-apps."

	// Credential keys. The first two are entered by the user; the rest are
	// written by the authorization flow and removed when access is revoked.
	credClientID     = "client_id"
	credClientSecret = "client_secret"
	credRefreshToken = "refresh_token"
	credAccountEmail = "account_email"
	credAccountID    = "account_id"

	driveScope = "https://www.googleapis.com/auth/drive.readonly"
)

// nativeExports maps Google editor formats, which have no downloadable bytes,
// to the format they are exported in.
var nativeExports = map[string]struct{ mime, ext string }{
	"application/vnd.google-apps.document": {"text/markdown", ".md"},
	"application/vnd.google-apps.spreadsheet": {
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx",
	},
	"application/vnd.google-apps.presentation": {
		"application/vnd.openxmlformats-officedocument.presentationml.presentation", ".pptx",
	},
}

type config struct {
	clientID, clientSecret, refreshToken string
	accountID, accountEmail              string
}

func credential(ds *types.DataSourceConfig, key string) string {
	value, _ := ds.Credentials[key].(string)
	return strings.TrimSpace(value)
}

// parseConfig checks the OAuth client registration. The refresh token is
// optional here: a data source exists before its owner has authorized it.
func parseConfig(ds *types.DataSourceConfig) (config, error) {
	if ds == nil {
		return config{}, fmt.Errorf("%w: Google Drive configuration is required", datasource.ErrInvalidConfig)
	}
	cfg := config{
		clientID: credential(ds, credClientID), clientSecret: credential(ds, credClientSecret),
		refreshToken: credential(ds, credRefreshToken),
		accountID:    credential(ds, credAccountID), accountEmail: credential(ds, credAccountEmail),
	}
	invalid := func(s string) bool {
		return s == "" || strings.ContainsFunc(s, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		})
	}
	if invalid(cfg.clientID) {
		return config{}, fmt.Errorf("%w: client_id is required", datasource.ErrInvalidConfig)
	}
	if invalid(cfg.clientSecret) {
		return config{}, fmt.Errorf("%w: client_secret is required", datasource.ErrInvalidConfig)
	}
	return cfg, nil
}

// parseAuthorizedConfig additionally requires a completed authorization.
func parseAuthorizedConfig(ds *types.DataSourceConfig) (config, error) {
	cfg, err := parseConfig(ds)
	if err != nil {
		return config{}, err
	}
	if cfg.refreshToken == "" {
		return config{}, fmt.Errorf("%w: Google Drive access has not been authorized", datasource.ErrInvalidCredentials)
	}
	return cfg, nil
}

// scope binds cursors to the authorized Google account without storing
// credentials in the cursor. Re-authorizing the same account keeps the scope.
func (c config) scope() string {
	account := c.accountID
	if account == "" {
		account = strings.ToLower(c.accountEmail)
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(account)))
}

// selectedRoots validates and deduplicates the selection. Drive IDs are
// opaque, so nested selections are reconciled while scanning, not here.
func selectedRoots(ids []string) ([]string, error) {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if !validID(id) {
			return nil, fmt.Errorf("%w: invalid Google Drive resource ID", datasource.ErrInvalidConfig)
		}
		seen[id] = true
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("%w: select at least one Google Drive folder or file", datasource.ErrInvalidConfig)
	}
	roots := make([]string, 0, len(seen))
	for id := range seen {
		roots = append(roots, id)
	}
	sort.Strings(roots)
	return roots, nil
}

// validID accepts the URL-safe alphabet Drive uses for file and drive IDs.
// IDs are interpolated into search queries, so nothing else may pass.
func validID(id string) bool {
	if id == "" || len(id) > 256 {
		return false
	}
	for _, r := range id {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// file is the subset of the Drive file resource the connector reads.
type file struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	MimeType     string   `json:"mimeType"`
	Size         int64    `json:"size,string"`
	MD5          string   `json:"md5Checksum"`
	ModifiedTime string   `json:"modifiedTime"`
	CreatedTime  string   `json:"createdTime"`
	Trashed      bool     `json:"trashed"`
	DriveID      string   `json:"driveId"`
	Parents      []string `json:"parents"`
	WebViewLink  string   `json:"webViewLink"`
	Capabilities *struct {
		CanDownload *bool `json:"canDownload"`
	} `json:"capabilities"`
}

func (f file) isFolder() bool { return f.MimeType == mimeFolder }

// Drive omits timestamps on some virtual folders; a missing one is zero.
func parseTime(value string) time.Time {
	t, _ := time.Parse(time.RFC3339, value)
	return t
}

func (f file) downloadable() bool {
	return f.Capabilities == nil || f.Capabilities.CanDownload == nil || *f.Capabilities.CanDownload
}

// exportAs reports the export format of a Google editor file.
func (f file) exportAs() (mime, ext string, ok bool) {
	export, ok := nativeExports[f.MimeType]
	return export.mime, export.ext, ok
}

// syncName returns the file name ingestion sees, or false when the file cannot
// be imported: folders, shortcuts, unsupported editor formats and extensions.
func (f file) syncName() (string, bool) {
	if _, ext, ok := f.exportAs(); ok {
		if strings.EqualFold(path.Ext(f.Name), ext) {
			return f.Name, true
		}
		return f.Name + ext, true
	}
	if strings.HasPrefix(f.MimeType, mimeNative) || !utils.IsSupportedImportExtension(path.Ext(f.Name)) {
		return "", false
	}
	return f.Name, true
}

// fingerprint identifies one version of a file at one location. Binary files
// are compared by checksum, so a touch without a content change is not a new
// version. Editor files expose no checksum and fall back to the edit time.
func fingerprint(f file, filePath string) string {
	var raw []byte
	if f.MD5 != "" {
		raw, _ = json.Marshal([]any{"md5", f.MD5, f.Size, filePath})
	} else {
		raw, _ = json.Marshal([]any{"time", parseTime(f.ModifiedTime).UTC(), f.Size, filePath})
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func externalID(fileID string) string { return types.ConnectorTypeGoogleDrive + ":" + fileID }

// knowledgeFileName mirrors the Drive hierarchy: ingestion derives the
// knowledge base folder from the directory part of the name.
func knowledgeFileName(dir []string, name string) string {
	segments := make([]string, 0, len(dir)+2)
	segments = append(segments, "Google Drive")
	for _, segment := range dir {
		segments = append(segments, datasource.SanitizeFileName(segment))
	}
	ext := path.Ext(name)
	segments = append(segments, datasource.SanitizeFileName(strings.TrimSuffix(name, ext))+ext)
	return strings.Join(segments, "/")
}

const (
	reasonPermissionDenied = "google_drive_permission_denied"
	reasonNotFound         = "google_drive_not_found"
	reasonFileTooLarge     = "google_drive_file_too_large"
	reasonExportTooLarge   = "google_drive_export_too_large"
	reasonEmptyFile        = "google_drive_empty_file"
	reasonRateLimited      = "google_drive_rate_limited"
	reasonFetchFailed      = "google_drive_fetch_failed"
)

var reasonText = map[string]string{
	reasonPermissionDenied: "Permission to download the Google Drive file was denied",
	reasonNotFound:         "The Google Drive file was not found",
	reasonFileTooLarge:     "The Google Drive file exceeds the configured size limit",
	reasonExportTooLarge:   "The Google document is too large to export",
	reasonEmptyFile:        "The Google Drive file is empty",
	reasonRateLimited:      "Google Drive rate limit reached",
	reasonFetchFailed:      "Failed to fetch the file from Google Drive",
}
