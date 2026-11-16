package googledrive

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
)

var (
	_ datasource.Connector              = (*Connector)(nil)
	_ datasource.FullStreamingConnector = (*Connector)(nil)
)

const (
	maxPickerEntries  = 5000
	maxAncestorLookup = 500
)

// Connector keeps no credentials or sync state between data sources; it only
// caches short-lived access tokens.
type Connector struct {
	ep      endpoints
	tokens  *tokenCache
	backoff time.Duration
}

// NewConnector creates a Google Drive connector.
func NewConnector() *Connector {
	return &Connector{ep: googleEndpoints, tokens: newTokenCache(), backoff: time.Second}
}

// Type returns the registered connector type.
func (*Connector) Type() string { return types.ConnectorTypeGoogleDrive }

// Validate checks the OAuth client registration and, once the data source has
// been authorized, that the stored grant still works. A data source is created
// before its owner can authorize it, so a missing grant is not an error here;
// listing and syncing require it.
func (c *Connector) Validate(ctx context.Context, ds *types.DataSourceConfig) error {
	cfg, err := parseConfig(ds)
	if err != nil {
		return err
	}
	if len(ds.ResourceIDs) > 0 {
		if _, err := selectedRoots(ds.ResourceIDs); err != nil {
			return err
		}
	}
	if cfg.refreshToken == "" {
		return nil
	}
	client := c.newClient(cfg)
	defer client.close()
	_, _, err = client.about(ctx)
	return err
}

func mapListingError(err error) error {
	if isRateLimited(err) {
		return err
	}
	switch statusOf(err) {
	case http.StatusNotFound:
		return fmt.Errorf("%w: selected Google Drive resource was not found", datasource.ErrResourceNotFound)
	case http.StatusForbidden:
		return fmt.Errorf("%w: %s", datasource.ErrFetchFailed, reasonPermissionDenied)
	default:
		return err
	}
}

func resourceOf(f file, parentID string) (types.Resource, bool) {
	kind := "file"
	if f.isFolder() {
		kind = "directory"
	} else if _, ok := f.syncName(); !ok {
		return types.Resource{}, false
	}
	return types.Resource{
		ExternalID: f.ID, Name: f.Name, Type: kind, ParentID: parentID,
		HasChildren: f.isFolder(), ModifiedAt: parseTime(f.ModifiedTime), URL: f.WebViewLink,
	}, true
}

// ListResources exposes My Drive, the items shared with the account and every
// shared drive at the top level, then lazily lists one folder level.
func (c *Connector) ListResources(
	ctx context.Context, ds *types.DataSourceConfig, parentID string,
) ([]types.Resource, error) {
	cfg, err := parseAuthorizedConfig(ds)
	if err != nil {
		return nil, err
	}
	client := c.newClient(cfg)
	defer client.close()
	if parentID == "" {
		return client.topLevel(ctx)
	}
	query, driveID := sharedWithMeQuery, ""
	if parentID != sharedWithMeID {
		if !validID(parentID) {
			return nil, fmt.Errorf("%w: invalid Google Drive resource ID", datasource.ErrInvalidConfig)
		}
		parent, err := client.getFile(ctx, parentID)
		if err != nil {
			return nil, mapListingError(err)
		}
		query, driveID = childrenQuery(parent.ID), parent.DriveID
	}
	out := []types.Resource{}
	for pageToken := ""; ; {
		files, next, err := client.list(ctx, query, driveID, pageToken)
		if err != nil {
			return nil, mapListingError(err)
		}
		for _, f := range files {
			if resource, ok := resourceOf(f, parentID); ok {
				out = append(out, resource)
			}
		}
		if next == "" || len(out) >= maxPickerEntries {
			return out, nil
		}
		pageToken = next
	}
}

func (c *client) topLevel(ctx context.Context) ([]types.Resource, error) {
	out := []types.Resource{
		{ExternalID: rootID, Name: "My Drive", Type: "directory", HasChildren: true},
		{ExternalID: sharedWithMeID, Name: "Shared with me", Type: "directory", HasChildren: true},
	}
	for pageToken := ""; ; {
		drives, next, err := c.drives(ctx, pageToken)
		if err != nil {
			return nil, mapListingError(err)
		}
		for _, d := range drives {
			out = append(out, types.Resource{ExternalID: d.ID, Name: d.Name, Type: "directory", HasChildren: true})
		}
		if next == "" || len(out) >= maxPickerEntries {
			return out, nil
		}
		pageToken = next
	}
}

// ResolveResourceAncestors walks each selection up to a top-level picker node.
// Drive IDs do not encode the hierarchy, so every level costs one lookup; the
// walk stops at the first ancestor another selection already resolved.
func (c *Connector) ResolveResourceAncestors(
	ctx context.Context, ds *types.DataSourceConfig, ids []string,
) ([]string, error) {
	cfg, err := parseAuthorizedConfig(ds)
	if err != nil {
		return nil, err
	}
	client := c.newClient(cfg)
	defer client.close()
	myDrive, err := client.getFile(ctx, rootID)
	if err != nil {
		return nil, mapListingError(err)
	}
	seen := map[string]bool{}
	lookups := 0
	for _, id := range ids {
		if id == rootID || id == sharedWithMeID || !validID(id) {
			continue
		}
		for current := id; lookups < maxAncestorLookup; {
			lookups++
			f, err := client.getFile(ctx, current)
			if err != nil || (f.DriveID != "" && f.ID == f.DriveID) {
				break // Unreachable now, or a shared drive: already a top-level node.
			}
			if len(f.Parents) == 0 {
				if f.ID != myDrive.ID {
					seen[sharedWithMeID] = true
				}
				break
			}
			parent := f.Parents[0]
			if parent == myDrive.ID {
				seen[rootID] = true
				break
			}
			if seen[parent] {
				break
			}
			seen[parent] = true
			current = parent
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}

type collector struct{ items []types.FetchedItem }

func (h *collector) Emit(_ context.Context, item types.FetchedItem) error {
	h.items = append(h.items, item)
	return nil
}

func (*collector) Checkpoint(context.Context, *types.SyncCursor) error { return nil }

// FetchAll collects a fresh sync of the selected resources.
func (c *Connector) FetchAll(
	ctx context.Context, ds *types.DataSourceConfig, ids []string,
) ([]types.FetchedItem, error) {
	if ds == nil {
		return nil, datasource.ErrInvalidConfig
	}
	configCopy := *ds
	configCopy.ResourceIDs = ids
	items, _, err := c.FetchIncremental(ctx, &configCopy, nil)
	return items, err
}

// FetchIncremental collects changed files and deletions using the old cursor.
func (c *Connector) FetchIncremental(
	ctx context.Context, ds *types.DataSourceConfig, old *types.SyncCursor,
) ([]types.FetchedItem, *types.SyncCursor, error) {
	h := &collector{}
	next, err := c.FetchStream(ctx, ds, old, h)
	return h.items, next, err
}

// FetchStream downloads one file at a time and checkpoints resumable progress.
func (c *Connector) FetchStream(
	ctx context.Context, ds *types.DataSourceConfig, old *types.SyncCursor, h datasource.StreamHandler,
) (*types.SyncCursor, error) {
	return c.runSync(ctx, ds, old, h, false)
}

// FetchFullStream re-fetches all files while retaining the deletion baseline.
func (c *Connector) FetchFullStream(
	ctx context.Context, ds *types.DataSourceConfig, old *types.SyncCursor, h datasource.StreamHandler,
) (*types.SyncCursor, error) {
	return c.runSync(ctx, ds, old, h, true)
}
