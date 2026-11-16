package googledrive

import (
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
)

func TestValidateIsStructuralUntilAuthorizedAndLiveAfterwards(t *testing.T) {
	f := newFakeDrive(t)
	c := f.connector()
	for _, cfg := range []*types.DataSourceConfig{
		nil,
		{Credentials: map[string]any{credClientSecret: testClientSecret}},
		{Credentials: map[string]any{credClientID: testClientID}},
		{Credentials: map[string]any{credClientID: "has space", credClientSecret: testClientSecret}},
	} {
		if err := c.Validate(t.Context(), cfg); !errors.Is(err, datasource.ErrInvalidConfig) {
			t.Fatalf("Validate(%+v) = %v", cfg, err)
		}
	}
	// A data source is created before it can be authorized: no network call yet.
	draft := &types.DataSourceConfig{Credentials: map[string]any{
		credClientID: testClientID, credClientSecret: testClientSecret,
	}}
	if err := c.Validate(t.Context(), draft); err != nil || len(f.tokenForms) != 0 {
		t.Fatalf("draft validation = %v, token calls = %d", err, len(f.tokenForms))
	}
	if err := c.Validate(t.Context(), f.config()); err != nil || f.count("about") != 1 {
		t.Fatalf("authorized validation = %v", err)
	}
	bad := f.config("not a valid id")
	if err := c.Validate(t.Context(), bad); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("invalid selection = %v", err)
	}
	f.mu.Lock()
	f.tokenError = "invalid_grant"
	f.mu.Unlock()
	if err := f.connector().Validate(t.Context(), f.config()); !errors.Is(err, datasource.ErrInvalidCredentials) ||
		!strings.Contains(err.Error(), "invalid_grant") || strings.Contains(err.Error(), testClientSecret) {
		t.Fatalf("revoked grant = %v", err)
	}
}

const testRedirectURI = "https://kb.example/api/v1/datasource-oauth/callback"

func TestAuthorizationURLExchangeStatusAndRevocation(t *testing.T) {
	f := newFakeDrive(t)
	c := f.connector()
	draft := &types.DataSourceConfig{Credentials: map[string]any{
		credClientID: testClientID, credClientSecret: testClientSecret,
	}}
	if status := c.OAuthStatus(draft); status.Authorized || status.Account != "" {
		t.Fatalf("draft status = %+v", status)
	}

	raw, err := c.OAuthAuthorizationURL(draft, datasource.OAuthAuthorizationRequest{
		State: "state-1", CodeChallenge: "challenge-1", RedirectURI: testRedirectURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(raw)
	want := url.Values{
		"client_id": {testClientID}, "redirect_uri": {testRedirectURI},
		"response_type": {"code"}, "scope": {driveScope}, "access_type": {"offline"}, "prompt": {"consent"},
		"state": {"state-1"}, "code_challenge": {"challenge-1"}, "code_challenge_method": {"S256"},
	}
	if !strings.HasPrefix(raw, f.server.URL+"/auth?") || !reflect.DeepEqual(u.Query(), want) ||
		strings.Contains(raw, testClientSecret) {
		t.Fatalf("authorization URL = %s", raw)
	}

	exchange := datasource.OAuthExchangeRequest{
		Code: testAuthCode, CodeVerifier: "verifier-1", RedirectURI: testRedirectURI,
	}
	granted, err := c.ExchangeOAuthCode(t.Context(), draft, exchange)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(granted, map[string]any{
		credRefreshToken: testRefreshToken, credAccountEmail: "alice@example.com", credAccountID: "perm-1",
	}) {
		t.Fatalf("granted credentials = %+v", granted)
	}
	if form := f.tokenForms[0]; form["code_verifier"] != "verifier-1" || form["redirect_uri"] != exchange.RedirectURI {
		t.Fatalf("token request = %+v", form)
	}
	for key := range granted {
		found := false
		for _, owned := range c.OAuthCredentialKeys() {
			found = found || owned == key
		}
		if !found {
			t.Fatalf("%q is not declared as an OAuth credential key", key)
		}
	}

	authorized := f.config()
	if status := c.OAuthStatus(authorized); !status.Authorized || status.Account != "alice@example.com" {
		t.Fatalf("authorized status = %+v", status)
	}
	err = c.RevokeOAuth(t.Context(), authorized)
	if err != nil || !reflect.DeepEqual(f.revoked, []string{testRefreshToken}) {
		t.Fatalf("revoke = %v, %v", err, f.revoked)
	}
	if err := c.RevokeOAuth(t.Context(), draft); err != nil || len(f.revoked) != 1 {
		t.Fatalf("revoking an unauthorized source = %v", err)
	}
}

func TestExchangeRejectsBadCodesMissingRefreshTokensAndDeclinedScopes(t *testing.T) {
	f := newFakeDrive(t)
	c := f.connector()
	draft := &types.DataSourceConfig{Credentials: map[string]any{
		credClientID: testClientID, credClientSecret: testClientSecret,
	}}
	request := datasource.OAuthExchangeRequest{Code: "wrong", CodeVerifier: "v", RedirectURI: "https://kb.example/cb"}
	if _, err := c.ExchangeOAuthCode(t.Context(), draft, request); !errors.Is(err, datasource.ErrInvalidCredentials) {
		t.Fatalf("wrong code = %v", err)
	}
	request.Code = testAuthCode
	f.mu.Lock()
	f.grantedScope = "openid"
	f.mu.Unlock()
	if _, err := c.ExchangeOAuthCode(t.Context(), draft, request); !errors.Is(err, datasource.ErrInvalidCredentials) {
		t.Fatalf("declined scope = %v", err)
	}
	f.mu.Lock()
	f.grantedScope, f.refreshToken = driveScope, ""
	f.mu.Unlock()
	if _, err := c.ExchangeOAuthCode(t.Context(), draft, request); !errors.Is(err, datasource.ErrInvalidCredentials) {
		t.Fatalf("missing refresh token = %v", err)
	}
}

func TestPickerListsTopLevelFoldersAndRestoresAncestors(t *testing.T) {
	f := newFakeDrive(t)
	f.drives = []sharedDrive{{ID: "team", Name: "Team"}}
	f.put("team", &fakeFile{name: "Team", mime: mimeFolder, driveID: "team"})
	f.folder("specs", "Specs", "team")
	f.add("spec", "spec.pdf", "specs", "spec")
	f.folder("docs", "Docs", testMyDriveID)
	f.folder("deep", "Deep", "docs")
	f.add("pdf", "a.pdf", "deep", "a")
	f.add("zip", "a.zip", "docs", "z")
	f.doc("gdoc", "Plan", "docs", "p")
	f.put("gift", &fakeFile{name: "Gift", mime: mimeFolder, shared: true})
	f.add("inner", "inner.pdf", "gift", "i")
	c, cfg := f.connector(), f.config()

	top, err := c.ListResources(t.Context(), cfg, "")
	if err != nil || len(top) != 3 || top[0].ExternalID != rootID || top[1].ExternalID != sharedWithMeID ||
		top[2].ExternalID != "team" || !top[2].HasChildren {
		t.Fatalf("top level = %+v, %v", top, err)
	}
	names := func(parent string) string {
		t.Helper()
		resources, err := c.ListResources(t.Context(), cfg, parent)
		if err != nil {
			t.Fatalf("list %s: %v", parent, err)
		}
		var out []string
		for _, r := range resources {
			if r.ParentID != parent || r.HasChildren != (r.Type == "directory") {
				t.Fatalf("resource = %+v", r)
			}
			out = append(out, r.Type+":"+r.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(rootID); got != "directory:Docs" {
		t.Fatalf("My Drive = %s", got)
	}
	if got := names("docs"); got != "directory:Deep,file:Plan" {
		t.Fatalf("unsupported files must be hidden: %s", got)
	}
	if got := names("specs"); got != "file:spec.pdf" {
		t.Fatalf("shared drive folder = %s", got)
	}
	if got := names(sharedWithMeID); got != "directory:Gift" {
		t.Fatalf("shared with me = %s", got)
	}
	if _, err := c.ListResources(t.Context(), cfg, "missing"); !errors.Is(err, datasource.ErrResourceNotFound) {
		t.Fatalf("missing folder = %v", err)
	}
	if _, err := c.ListResources(t.Context(), cfg, "bad id"); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("invalid folder ID = %v", err)
	}
	draft := f.config()
	delete(draft.Credentials, credRefreshToken)
	if _, err := c.ListResources(t.Context(), draft, ""); !errors.Is(err, datasource.ErrInvalidCredentials) {
		t.Fatalf("unauthorized listing = %v", err)
	}

	ancestors, err := c.ResolveResourceAncestors(t.Context(), cfg,
		[]string{"pdf", "deep", "spec", "inner", "team", rootID, "missing", "bad id"})
	want := []string{"deep", "docs", "gift", rootID, sharedWithMeID, "specs", "team"}
	if err != nil || !reflect.DeepEqual(ancestors, want) {
		t.Fatalf("ancestors = %v, %v", ancestors, err)
	}
}

func TestBatchFetchAllUsesTheGivenSelection(t *testing.T) {
	f := newFakeDrive(t)
	f.folder("docs", "Docs", testMyDriveID)
	f.add("a", "a.pdf", "docs", "a")
	c := f.connector()
	items, err := c.FetchAll(t.Context(), f.config(), []string{"docs"})
	if err != nil || len(items) != 1 || c.Type() != types.ConnectorTypeGoogleDrive {
		t.Fatalf("FetchAll = %+v, %v", items, err)
	}
	if _, err := c.FetchAll(t.Context(), nil, nil); !errors.Is(err, datasource.ErrInvalidConfig) {
		t.Fatalf("nil config = %v", err)
	}
}
