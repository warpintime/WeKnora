package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const oauthTestRedirect = "https://kb.example/api/v1/datasource-oauth/callback"

// oauthTestConnector is a provider-agnostic OAuthConnector: it issues a token
// for one valid code and records what the service passed to it.
type oauthTestConnector struct {
	datasource.Connector
	exchanges   []datasource.OAuthExchangeRequest
	revoked     int
	revokeErr   error
	extraSecret bool
}

func (*oauthTestConnector) Type() string { return "oauth_test" }

func (*oauthTestConnector) OAuthAuthorizationURL(
	cfg *types.DataSourceConfig, req datasource.OAuthAuthorizationRequest,
) (string, error) {
	clientID, _ := cfg.Credentials["client_id"].(string)
	if clientID == "" {
		return "", datasource.ErrInvalidConfig
	}
	return "https://provider.example/auth?" + url.Values{
		"client_id": {clientID}, "state": {req.State}, "code_challenge": {req.CodeChallenge},
		"redirect_uri": {req.RedirectURI},
	}.Encode(), nil
}

func (c *oauthTestConnector) ExchangeOAuthCode(
	_ context.Context, _ *types.DataSourceConfig, req datasource.OAuthExchangeRequest,
) (map[string]interface{}, error) {
	c.exchanges = append(c.exchanges, req)
	if req.Code != "good-code" {
		return nil, datasource.ErrInvalidCredentials
	}
	granted := map[string]interface{}{"refresh_token": "refresh-1", "account_email": "alice@example.com"}
	if c.extraSecret {
		granted["client_secret"] = "overwritten"
	}
	return granted, nil
}

func (*oauthTestConnector) OAuthStatus(cfg *types.DataSourceConfig) types.DataSourceOAuthStatus {
	token, _ := cfg.Credentials["refresh_token"].(string)
	account, _ := cfg.Credentials["account_email"].(string)
	return types.DataSourceOAuthStatus{Authorized: token != "", Account: account}
}

func (*oauthTestConnector) OAuthCredentialKeys() []string {
	return []string{"refresh_token", "account_email"}
}

func (c *oauthTestConnector) RevokeOAuth(context.Context, *types.DataSourceConfig) error {
	c.revoked++
	return c.revokeErr
}

type plainTestConnector struct{ datasource.Connector }

func (*plainTestConnector) Type() string { return "plain_test" }

type oauthTestRepo struct {
	interfaces.DataSourceRepository
	rows    map[string]*types.DataSource
	updates int
}

func (r *oauthTestRepo) FindByID(_ context.Context, id string) (*types.DataSource, error) {
	row, ok := r.rows[id]
	if !ok {
		return nil, datasource.ErrDataSourceNotFound
	}
	cp := *row
	return &cp, nil
}

func (r *oauthTestRepo) Update(_ context.Context, ds *types.DataSource) error {
	cp := *ds
	r.rows[ds.ID] = &cp
	r.updates++
	return nil
}

type oauthTestEnv struct {
	svc       *DataSourceOAuthService
	repo      *oauthTestRepo
	connector *oauthTestConnector
}

func newOAuthTestEnv(t *testing.T) *oauthTestEnv {
	t.Helper()
	registry := datasource.NewConnectorRegistry()
	connector := &oauthTestConnector{}
	require.NoError(t, registry.Register(connector))
	require.NoError(t, registry.Register(&plainTestConnector{}))
	repo := &oauthTestRepo{rows: map[string]*types.DataSource{}}
	env := &oauthTestEnv{svc: NewDataSourceOAuthService(repo, registry, nil, nil), repo: repo, connector: connector}
	env.put(t, "ds-1", "oauth_test", map[string]interface{}{"client_id": "client-1", "client_secret": "secret-1"})
	return env
}

func (e *oauthTestEnv) put(t *testing.T, id, connectorType string, credentials map[string]interface{}) {
	t.Helper()
	cfg := &types.DataSourceConfig{Type: connectorType, Credentials: credentials, ResourceIDs: []string{"root"}}
	blob, err := cfg.ToJSON()
	require.NoError(t, err)
	e.repo.rows[id] = &types.DataSource{
		ID: id, TenantID: 7, KnowledgeBaseID: "kb-1", Type: connectorType, Name: "Drive", Config: blob,
	}
}

func (e *oauthTestEnv) row(t *testing.T, id string) (*types.DataSource, *types.DataSourceConfig) {
	t.Helper()
	ds, err := e.repo.FindByID(t.Context(), id)
	require.NoError(t, err)
	cfg, err := ds.ParseConfig()
	require.NoError(t, err)
	return ds, cfg
}

func TestDataSourceOAuthFlowStoresTheGrantNextToUserCredentials(t *testing.T) {
	env := newOAuthTestEnv(t)
	ctx := t.Context()
	ds, _ := env.row(t, "ds-1")

	authURL, attempt, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/settings?tab=sources")
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	query := u.Query()
	assert.Equal(t, attempt, query.Get("state"))
	assert.Equal(t, oauthTestRedirect, query.Get("redirect_uri"))
	assert.NotContains(t, authURL, "secret-1")

	done, err := env.svc.IsAttemptComplete(ctx, ds, attempt)
	require.NoError(t, err)
	assert.False(t, done, "an attempt is pending until the callback stores the grant")

	result, err := env.svc.CompleteAuthorization(ctx, attempt, "good-code")
	require.NoError(t, err)
	assert.Equal(t, DataSourceOAuthResult{
		FrontendRedirect: "/settings?tab=sources", TenantID: 7, DataSourceID: "ds-1",
	}, result)

	// The verifier sent to the provider is the one whose S256 hash was in the URL.
	require.Len(t, env.connector.exchanges, 1)
	exchange := env.connector.exchanges[0]
	challenge := sha256.Sum256([]byte(exchange.CodeVerifier))
	assert.Equal(t, query.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(challenge[:]))
	assert.Equal(t, oauthTestRedirect, exchange.RedirectURI)

	stored, cfg := env.row(t, "ds-1")
	assert.Equal(t, map[string]interface{}{
		"client_id": "client-1", "client_secret": "secret-1",
		"refresh_token": "refresh-1", "account_email": "alice@example.com",
	}, cfg.Credentials)
	assert.Equal(t, []string{"root"}, cfg.ResourceIDs)
	status, err := env.svc.Status(stored)
	require.NoError(t, err)
	assert.Equal(t, types.DataSourceOAuthStatus{Authorized: true, Account: "alice@example.com"}, status)
	done, err = env.svc.IsAttemptComplete(ctx, stored, attempt)
	require.NoError(t, err)
	assert.True(t, done)

	// A state is single-use: replaying the callback changes nothing.
	_, err = env.svc.CompleteAuthorization(ctx, attempt, "good-code")
	assert.ErrorIs(t, err, datasource.ErrOAuthStateNotFound)
	assert.Len(t, env.connector.exchanges, 1)
}

func TestDataSourceOAuthFailedExchangeStoresNothing(t *testing.T) {
	env := newOAuthTestEnv(t)
	ctx := t.Context()
	ds, _ := env.row(t, "ds-1")
	_, attempt, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/")
	require.NoError(t, err)

	result, err := env.svc.CompleteAuthorization(ctx, attempt, "bad-code")
	assert.ErrorIs(t, err, datasource.ErrInvalidCredentials)
	assert.Equal(t, "/", result.FrontendRedirect, "the browser still returns to the application")
	assert.Zero(t, env.repo.updates)
	done, err := env.svc.IsAttemptComplete(ctx, ds, attempt)
	require.NoError(t, err)
	assert.False(t, done)

	_, err = env.svc.CompleteAuthorization(ctx, "never-issued", "good-code")
	assert.ErrorIs(t, err, datasource.ErrOAuthStateNotFound)
}

func TestDataSourceOAuthOnlyDeclaredKeysAreMerged(t *testing.T) {
	env := newOAuthTestEnv(t)
	env.connector.extraSecret = true
	ds, _ := env.row(t, "ds-1")
	_, attempt, err := env.svc.StartAuthorization(t.Context(), ds, oauthTestRedirect, "")
	require.NoError(t, err)
	_, err = env.svc.CompleteAuthorization(t.Context(), attempt, "good-code")
	require.NoError(t, err)
	_, cfg := env.row(t, "ds-1")
	assert.Equal(t, "secret-1", cfg.Credentials["client_secret"])
}

func TestDataSourceOAuthCallbackRechecksTheRow(t *testing.T) {
	env := newOAuthTestEnv(t)
	ctx := t.Context()
	ds, _ := env.row(t, "ds-1")

	_, deleted, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/")
	require.NoError(t, err)
	_, moved, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/")
	require.NoError(t, err)

	env.repo.rows["ds-1"].TenantID = 8
	_, err = env.svc.CompleteAuthorization(ctx, moved, "good-code")
	assert.ErrorIs(t, err, datasource.ErrDataSourceNotFound)

	delete(env.repo.rows, "ds-1")
	_, err = env.svc.CompleteAuthorization(ctx, deleted, "good-code")
	assert.ErrorIs(t, err, datasource.ErrDataSourceNotFound)
	assert.Empty(t, env.connector.exchanges, "no code is redeemed for a row that is gone")
}

func TestDataSourceOAuthRejectsUnsafeRedirectsAndForeignAttempts(t *testing.T) {
	env := newOAuthTestEnv(t)
	ctx := t.Context()
	ds, _ := env.row(t, "ds-1")

	for _, redirectURI := range []string{
		"", "/api/v1/datasource-oauth/callback", "https://kb.example/elsewhere",
		"https://user@kb.example/api/v1/datasource-oauth/callback",
		"https://kb.example/api/v1/datasource-oauth/callback?next=x",
		"javascript://kb.example/api/v1/datasource-oauth/callback",
	} {
		_, _, err := env.svc.StartAuthorization(ctx, ds, redirectURI, "/")
		assert.ErrorIs(t, err, datasource.ErrInvalidConfig, "redirect_uri %q", redirectURI)
	}
	for _, frontendRedirect := range []string{
		"https://evil.example/", "//evil.example/", "settings", "/a\\b", "/ok#fragment",
	} {
		_, _, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, frontendRedirect)
		assert.ErrorIs(t, err, datasource.ErrInvalidConfig, "frontend_redirect %q", frontendRedirect)
	}

	_, attempt, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/")
	require.NoError(t, err)
	env.put(t, "ds-2", "oauth_test", map[string]interface{}{"client_id": "client-2"})
	other, _ := env.row(t, "ds-2")
	_, err = env.svc.IsAttemptComplete(ctx, other, attempt)
	assert.Error(t, err, "an attempt cannot be polled through another data source")

	env.put(t, "ds-3", "plain_test", map[string]interface{}{"token": "t"})
	plain, _ := env.row(t, "ds-3")
	_, _, err = env.svc.StartAuthorization(ctx, plain, oauthTestRedirect, "/")
	assert.ErrorIs(t, err, datasource.ErrOAuthNotSupported)
	_, err = env.svc.Status(plain)
	assert.ErrorIs(t, err, datasource.ErrOAuthNotSupported)
}

func TestDataSourceOAuthRevokeKeepsUserCredentials(t *testing.T) {
	env := newOAuthTestEnv(t)
	ctx := t.Context()
	ds, _ := env.row(t, "ds-1")

	require.NoError(t, env.svc.Revoke(ctx, ds))
	assert.Zero(t, env.connector.revoked, "nothing to revoke before authorization")
	assert.Zero(t, env.repo.updates)

	_, attempt, err := env.svc.StartAuthorization(ctx, ds, oauthTestRedirect, "/")
	require.NoError(t, err)
	_, err = env.svc.CompleteAuthorization(ctx, attempt, "good-code")
	require.NoError(t, err)

	// The provider being unreachable must not keep the grant stored locally.
	env.connector.revokeErr = errors.New("provider unreachable")
	authorized, _ := env.row(t, "ds-1")
	require.NoError(t, env.svc.Revoke(ctx, authorized))
	assert.Equal(t, 1, env.connector.revoked)
	stored, cfg := env.row(t, "ds-1")
	assert.Equal(t, map[string]interface{}{"client_id": "client-1", "client_secret": "secret-1"}, cfg.Credentials)
	status, err := env.svc.Status(stored)
	require.NoError(t, err)
	assert.False(t, status.Authorized)
}
