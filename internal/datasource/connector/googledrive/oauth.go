package googledrive

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
)

var _ datasource.OAuthConnector = (*Connector)(nil)

// OAuthAuthorizationURL requests offline, read-only access. prompt=consent
// makes Google return a refresh token even when the account authorized this
// client before; without it a re-authorization yields no refresh token.
func (c *Connector) OAuthAuthorizationURL(
	ds *types.DataSourceConfig, req datasource.OAuthAuthorizationRequest,
) (string, error) {
	cfg, err := parseConfig(ds)
	if err != nil {
		return "", err
	}
	return c.ep.auth + "?" + url.Values{
		"client_id": {cfg.clientID}, "redirect_uri": {req.RedirectURI}, "response_type": {"code"},
		"scope": {driveScope}, "access_type": {"offline"}, "prompt": {"consent"}, "state": {req.State},
		"code_challenge": {req.CodeChallenge}, "code_challenge_method": {"S256"},
	}.Encode(), nil
}

// ExchangeOAuthCode redeems the code and records which account authorized.
func (c *Connector) ExchangeOAuthCode(
	ctx context.Context, ds *types.DataSourceConfig, req datasource.OAuthExchangeRequest,
) (map[string]interface{}, error) {
	cfg, err := parseConfig(ds)
	if err != nil {
		return nil, err
	}
	client := c.newClient(cfg)
	defer client.close()
	token, err := client.tokenRequest(ctx, url.Values{
		"grant_type": {"authorization_code"}, "code": {req.Code}, "code_verifier": {req.CodeVerifier},
		"redirect_uri": {req.RedirectURI}, "client_id": {cfg.clientID}, "client_secret": {cfg.clientSecret},
	})
	if err != nil {
		return nil, err
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("%w: Google did not issue a refresh token", datasource.ErrInvalidCredentials)
	}
	// Granular consent lets the user decline individual scopes.
	if token.Scope != "" && !strings.Contains(" "+token.Scope+" ", " "+driveScope+" ") {
		return nil, fmt.Errorf("%w: read access to Google Drive was not granted", datasource.ErrInvalidCredentials)
	}
	client.cfg.refreshToken = token.RefreshToken
	client.remember(token)
	email, accountID, err := client.about(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		credRefreshToken: token.RefreshToken, credAccountEmail: email, credAccountID: accountID,
	}, nil
}

// OAuthStatus reports whether a refresh token is stored.
func (*Connector) OAuthStatus(ds *types.DataSourceConfig) types.DataSourceOAuthStatus {
	if ds == nil || credential(ds, credRefreshToken) == "" {
		return types.DataSourceOAuthStatus{}
	}
	return types.DataSourceOAuthStatus{Authorized: true, Account: credential(ds, credAccountEmail)}
}

// OAuthCredentialKeys lists the keys written by ExchangeOAuthCode.
func (*Connector) OAuthCredentialKeys() []string {
	return []string{credRefreshToken, credAccountEmail, credAccountID}
}

// RevokeOAuth invalidates the refresh token at Google.
func (c *Connector) RevokeOAuth(ctx context.Context, ds *types.DataSourceConfig) error {
	cfg, err := parseConfig(ds)
	if err != nil || cfg.refreshToken == "" {
		return err
	}
	client := c.newClient(cfg)
	defer client.close()
	client.tokens.drop(client.cacheKey())
	form := url.Values{"token": {cfg.refreshToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ep.revoke, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: Google revoke request failed", datasource.ErrFetchFailed)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: Google revoke request failed", datasource.ErrFetchFailed)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return &apiError{op: "revoke", status: resp.StatusCode}
	}
	return nil
}
