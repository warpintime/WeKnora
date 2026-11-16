package datasource

import (
	"context"
	"errors"

	"github.com/Tencent/WeKnora/internal/types"
)

// OAuthCallbackPath is the public route, below the API prefix, that providers
// redirect the browser to. Every connector shares it; the state parameter
// identifies the data source.
const OAuthCallbackPath = "/datasource-oauth/callback"

// ErrOAuthNotSupported means the connector does not use an authorization flow.
var ErrOAuthNotSupported = errors.New("connector does not support OAuth authorization")

// OAuthAuthorizationRequest carries the per-attempt values a connector must
// place in the provider's authorization URL.
type OAuthAuthorizationRequest struct {
	// State is the opaque, single-use value the provider echoes to the callback.
	State string
	// CodeChallenge is the S256 PKCE challenge of the verifier kept server-side.
	CodeChallenge string
	// RedirectURI is the WeKnora callback registered with the provider.
	RedirectURI string
}

// OAuthExchangeRequest carries what the callback received, plus the PKCE
// verifier and redirect URI the attempt started with.
type OAuthExchangeRequest struct {
	Code         string
	CodeVerifier string
	RedirectURI  string
}

// OAuthConnector is an optional interface for connectors whose credentials are
// completed by a browser authorization-code flow instead of a pasted token.
//
// The connector owns everything provider-specific: endpoints, scopes, the code
// exchange and which credential keys the flow produces. The service owns the
// flow itself: state, PKCE, the callback route and persistence. The user-entered
// part of the credentials (typically an OAuth client ID and secret) is stored
// before the flow starts and is passed to every method in config.
type OAuthConnector interface {
	Connector

	// OAuthAuthorizationURL returns the provider URL the browser must open.
	OAuthAuthorizationURL(config *types.DataSourceConfig, req OAuthAuthorizationRequest) (string, error)

	// ExchangeOAuthCode trades the authorization code for long-lived
	// credentials. The returned entries are merged into the stored credential
	// map; every key must be one of OAuthCredentialKeys.
	ExchangeOAuthCode(
		ctx context.Context, config *types.DataSourceConfig, req OAuthExchangeRequest,
	) (map[string]interface{}, error)

	// OAuthStatus reports, from the stored credentials alone and without a
	// network call, whether the flow has been completed and for which account.
	OAuthStatus(config *types.DataSourceConfig) types.DataSourceOAuthStatus

	// OAuthCredentialKeys lists the credential keys the flow owns. They are
	// removed when access is revoked; all other keys are left in place.
	OAuthCredentialKeys() []string

	// RevokeOAuth asks the provider to invalidate the stored grant. It is best
	// effort: local credentials are removed whether or not it succeeds.
	RevokeOAuth(ctx context.Context, config *types.DataSourceConfig) error
}
