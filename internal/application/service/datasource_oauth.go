package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/redis/go-redis/v9"
)

// dataSourceOAuthCallbackTimeout bounds the code exchange. The browser leaves
// as soon as it is redirected, which cancels the request context, so the
// exchange runs detached from it.
const dataSourceOAuthCallbackTimeout = 60 * time.Second

// DataSourceOAuthResult tells the callback where to send the browser and which
// data source the attempt belonged to.
type DataSourceOAuthResult struct {
	// FrontendRedirect is set as soon as the attempt's state has been read,
	// including when the exchange then fails.
	FrontendRedirect string
	TenantID         uint64
	DataSourceID     string
}

// DataSourceOAuthService runs the browser authorization-code flow for
// connectors implementing datasource.OAuthConnector. It is connector-agnostic:
// state, PKCE and persistence live here, everything provider-specific in the
// connector. The exchanged credentials are merged into the data source's
// encrypted credential map, next to the values the user entered.
type DataSourceOAuthService struct {
	dsRepo   interfaces.DataSourceRepository
	registry *datasource.ConnectorRegistry
	states   *datasource.OAuthStateStore
	audit    interfaces.AuditLogService
}

// NewDataSourceOAuthService creates the service. rdb may be nil, in which case
// in-flight authorizations are kept in memory.
func NewDataSourceOAuthService(
	dsRepo interfaces.DataSourceRepository,
	registry *datasource.ConnectorRegistry,
	rdb *redis.Client,
	audit interfaces.AuditLogService,
) *DataSourceOAuthService {
	return &DataSourceOAuthService{
		dsRepo: dsRepo, registry: registry, states: datasource.NewOAuthStateStore(rdb), audit: audit,
	}
}

func (s *DataSourceOAuthService) connectorFor(
	ds *types.DataSource,
) (datasource.OAuthConnector, *types.DataSourceConfig, error) {
	if ds == nil {
		return nil, nil, datasource.ErrDataSourceInvalid
	}
	connector, err := s.registry.Get(ds.Type)
	if err != nil {
		return nil, nil, err
	}
	oauthConnector, ok := connector.(datasource.OAuthConnector)
	if !ok {
		return nil, nil, datasource.ErrOAuthNotSupported
	}
	cfg, err := ds.ParseConfig()
	if err != nil {
		return nil, nil, datasource.ErrInvalidConfig
	}
	if cfg == nil {
		cfg = &types.DataSourceConfig{Type: ds.Type}
	}
	return oauthConnector, cfg, nil
}

// validateOAuthRedirectURI accepts only this deployment's callback route. The
// provider additionally compares it with the URIs registered for the client.
func validateOAuthRedirectURI(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || !strings.HasSuffix(u.Path, "/api/v1"+datasource.OAuthCallbackPath) {
		return "", fmt.Errorf("%w: redirect_uri must be this deployment's data source OAuth callback",
			datasource.ErrInvalidConfig)
	}
	return u.String(), nil
}

// validateOAuthFrontendRedirect accepts only an application-relative path, so
// the callback can never be used as an open redirect.
func validateOAuthFrontendRedirect(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" ||
		!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") || strings.ContainsAny(raw, "\\\r\n\t") {
		return "", fmt.Errorf("%w: frontend_redirect must be an application-relative path",
			datasource.ErrInvalidConfig)
	}
	return u.String(), nil
}

func randomURLToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// StartAuthorization returns the provider URL the browser must open and an
// opaque attempt ID the caller polls with IsAttemptComplete.
func (s *DataSourceOAuthService) StartAuthorization(
	ctx context.Context, ds *types.DataSource, redirectURI, frontendRedirect string,
) (authorizationURL, attemptID string, err error) {
	connector, cfg, err := s.connectorFor(ds)
	if err != nil {
		return "", "", err
	}
	if redirectURI, err = validateOAuthRedirectURI(redirectURI); err != nil {
		return "", "", err
	}
	if frontendRedirect, err = validateOAuthFrontendRedirect(frontendRedirect); err != nil {
		return "", "", err
	}
	verifier, err := randomURLToken()
	if err != nil {
		return "", "", fmt.Errorf("generate PKCE verifier: %w", err)
	}
	state, err := randomURLToken()
	if err != nil {
		return "", "", fmt.Errorf("generate state: %w", err)
	}
	challenge := sha256.Sum256([]byte(verifier))
	authorizationURL, err = connector.OAuthAuthorizationURL(cfg, datasource.OAuthAuthorizationRequest{
		State: state, CodeChallenge: base64.RawURLEncoding.EncodeToString(challenge[:]), RedirectURI: redirectURI,
	})
	if err != nil {
		return "", "", err
	}
	if err := s.states.Put(ctx, state, datasource.OAuthState{
		TenantID: ds.TenantID, DataSourceID: ds.ID, CodeVerifier: verifier,
		RedirectURI: redirectURI, FrontendRedirect: frontendRedirect,
	}); err != nil {
		return "", "", fmt.Errorf("persist authorization state: %w", err)
	}
	return authorizationURL, state, nil
}

// CompleteAuthorization handles the provider callback: it redeems the
// single-use state, exchanges the code and stores the resulting credentials.
func (s *DataSourceOAuthService) CompleteAuthorization(
	ctx context.Context, state, code string,
) (DataSourceOAuthResult, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dataSourceOAuthCallbackTimeout)
	defer cancel()

	st, err := s.states.Take(ctx, state)
	if err != nil {
		return DataSourceOAuthResult{}, err
	}
	result := DataSourceOAuthResult{
		FrontendRedirect: st.FrontendRedirect, TenantID: st.TenantID, DataSourceID: st.DataSourceID,
	}
	// Re-read the row: the user may have edited or deleted it since the
	// authorization started.
	ds, err := s.dsRepo.FindByID(ctx, st.DataSourceID)
	if err != nil {
		return result, err
	}
	if ds.TenantID != st.TenantID {
		return result, datasource.ErrDataSourceNotFound
	}
	connector, cfg, err := s.connectorFor(ds)
	if err != nil {
		return result, err
	}
	granted, err := connector.ExchangeOAuthCode(ctx, cfg, datasource.OAuthExchangeRequest{
		Code: code, CodeVerifier: st.CodeVerifier, RedirectURI: st.RedirectURI,
	})
	if err != nil {
		return result, fmt.Errorf("authorization code exchange failed: %w", err)
	}
	if cfg.Credentials == nil {
		cfg.Credentials = make(map[string]interface{})
	}
	for _, key := range connector.OAuthCredentialKeys() {
		if value, ok := granted[key]; ok {
			cfg.Credentials[key] = value
		}
	}
	if err := s.saveConfig(ctx, ds, cfg); err != nil {
		return result, err
	}
	if err := s.states.CompleteAttempt(ctx, state); err != nil {
		// The grant is stored; only the opener's poll loses its shortcut.
		logger.Warnf(ctx, "data source OAuth attempt could not be marked complete: %v", err)
	}
	logger.Infof(ctx, "data source authorized via OAuth: id=%s", secutils.SanitizeForLog(ds.ID))
	s.recordCredentialChange(ctx, ds)
	return result, nil
}

func (s *DataSourceOAuthService) saveConfig(
	ctx context.Context, ds *types.DataSource, cfg *types.DataSourceConfig,
) error {
	blob, err := cfg.ToJSON()
	if err != nil {
		return err
	}
	ds.Config = blob
	return s.dsRepo.Update(ctx, ds)
}

func (s *DataSourceOAuthService) recordCredentialChange(ctx context.Context, ds *types.DataSource) {
	recordKBActivity(ctx, s.audit, ds.TenantID, ds.KnowledgeBaseID, types.AuditActionDataSourceUpdated,
		"data_source", ds.ID, types.AuditOutcomeSuccess,
		map[string]any{"name": ds.Name, "type": ds.Type, "changed_fields": []string{"credentials"}})
}

// IsAttemptComplete reports whether the given attempt, and not an earlier
// authorization of the same data source, has stored its credentials.
func (s *DataSourceOAuthService) IsAttemptComplete(
	ctx context.Context, ds *types.DataSource, attemptID string,
) (bool, error) {
	if ds == nil {
		return false, datasource.ErrDataSourceInvalid
	}
	attempt, err := s.states.Attempt(ctx, attemptID)
	if err != nil {
		return false, err
	}
	if attempt.TenantID != ds.TenantID || attempt.DataSourceID != ds.ID {
		return false, errors.New("oauth authorization attempt does not match the data source")
	}
	return attempt.Completed, nil
}

// Status reports whether the data source currently holds a grant.
func (s *DataSourceOAuthService) Status(ds *types.DataSource) (types.DataSourceOAuthStatus, error) {
	connector, cfg, err := s.connectorFor(ds)
	if err != nil {
		return types.DataSourceOAuthStatus{}, err
	}
	return connector.OAuthStatus(cfg), nil
}

// Revoke removes the credentials the flow produced and asks the provider to
// invalidate them. The values the user entered are kept, so the data source
// can be authorized again without re-typing them.
func (s *DataSourceOAuthService) Revoke(ctx context.Context, ds *types.DataSource) error {
	connector, cfg, err := s.connectorFor(ds)
	if err != nil {
		return err
	}
	if !connector.OAuthStatus(cfg).Authorized {
		return nil
	}
	if err := connector.RevokeOAuth(ctx, cfg); err != nil {
		logger.Warnf(ctx, "provider-side OAuth revocation failed for data source %s: %v",
			secutils.SanitizeForLog(ds.ID), err)
	}
	for _, key := range connector.OAuthCredentialKeys() {
		delete(cfg.Credentials, key)
	}
	if err := s.saveConfig(ctx, ds, cfg); err != nil {
		return err
	}
	logger.Infof(ctx, "data source OAuth authorization revoked: id=%s", secutils.SanitizeForLog(ds.ID))
	s.recordCredentialChange(ctx, ds)
	return nil
}
