package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Tencent/WeKnora/internal/application/service"
	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubDataSourceOAuthFlow struct {
	startErr, completeErr, attemptErr, revokeErr error
	status                                       types.DataSourceOAuthStatus
	attemptDone                                  bool
	started                                      []string
	completed                                    []string
	revoked                                      []string
}

func (s *stubDataSourceOAuthFlow) StartAuthorization(
	_ context.Context, ds *types.DataSource, redirectURI, frontendRedirect string,
) (string, string, error) {
	s.started = append(s.started, ds.ID+"|"+redirectURI+"|"+frontendRedirect)
	return "https://provider.example/auth?state=attempt-1", "attempt-1", s.startErr
}

func (s *stubDataSourceOAuthFlow) CompleteAuthorization(
	_ context.Context, state, code string,
) (service.DataSourceOAuthResult, error) {
	s.completed = append(s.completed, state+"|"+code)
	return service.DataSourceOAuthResult{FrontendRedirect: "/settings", DataSourceID: "ds-1"}, s.completeErr
}

func (s *stubDataSourceOAuthFlow) IsAttemptComplete(context.Context, *types.DataSource, string) (bool, error) {
	return s.attemptDone, s.attemptErr
}

func (s *stubDataSourceOAuthFlow) Status(*types.DataSource) (types.DataSourceOAuthStatus, error) {
	return s.status, nil
}

func (s *stubDataSourceOAuthFlow) Revoke(_ context.Context, ds *types.DataSource) error {
	s.revoked = append(s.revoked, ds.ID)
	return s.revokeErr
}

func newDataSourceOAuthTestRouter(flow *stubDataSourceOAuthFlow) *gin.Engine {
	h := &DataSourceOAuthHandler{
		oauth: flow,
		service: &stubDataSourceService{getDataSource: func(_ context.Context, id string) (*types.DataSource, error) {
			if id != "ds-1" {
				return nil, datasource.ErrDataSourceNotFound
			}
			return &types.DataSource{ID: id, TenantID: 7, KnowledgeBaseID: "kb-1", Type: "google_drive"}, nil
		}},
		kbService: &stubKBServiceForDS{getByID: func(context.Context, string) (*types.KnowledgeBase, error) {
			return &types.KnowledgeBase{ID: "kb-1", TenantID: 7}, nil
		}},
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(errorCapture())
	r.Use(func(c *gin.Context) {
		if tenantID, ok := c.Request.Context().Value(types.TenantIDContextKey).(uint64); ok {
			c.Set(types.TenantIDContextKey.String(), tenantID)
		}
		c.Next()
	})
	r.POST("/datasource/:id/oauth/authorize-url", h.AuthorizeURL)
	r.GET("/datasource/:id/oauth/status", h.Status)
	r.DELETE("/datasource/:id/oauth/token", h.Revoke)
	r.GET("/datasource-oauth/callback", h.Callback)
	return r
}

func serveDataSourceOAuth(r *gin.Engine, tenantID uint64, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenantID != 0 {
		req = withDSCtx(req, tenantID)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestDataSourceOAuthAuthorizeURL(t *testing.T) {
	flow := &stubDataSourceOAuthFlow{}
	r := newDataSourceOAuthTestRouter(flow)
	body := `{"redirect_uri":"https://kb.example/api/v1/datasource-oauth/callback","frontend_redirect":"/"}`

	w := serveDataSourceOAuth(r, 7, http.MethodPost, "/datasource/ds-1/oauth/authorize-url", body)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data map[string]string `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "attempt-1", resp.Data["authorization_attempt"])
	assert.Equal(t, "https://provider.example/auth?state=attempt-1", resp.Data["authorization_url"])
	assert.Equal(t, []string{"ds-1|https://kb.example/api/v1/datasource-oauth/callback|/"}, flow.started)

	// Another tenant's data source, a missing one and an anonymous caller.
	for target, tenant := range map[string]uint64{
		"/datasource/ds-1/oauth/authorize-url":    8,
		"/datasource/missing/oauth/authorize-url": 7,
	} {
		w = serveDataSourceOAuth(r, tenant, http.MethodPost, target, body)
		assert.Equal(t, http.StatusNotFound, w.Code, target)
	}
	w = serveDataSourceOAuth(r, 0, http.MethodPost, "/datasource/ds-1/oauth/authorize-url", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Len(t, flow.started, 1)

	w = serveDataSourceOAuth(r, 7, http.MethodPost, "/datasource/ds-1/oauth/authorize-url", `{}`)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	flow.startErr = datasource.ErrOAuthNotSupported
	w = serveDataSourceOAuth(r, 7, http.MethodPost, "/datasource/ds-1/oauth/authorize-url", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Internal causes are logged, never echoed.
	flow.startErr = errors.New("redis: connection refused at 10.0.0.5")
	w = serveDataSourceOAuth(r, 7, http.MethodPost, "/datasource/ds-1/oauth/authorize-url", body)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "10.0.0.5")
}

func TestDataSourceOAuthCallbackRedirectsWithoutLeakingDetails(t *testing.T) {
	flow := &stubDataSourceOAuthFlow{}
	r := newDataSourceOAuthTestRouter(flow)

	// The callback carries no tenant: the state authenticates it.
	w := serveDataSourceOAuth(r, 0, http.MethodGet, "/datasource-oauth/callback?state=s1&code=c1", "")
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/settings#datasource_oauth_result=success", w.Header().Get("Location"))
	assert.Equal(t, []string{"s1|c1"}, flow.completed)

	flow.completeErr = errors.New("token endpoint said: secret-detail")
	w = serveDataSourceOAuth(r, 0, http.MethodGet, "/datasource-oauth/callback?state=s2&code=c2", "")
	require.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/settings#datasource_oauth_error=authorization_failed", w.Header().Get("Location"))

	w = serveDataSourceOAuth(r, 0, http.MethodGet, "/datasource-oauth/callback?error=access_denied&state=s3", "")
	assert.Equal(t, "/#datasource_oauth_error=access_denied", w.Header().Get("Location"))
	w = serveDataSourceOAuth(r, 0, http.MethodGet, "/datasource-oauth/callback?state=s4", "")
	assert.Equal(t, "/#datasource_oauth_error=missing_code_or_state", w.Header().Get("Location"))
	assert.Len(t, flow.completed, 2, "no exchange without both a state and a code")
}

func TestDataSourceOAuthStatusAndRevoke(t *testing.T) {
	flow := &stubDataSourceOAuthFlow{
		status: types.DataSourceOAuthStatus{Authorized: true, Account: "alice@example.com"},
	}
	r := newDataSourceOAuthTestRouter(flow)
	status := func(target string) (int, types.DataSourceOAuthStatus) {
		w := serveDataSourceOAuth(r, 7, http.MethodGet, target, "")
		var resp struct {
			Data types.DataSourceOAuthStatus `json:"data"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Data
	}

	code, got := status("/datasource/ds-1/oauth/status")
	assert.Equal(t, http.StatusOK, code)
	assert.Equal(t, flow.status, got)

	// An older grant must not answer for an attempt that is still pending.
	code, got = status("/datasource/ds-1/oauth/status?authorization_attempt=attempt-1")
	assert.Equal(t, http.StatusOK, code)
	assert.False(t, got.Authorized)
	assert.Empty(t, got.Account)

	flow.attemptDone = true
	_, got = status("/datasource/ds-1/oauth/status?authorization_attempt=attempt-1")
	assert.Equal(t, flow.status, got)

	flow.attemptErr = datasource.ErrOAuthStateNotFound
	code, _ = status("/datasource/ds-1/oauth/status?authorization_attempt=expired")
	assert.Equal(t, http.StatusBadRequest, code)

	w := serveDataSourceOAuth(r, 7, http.MethodDelete, "/datasource/ds-1/oauth/token", "")
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, []string{"ds-1"}, flow.revoked)
	w = serveDataSourceOAuth(r, 8, http.MethodDelete, "/datasource/ds-1/oauth/token", "")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Len(t, flow.revoked, 1)
}
