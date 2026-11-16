package handler

import (
	"context"
	stderrors "errors"
	"net/http"
	"strings"

	"github.com/Tencent/WeKnora/internal/application/service"
	"github.com/Tencent/WeKnora/internal/datasource"
	"github.com/Tencent/WeKnora/internal/errors"
	"github.com/Tencent/WeKnora/internal/logger"
	"github.com/Tencent/WeKnora/internal/types"
	"github.com/Tencent/WeKnora/internal/types/interfaces"
	secutils "github.com/Tencent/WeKnora/internal/utils"
	"github.com/gin-gonic/gin"
)

// dataSourceOAuthFlow is the part of service.DataSourceOAuthService the
// handler drives.
type dataSourceOAuthFlow interface {
	StartAuthorization(
		ctx context.Context, ds *types.DataSource, redirectURI, frontendRedirect string,
	) (authorizationURL, attemptID string, err error)
	CompleteAuthorization(ctx context.Context, state, code string) (service.DataSourceOAuthResult, error)
	IsAttemptComplete(ctx context.Context, ds *types.DataSource, attemptID string) (bool, error)
	Status(ds *types.DataSource) (types.DataSourceOAuthStatus, error)
	Revoke(ctx context.Context, ds *types.DataSource) error
}

// DataSourceOAuthHandler exposes the browser authorization flow of data
// sources whose connector signs in at the provider (for example Google Drive)
// instead of accepting a pasted token.
type DataSourceOAuthHandler struct {
	oauth     dataSourceOAuthFlow
	service   interfaces.DataSourceService
	kbService interfaces.KnowledgeBaseService
}

// NewDataSourceOAuthHandler constructs the handler.
func NewDataSourceOAuthHandler(
	oauth *service.DataSourceOAuthService,
	dsService interfaces.DataSourceService,
	kbService interfaces.KnowledgeBaseService,
) *DataSourceOAuthHandler {
	return &DataSourceOAuthHandler{oauth: oauth, service: dsService, kbService: kbService}
}

// ownDataSource applies the same tenant isolation as the other data source
// handlers; a foreign or missing row is reported as not found.
func (h *DataSourceOAuthHandler) ownDataSource(c *gin.Context) (*types.DataSource, bool) {
	ctx := c.Request.Context()
	tenantID := c.GetUint64(types.TenantIDContextKey.String())
	if tenantID == 0 {
		_ = c.Error(errors.NewUnauthorizedError("authentication required"))
		return nil, false
	}
	ds, err := h.service.GetDataSource(ctx, c.Param("id"))
	if err != nil || ds == nil {
		_ = c.Error(errors.NewNotFoundError("data source not found"))
		return nil, false
	}
	kb, err := h.kbService.GetKnowledgeBaseByID(ctx, ds.KnowledgeBaseID)
	if err != nil || kb == nil || kb.TenantID != tenantID || ds.TenantID != tenantID {
		_ = c.Error(errors.NewNotFoundError("data source not found"))
		return nil, false
	}
	if err := types.AuthorizeTenantAPIKeyKnowledgeBases(ctx, ds.KnowledgeBaseID); err != nil {
		_ = c.Error(errors.NewForbiddenError(err.Error()))
		return nil, false
	}
	return ds, true
}

func (h *DataSourceOAuthHandler) fail(c *gin.Context, ds *types.DataSource, action string, err error) {
	if stderrors.Is(err, datasource.ErrOAuthNotSupported) || stderrors.Is(err, datasource.ErrInvalidConfig) {
		_ = c.Error(errors.NewValidationError(err.Error()))
		return
	}
	logger.ErrorWithFields(c.Request.Context(), err, map[string]interface{}{
		"data_source_id": secutils.SanitizeForLog(ds.ID),
	})
	_ = c.Error(errors.NewInternalServerError("failed to " + action))
}

type dataSourceOAuthAuthorizeRequest struct {
	// RedirectURI is the absolute backend callback URL registered with the
	// provider, e.g. https://host/api/v1/datasource-oauth/callback.
	RedirectURI string `json:"redirect_uri"`
	// FrontendRedirect is the application-relative path the callback sends the
	// browser to when done. Optional; defaults to "/".
	FrontendRedirect string `json:"frontend_redirect"`
}

// AuthorizeURL godoc
// @Summary      发起数据源 OAuth 授权
// @Description  为使用浏览器授权流程的数据源（如 Google Drive）生成授权地址。数据源需已保存 OAuth 客户端凭据
// @Tags         数据源
// @Accept       json
// @Produce      json
// @Param        id       path      string                  true  "数据源 ID"
// @Param        request  body      map[string]interface{}  true  "{redirect_uri: string, frontend_redirect?: string}"
// @Success      200      {object}  map[string]interface{}  "{authorization_url: string, authorization_attempt: string}"
// @Failure      400      {object}  errors.AppError
// @Failure      404      {object}  errors.AppError
// @Security     Bearer
// @Router       /datasource/{id}/oauth/authorize-url [post]
func (h *DataSourceOAuthHandler) AuthorizeURL(c *gin.Context) {
	ds, ok := h.ownDataSource(c)
	if !ok {
		return
	}
	var req dataSourceOAuthAuthorizeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(errors.NewBadRequestError("invalid request body"))
		return
	}
	if strings.TrimSpace(req.RedirectURI) == "" {
		_ = c.Error(errors.NewValidationError("redirect_uri is required"))
		return
	}
	authURL, attemptID, err := h.oauth.StartAuthorization(
		c.Request.Context(), ds, req.RedirectURI, req.FrontendRedirect,
	)
	if err != nil {
		h.fail(c, ds, "start authorization", err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{
		"authorization_url":     authURL,
		"authorization_attempt": attemptID,
	}})
}

// Callback receives the provider redirect. It is a public route: the browser
// arrives from a third party without a WeKnora bearer, and the opaque
// single-use state parameter authenticates the request. The outcome is passed
// to the frontend in the URL fragment, which is never sent to a server.
//
// Callback godoc
// @Summary      数据源 OAuth 回调
// @Description  接收授权服务器回调并完成 code 交换，随后重定向回前端
// @Tags         数据源
// @Param        code   query  string  false  "授权码"
// @Param        state  query  string  false  "状态参数"
// @Param        error  query  string  false  "授权错误码"
// @Success      302
// @Router       /datasource-oauth/callback [get]
func (h *DataSourceOAuthHandler) Callback(c *gin.Context) {
	ctx := c.Request.Context()
	state := strings.TrimSpace(c.Query("state"))
	code := strings.TrimSpace(c.Query("code"))

	const fallbackRedirect = "/"
	if providerErr := strings.TrimSpace(c.Query("error")); providerErr != "" {
		c.Redirect(http.StatusFound, fallbackRedirect+"#datasource_oauth_error="+urlQueryEscape(providerErr))
		return
	}
	if state == "" || code == "" {
		c.Redirect(http.StatusFound, fallbackRedirect+"#datasource_oauth_error=missing_code_or_state")
		return
	}
	result, err := h.oauth.CompleteAuthorization(ctx, state, code)
	frontendRedirect := result.FrontendRedirect
	if frontendRedirect == "" {
		frontendRedirect = fallbackRedirect
	}
	if err != nil {
		logger.Errorf(ctx, "data source OAuth callback failed: %v", err)
		c.Redirect(http.StatusFound, frontendRedirect+"#datasource_oauth_error=authorization_failed")
		return
	}
	c.Redirect(http.StatusFound, frontendRedirect+"#datasource_oauth_result=success")
}

// Status godoc
// @Summary      查询数据源 OAuth 授权状态
// @Description  返回数据源是否已授权及授权账号；传 authorization_attempt 时只检查本次授权流程是否完成
// @Tags         数据源
// @Produce      json
// @Param        id                     path   string  true   "数据源 ID"
// @Param        authorization_attempt  query  string  false  "本次授权尝试 ID；传入后不会接受历史授权"
// @Success      200  {object}  handler.DataResponse{data=types.DataSourceOAuthStatus}
// @Failure      400  {object}  errors.AppError
// @Failure      404  {object}  errors.AppError
// @Security     Bearer
// @Router       /datasource/{id}/oauth/status [get]
func (h *DataSourceOAuthHandler) Status(c *gin.Context) {
	ds, ok := h.ownDataSource(c)
	if !ok {
		return
	}
	status, err := h.oauth.Status(ds)
	if err != nil {
		h.fail(c, ds, "query authorization status", err)
		return
	}
	if attemptID := strings.TrimSpace(c.Query("authorization_attempt")); attemptID != "" {
		completed, err := h.oauth.IsAttemptComplete(c.Request.Context(), ds, attemptID)
		if err != nil {
			_ = c.Error(errors.NewBadRequestError("authorization attempt not found or expired"))
			return
		}
		if !completed {
			status = types.DataSourceOAuthStatus{}
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": status})
}

// Revoke godoc
// @Summary      撤销数据源 OAuth 授权
// @Description  删除授权流程写入的令牌并通知授权服务器失效；用户填写的客户端凭据保留
// @Tags         数据源
// @Param        id  path  string  true  "数据源 ID"
// @Success      204
// @Failure      400  {object}  errors.AppError
// @Failure      404  {object}  errors.AppError
// @Security     Bearer
// @Router       /datasource/{id}/oauth/token [delete]
func (h *DataSourceOAuthHandler) Revoke(c *gin.Context) {
	ds, ok := h.ownDataSource(c)
	if !ok {
		return
	}
	if err := h.oauth.Revoke(c.Request.Context(), ds); err != nil {
		h.fail(c, ds, "revoke authorization", err)
		return
	}
	c.Status(http.StatusNoContent)
}
