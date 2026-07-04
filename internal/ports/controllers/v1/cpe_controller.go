package v1

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"

	"device-api/internal/app"
	"device-api/internal/app/command"
	"device-api/internal/app/query"
	"device-api/internal/cpe"
	"device-api/internal/tcerr"

	"github.com/gin-gonic/gin"
)

func NewCpeController(app *app.Application, logger *slog.Logger) *CpeController {
	return &CpeController{app: app, logger: logger}
}

type CpeController struct {
	app    *app.Application
	logger *slog.Logger
}

type collectRequest struct {
	IP    string `json:"ip"`
	Port  int    `json:"port,omitempty"`
	Model string `json:"model,omitempty"`
} // @Name CollectRequest

type actionRequest struct {
	IP     string            `json:"ip" example:"10.0.0.1"`
	Port   int               `json:"port,omitempty" example:"60022"`
	Model  string            `json:"model,omitempty" example:"F1X"`
	Action string            `json:"action" example:"reboot"`
	Params map[string]string `json:"params,omitempty"`
	DryRun bool              `json:"dryRun,omitempty" example:"true"`
} // @Name ActionRequest

// Collect is a gin handler function.
// @Summary Collect CPE diagnostics
// @Description Returns parsed diagnostics collected over SSH.
// @Tags CPE
// @Produce json
// @Security BearerAuth
// @Param ip query string false "Target CPE IP"
// @Param port query int false "Target SSH port (defaults per model)"
// @Param model query string false "Model (VANTIVA/F1X/EWA/FMG/P2812/VMG/AX/EX)"
// @Param raw query bool false "Include raw command output"
// @Param includePsk query bool false "Include cleartext PSK values"
// @Success 200 {object} cpe.CollectResponse
// @Failure 400 {object} tcerr.ErrorEnvelope
// @Failure 401 {object} tcerr.ErrorEnvelope
// @Failure 403 {object} tcerr.ErrorEnvelope
// @Failure 413 {object} tcerr.ErrorEnvelope
// @Failure 429 {object} tcerr.ErrorEnvelope
// @Failure 502 {object} cpe.CollectResponse
// @Router /v1/cpe/collect [get]
func (controller *CpeController) Collect(c *gin.Context) {
	controller.collect(c)
}

// CollectPost is a gin handler function.
// @Summary Collect CPE diagnostics (JSON body)
// @Description Same as GET but takes a JSON body. Returns parsed diagnostics collected over SSH.
// @Tags CPE
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param payload body collectRequest true "Target CPE data"
// @Success 200 {object} cpe.CollectResponse
// @Failure 400 {object} tcerr.ErrorEnvelope
// @Failure 401 {object} tcerr.ErrorEnvelope
// @Failure 403 {object} tcerr.ErrorEnvelope
// @Failure 413 {object} tcerr.ErrorEnvelope
// @Failure 429 {object} tcerr.ErrorEnvelope
// @Failure 502 {object} cpe.CollectResponse
// @Router /v1/cpe/collect [post]
func (controller *CpeController) CollectPost(c *gin.Context) {
	controller.collect(c)
}

func (controller *CpeController) collect(c *gin.Context) {
	var req collectRequest
	if c.Request.Method == http.MethodGet {
		req.IP = c.Query("ip")
		req.Model = c.Query("model")
		if p := strings.TrimSpace(c.Query("port")); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil {
				_ = c.Error(tcerr.WrapRequestValidationError(errors.New("invalid port")))
				return
			}
			req.Port = n
		}
	} else if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(tcerr.WrapRequestValidationError(err))
		return
	}

	target, err := resolveTarget(req.IP, req.Port, req.Model)
	if err != nil {
		_ = c.Error(err)
		return
	}

	response, err := controller.app.Queries.CollectCpeInfo.Handle(c.Request.Context(), query.CollectCpeInfo{
		IP:   target.ip,
		Port: target.port,
		Options: cpe.CollectOptions{
			IncludeRaw: queryFlag(c, "raw"),
			IncludePSK: queryFlag(c, "includePsk"),
			Model:      target.model,
		},
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	if response.SSHFailed {
		c.JSON(http.StatusBadGateway, response)
		return
	}
	c.JSON(http.StatusOK, response)
}

// PerformAction is a gin handler function.
// @Summary Perform an action on a CPE
// @Description Executes a model-aware action (reboot, semi_reset, factory_reset) over SSH. Supports dryRun.
// @Tags CPE
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param payload body actionRequest true "Action request"
// @Success 200 {object} cpe.ActionResponse
// @Failure 400 {object} tcerr.ErrorEnvelope
// @Failure 401 {object} tcerr.ErrorEnvelope
// @Failure 403 {object} tcerr.ErrorEnvelope
// @Failure 413 {object} tcerr.ErrorEnvelope
// @Failure 429 {object} tcerr.ErrorEnvelope
// @Failure 502 {object} cpe.ActionResponse
// @Router /v1/cpe/actions [post]
func (controller *CpeController) PerformAction(c *gin.Context) {
	var req actionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(tcerr.WrapRequestValidationError(err))
		return
	}

	target, err := resolveTarget(req.IP, req.Port, req.Model)
	if err != nil {
		_ = c.Error(err)
		return
	}

	action := strings.TrimSpace(req.Action)
	if action == "" {
		_ = c.Error(tcerr.WrapRequestValidationError(errors.New("missing action")))
		return
	}
	if !cpe.IsActionTokenSafe(action) {
		_ = c.Error(tcerr.WrapRequestValidationError(errors.New("invalid action")))
		return
	}
	for key, value := range req.Params {
		if !cpe.IsActionTokenSafe(key) || !cpe.IsActionTokenSafe(value) {
			_ = c.Error(tcerr.WrapRequestValidationError(errors.New("invalid action params")))
			return
		}
	}

	result, err := controller.app.Commands.PerformCpeAction.Handle(c.Request.Context(), command.PerformCpeAction{
		IP:   target.ip,
		Port: target.port,
		Options: cpe.ActionOptions{
			Model:  target.model,
			Action: action,
			Params: req.Params,
			DryRun: req.DryRun,
		},
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	response := result.Response
	response.RequestID = c.Writer.Header().Get("X-Request-Id")
	if response.SSHFailed {
		c.JSON(http.StatusBadGateway, response)
		return
	}
	if !response.Success {
		message := "action failed"
		if len(response.Errors) > 0 && strings.TrimSpace(response.Errors[0]) != "" {
			message = response.Errors[0]
		}
		_ = c.Error(tcerr.NewUnsupportedAction(message, response.Retryable, map[string]any{
			"action":  response.Action,
			"profile": response.Profile,
		}))
		return
	}
	c.JSON(http.StatusOK, response)
}

type cpeTarget struct {
	ip    string
	port  int
	model string
}

func resolveTarget(ip string, port int, model string) (cpeTarget, error) {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return cpeTarget{}, tcerr.WrapRequestValidationError(errors.New("missing ip"))
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return cpeTarget{}, tcerr.NewBadRequest("invalid ip", map[string]any{"field": "ip"})
	}

	model = strings.TrimSpace(model)
	if model != "" && !cpe.IsModelSafe(model) {
		return cpeTarget{}, tcerr.WrapRequestValidationError(errors.New("invalid model"))
	}

	if port != 0 && (port < 1 || port > 65535) {
		return cpeTarget{}, tcerr.WrapRequestValidationError(errors.New("invalid port"))
	}
	if port == 0 {
		port = cpe.DefaultPortForModel(model)
	}

	return cpeTarget{ip: parsed.String(), port: port, model: model}, nil
}

func queryFlag(c *gin.Context, key string) bool {
	v := strings.TrimSpace(c.Query(key))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}
