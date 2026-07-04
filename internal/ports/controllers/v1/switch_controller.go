package v1

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"device-api/internal/app"
	"device-api/internal/app/query"
	"device-api/internal/snmp"
	"device-api/internal/tcerr"

	"github.com/gin-gonic/gin"
)

func NewSwitchController(app *app.Application, logger *slog.Logger, resolver *snmp.HostResolver) *SwitchController {
	return &SwitchController{app: app, logger: logger, resolver: resolver}
}

type SwitchController struct {
	app      *app.Application
	logger   *slog.Logger
	resolver *snmp.HostResolver
}

type switchPortRequest struct {
	Host             string `json:"host,omitempty" example:"10.160.25.72"`
	Port             string `json:"port,omitempty" example:"6/2"`
	PortGroup        string `json:"portGroup,omitempty" example:"TAFAALLERSTADAR2S003P20"`
	ReverseDirection bool   `json:"reverseDirection,omitempty" example:"false"`
	IncludeMACs      *bool  `json:"includeMacs,omitempty" example:"true"`
} // @Name SwitchPortRequest

// GetPorts is a gin handler function.
// @Summary Poll switch port status and optics over SNMP
// @Description Polls a switch (Cisco Catalyst 4500/9400, Huawei S5736) over SNMP for interface status, speed, duplex, error counters, byte counters, and transceiver optics. Omit port to return all interfaces.
// @Tags Switch
// @Produce json
// @Security BearerAuth
// @Param host query string false "Switch management IP; ignored when portGroup is set"
// @Param port query string false "Interface label, e.g. 6/2 or GigabitEthernet6/2; omit for all ports"
// @Param portGroup query string false "RADIUS port-group id, e.g. TAFAALLERSTADAR3S003P20; resolves host+interface"
// @Param macs query bool false "Include learned MAC addresses (defaults on when a single port is requested)"
// @Param reverse query bool false "Reverse Ds/Us direction mapping (for core-facing ports)"
// @Success 200 {object} snmp.PortResponse
// @Failure 400 {object} tcerr.ErrorEnvelope
// @Failure 401 {object} tcerr.ErrorEnvelope
// @Failure 403 {object} tcerr.ErrorEnvelope
// @Failure 404 {object} tcerr.ErrorEnvelope
// @Failure 429 {object} tcerr.ErrorEnvelope
// @Failure 502 {object} snmp.PortResponse
// @Router /v1/switch/ports [get]
func (controller *SwitchController) GetPorts(c *gin.Context) {
	controller.handle(c)
}

// PostPorts is a gin handler function.
// @Summary Poll switch port status and optics over SNMP (JSON body)
// @Description Same as GET but takes a JSON body. Omit port to return all interfaces.
// @Tags Switch
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param payload body switchPortRequest true "Switch poll request"
// @Success 200 {object} snmp.PortResponse
// @Failure 400 {object} tcerr.ErrorEnvelope
// @Failure 401 {object} tcerr.ErrorEnvelope
// @Failure 403 {object} tcerr.ErrorEnvelope
// @Failure 404 {object} tcerr.ErrorEnvelope
// @Failure 429 {object} tcerr.ErrorEnvelope
// @Failure 502 {object} snmp.PortResponse
// @Router /v1/switch/ports [post]
func (controller *SwitchController) PostPorts(c *gin.Context) {
	controller.handle(c)
}

func (controller *SwitchController) handle(c *gin.Context) {
	var req switchPortRequest
	if c.Request.Method == http.MethodGet {
		req.Host = c.Query("host")
		req.Port = c.Query("port")
		req.PortGroup = c.Query("portGroup")
		req.ReverseDirection = queryFlag(c, "reverse")
		if _, present := c.GetQuery("macs"); present {
			v := queryFlag(c, "macs")
			req.IncludeMACs = &v
		}
	} else if err := c.ShouldBindJSON(&req); err != nil {
		_ = c.Error(tcerr.WrapRequestValidationError(err))
		return
	}

	host := strings.TrimSpace(req.Host)
	port := strings.TrimSpace(req.Port)
	if pg := strings.TrimSpace(req.PortGroup); pg != "" {
		resolvedHost, resolvedPort, err := controller.resolvePortGroup(pg)
		if err != nil {
			_ = c.Error(err)
			return
		}
		host, port = resolvedHost, resolvedPort
	}

	if host == "" {
		_ = c.Error(tcerr.WrapRequestValidationError(errors.New("missing host or portGroup")))
		return
	}
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		_ = c.Error(tcerr.NewBadRequest("host must be an IP address", map[string]any{"field": "host"}))
		return
	}

	includeMACs := port != ""
	if req.IncludeMACs != nil {
		includeMACs = *req.IncludeMACs
	}

	response, err := controller.app.Queries.CollectSwitchPort.Handle(c.Request.Context(), query.CollectSwitchPort{
		Host:             parsedIP.String(),
		Port:             port,
		ReverseDirection: req.ReverseDirection,
		IncludeMACs:      includeMACs,
	})
	if err != nil {
		_ = c.Error(err)
		return
	}

	if response.SNMPFailed {
		c.JSON(http.StatusBadGateway, response)
		return
	}
	if port != "" && len(response.Ports) == 0 {
		message := "port not found"
		if len(response.Errors) > 0 && strings.TrimSpace(response.Errors[0]) != "" {
			message = response.Errors[0]
		}
		_ = c.Error(tcerr.NewNotFound(message))
		return
	}
	c.JSON(http.StatusOK, response)
}

func (controller *SwitchController) resolvePortGroup(pg string) (host, port string, err error) {
	if controller.resolver == nil {
		return "", "", tcerr.NewBadRequest("portGroup resolution is not configured (set SWITCH_HOSTS_FILE)", nil)
	}
	parsed, err := snmp.ParsePortGroup(pg)
	if err != nil {
		return "", "", tcerr.WrapRequestValidationError(err)
	}
	ip, ok := controller.resolver.Resolve(parsed.SwitchKey)
	if !ok {
		return "", "", tcerr.NewNotFound("no switch found for port group " + parsed.Raw)
	}
	return ip, parsed.Interface, nil
}
