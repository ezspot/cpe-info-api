package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func NewHealthController() *HealthController {
	return &HealthController{}
}

type HealthController struct{}

type healthStatus struct {
	Status string `json:"status"`
} // @Name HealthStatus

// Healthz is a gin handler function.
// @Summary Liveness probe
// @Tags Health
// @Produce json
// @Success 200 {object} healthStatus
// @Router /healthz [get]
func (controller *HealthController) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, healthStatus{Status: "ok"})
}

// Readyz is a gin handler function.
// @Summary Readiness probe
// @Tags Health
// @Produce json
// @Success 200 {object} healthStatus
// @Router /readyz [get]
func (controller *HealthController) Readyz(c *gin.Context) {
	c.JSON(http.StatusOK, healthStatus{Status: "ready"})
}
