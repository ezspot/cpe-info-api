package ports

import (
	"log/slog"
	"net/http"

	"cpe-api/internal/app"
	"cpe-api/internal/config"
	"cpe-api/internal/observability"
	v1 "cpe-api/internal/ports/controllers/v1"
	"cpe-api/internal/tcerr"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

const serviceName = "cpe-info-api"

func NewHttpServer(application *app.Application, cfg config.Config, logger *slog.Logger, metrics *observability.Registry) http.Handler {
	gin.SetMode(gin.ReleaseMode)
	binding.EnableDecoderDisallowUnknownFields = true

	router := gin.New()
	router.HandleMethodNotAllowed = true

	router.Use(
		requestIDMiddleware(),
		securityHeaders(),
		recovery(logger),
		metricsMiddleware(metrics),
		requestLogger(logger),
	)

	router.NoRoute(func(c *gin.Context) {
		writeAPIError(c, tcerr.NewNotFound("route not found"))
	})
	router.NoMethod(func(c *gin.Context) {
		writeAPIError(c, tcerr.NewMethodNotAllowed("method not allowed"))
	})

	healthController := v1.NewHealthController()
	router.GET("/healthz", healthController.Healthz)
	router.GET("/readyz", healthController.Readyz)

	registerDocRoutes(router)
	router.GET("/metrics", gin.WrapH(promhttp.HandlerFor(metrics.PrometheusGatherer(), promhttp.HandlerOpts{})))

	cpeController := v1.NewCpeController(application, logger)

	api := router.Group("/v1")
	api.Use(
		otelgin.Middleware(serviceName),
		errorHandler(logger),
		bearerAuth(cfg.APIKey),
		bodySizeLimit(maxBodyBytes),
		concurrencyLimit(cfg.Concurrency, metrics),
	)
	{
		cpeRoutes := api.Group("/cpe")
		cpeRoutes.GET("/collect", cpeController.Collect)
		cpeRoutes.POST("/collect", cpeController.Collect)
		cpeRoutes.POST("/actions", cpeController.PerformAction)
	}

	return router
}
