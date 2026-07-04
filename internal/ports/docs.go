package ports

import (
	"embed"
	"net/http"

	"device-api/internal/tcerr"

	"github.com/gin-gonic/gin"
)

//go:embed docs/openapi.yaml docs/swagger.html
var docsFS embed.FS

func registerDocRoutes(router *gin.Engine) {
	router.GET("/openapi.yaml", serveEmbedded("docs/openapi.yaml", "application/yaml; charset=utf-8"))
	router.GET("/docs", serveEmbedded("docs/swagger.html", "text/html; charset=utf-8"))
}

func serveEmbedded(path, contentType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		content, err := docsFS.ReadFile(path)
		if err != nil {
			writeAPIError(c, tcerr.NewInternal("failed to load documentation asset"))
			return
		}
		c.Data(http.StatusOK, contentType, content)
	}
}
