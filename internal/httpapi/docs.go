package httpapi

import (
	"embed"
	"net/http"
)

//go:embed docs/openapi.yaml docs/swagger.html
var docsFS embed.FS

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	content, err := docsFS.ReadFile("docs/openapi.yaml")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load openapi spec")
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleSwaggerUI(w http.ResponseWriter, _ *http.Request) {
	content, err := docsFS.ReadFile("docs/swagger.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to load swagger ui")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}
