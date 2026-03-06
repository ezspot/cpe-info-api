package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cpe-api/internal/config"
	"cpe-api/internal/cpe"
	"cpe-api/internal/observability"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const maxBodyBytes = 1 << 20

type requestIDKey struct{}

type collector interface {
	Collect(ctx context.Context, ip string, port int, options cpe.CollectOptions) cpe.CollectResponse
	IsAllowedTarget(ipStr string) bool
}

type Server struct {
	cfg       config.Config
	log       *slog.Logger
	collector collector
	metrics   *observability.Registry

	sem chan struct{}
	mux *http.ServeMux
}

type CollectRequestBody struct {
	IP    string `json:"ip"`
	Port  int    `json:"port,omitempty"`
	Model string `json:"model,omitempty"`
}

func NewServer(cfg config.Config, logger *slog.Logger, c collector, metrics *observability.Registry) http.Handler {
	if metrics == nil {
		metrics = observability.NewRegistry()
	}

	s := &Server{
		cfg:       cfg,
		log:       logger,
		collector: c,
		metrics:   metrics,
		sem:       make(chan struct{}, cfg.Concurrency),
		mux:       http.NewServeMux(),
	}
	s.routes()
	return s.recoverMiddleware(s.requestIDMiddleware(s.authMiddleware(s.metricsMiddleware(s.loggingMiddleware(s.mux)))))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)
	s.mux.HandleFunc("/openapi.yaml", s.handleOpenAPI)
	s.mux.HandleFunc("/docs", s.handleSwaggerUI)
	s.mux.HandleFunc("/docs/", s.handleSwaggerUI)
	s.mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.PrometheusGatherer(), promhttp.HandlerOpts{}))
	s.mux.HandleFunc("/v1/cpe/collect", s.handleCollect)
}

// handleHealthz godoc
// @Summary Liveness probe
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /healthz [get]
func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz godoc
// @Summary Readiness probe
// @Tags Health
// @Produce json
// @Success 200 {object} map[string]string
// @Router /readyz [get]
func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

// handleCollect godoc
// @Summary Collect CPE diagnostics
// @Description Supports GET query params and POST JSON body.
// @Tags CPE
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param ip query string false "Target CPE IP (GET)"
// @Param port query int false "Target SSH port (GET, default 22)"
// @Param model query string false "Model (VANTIVA/FMG/P2812/VMG/AX/EX)"
// @Param raw query bool false "Include raw command output"
// @Param includePsk query bool false "Include cleartext PSK values"
// @Param payload body CollectRequestBody false "Target CPE data (POST)"
// @Success 200 {object} cpe.CollectResponse
// @Failure 400 {object} apiErrorEnvelope
// @Failure 401 {object} apiErrorEnvelope
// @Failure 403 {object} apiErrorEnvelope
// @Failure 429 {object} apiErrorEnvelope
// @Failure 502 {object} cpe.CollectResponse
// @Router /v1/cpe/collect [get]
// @Router /v1/cpe/collect [post]
func (s *Server) handleCollect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeError(r.Context(), w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST", false, nil)
		return
	}

	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.metrics.ObserveConcurrencyReject("http_semaphore")
		writeError(r.Context(), w, http.StatusTooManyRequests, "too_many_requests", "server is at max concurrency", true, nil)
		return
	}

	target, err := parseCollectTarget(r)
	if err != nil {
		status := http.StatusBadRequest
		code := "bad_request"
		if errors.Is(err, errRequestBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
			code = "request_body_too_large"
		}
		writeError(r.Context(), w, status, code, err.Error(), false, nil)
		return
	}

	parsedIP := net.ParseIP(target.IP)
	if parsedIP == nil {
		writeError(r.Context(), w, http.StatusBadRequest, "bad_request", "invalid ip", false, map[string]any{"field": "ip"})
		return
	}
	if !s.collector.IsAllowedTarget(parsedIP.String()) {
		writeError(r.Context(), w, http.StatusForbidden, "forbidden", "target ip not allowed", false, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.RequestTimeout)
	defer cancel()

	response := s.collector.Collect(ctx, parsedIP.String(), target.Port, cpe.CollectOptions{
		IncludeRaw: queryBool(r, "raw"),
		IncludePSK: queryBool(r, "includePsk"),
		Model:      target.Model,
	})
	s.metrics.ObserveCollectorRequest(target.Model, collectorResultFromResponse(response))
	if response.SSHFailed {
		writeJSON(w, http.StatusBadGateway, response)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

type collectTarget struct {
	IP    string
	Port  int
	Model string
}

func parseCollectTarget(r *http.Request) (collectTarget, error) {
	target := collectTarget{Port: 22}

	switch r.Method {
	case http.MethodGet:
		target.IP = strings.TrimSpace(r.URL.Query().Get("ip"))
		target.Model = strings.TrimSpace(r.URL.Query().Get("model"))
		if p := strings.TrimSpace(r.URL.Query().Get("port")); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return collectTarget{}, errors.New("invalid port")
			}
			target.Port = n
		}
	case http.MethodPost:
		var req CollectRequestBody
		if err := decodeJSONBody(r, &req); err != nil {
			return collectTarget{}, err
		}
		target.IP = strings.TrimSpace(req.IP)
		target.Model = strings.TrimSpace(req.Model)
		if req.Port != 0 {
			if req.Port < 1 || req.Port > 65535 {
				return collectTarget{}, errors.New("invalid port")
			}
			target.Port = req.Port
		}
	}

	if target.IP == "" {
		return collectTarget{}, errors.New("missing ip")
	}
	if target.Model != "" && !isModelSafe(target.Model) {
		return collectTarget{}, errors.New("invalid model")
	}
	return target, nil
}

var modelPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func isModelSafe(model string) bool {
	return modelPattern.MatchString(model)
}

var errRequestBodyTooLarge = errors.New("request body too large")

func decodeJSONBody(r *http.Request, dst any) error {
	defer r.Body.Close()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return errors.New("invalid json")
	}
	if len(body) > maxBodyBytes {
		return errRequestBodyTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid json")
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("invalid json")
	}
	return nil
}

func queryBool(r *http.Request, key string) bool {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(statusCode int) {
	r.status = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(rec, r)

		requestID, _ := r.Context().Value(requestIDKey{}).(string)
		s.log.Info("http_request",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)
	})
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		route := canonicalRoute(r.URL.Path)
		s.metrics.ObserveHTTPInFlight(route, 1)
		defer s.metrics.ObserveHTTPInFlight(route, -1)

		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		s.metrics.ObserveHTTPRequest(route, r.Method, status, time.Since(start), rec.bytes)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "panic", rec)
				writeError(r.Context(), w, http.StatusInternalServerError, "internal_error", "unexpected server error", true, nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if requestID == "" {
			requestID = newRequestID()
		}
		w.Header().Set("X-Request-Id", requestID)
		ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if s.cfg.APIKey == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeError(r.Context(), w, http.StatusUnauthorized, "unauthorized", "missing bearer token", false, nil)
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.APIKey)) != 1 {
			writeError(r.Context(), w, http.StatusUnauthorized, "unauthorized", "invalid bearer token", false, nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isPublicPath(path string) bool {
	switch path {
	case "/healthz", "/readyz", "/openapi.yaml", "/docs", "/docs/", "/metrics":
		return true
	default:
		return false
	}
}

type apiErrorEnvelope struct {
	Error apiError `json:"error"`
}

type apiError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Status    int            `json:"status"`
	RequestID string         `json:"requestId,omitempty"`
	Retryable bool           `json:"retryable"`
	Details   map[string]any `json:"details,omitempty"`
}

func writeError(ctx context.Context, w http.ResponseWriter, status int, code, message string, retryable bool, details map[string]any) {
	requestID, _ := ctx.Value(requestIDKey{}).(string)
	writeJSON(w, status, apiErrorEnvelope{
		Error: apiError{
			Code:      code,
			Message:   message,
			Status:    status,
			RequestID: requestID,
			Retryable: retryable,
			Details:   details,
		},
	})
}

func canonicalRoute(path string) string {
	switch path {
	case "/healthz", "/readyz", "/openapi.yaml", "/docs", "/docs/", "/metrics", "/v1/cpe/collect":
		return path
	default:
		return "unknown"
	}
}

func collectorResultFromResponse(response cpe.CollectResponse) string {
	if response.SSHFailed {
		return "ssh_failed"
	}
	if len(response.Errors) > 0 {
		return "partial_success"
	}
	return "success"
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(payload)
}
