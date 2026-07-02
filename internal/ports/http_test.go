package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cpe-api/internal/app"
	"cpe-api/internal/app/command"
	"cpe-api/internal/app/query"
	"cpe-api/internal/config"
	"cpe-api/internal/cpe"
	"cpe-api/internal/observability"
	"cpe-api/internal/tcerr"

	"go.opentelemetry.io/otel"
)

type stubModel struct {
	allowed        bool
	response       cpe.CollectResponse
	actionResponse cpe.ActionResponse

	collectStarted chan struct{}
	collectRelease chan struct{}
}

func (s *stubModel) IsAllowedTarget(string) bool { return s.allowed }

func (s *stubModel) Collect(_ context.Context, ip string, port int, options cpe.CollectOptions) cpe.CollectResponse {
	if s.collectStarted != nil {
		close(s.collectStarted)
		s.collectStarted = nil
	}
	if s.collectRelease != nil {
		<-s.collectRelease
	}
	resp := s.response
	if resp.IP == "" {
		resp.IP = ip
	}
	if resp.Port == 0 {
		resp.Port = port
	}
	if resp.Model == "" {
		resp.Model = options.Model
	}
	if resp.Timestamp.IsZero() {
		resp.Timestamp = time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC)
	}
	return resp
}

func (s *stubModel) PerformAction(_ context.Context, ip string, port int, options cpe.ActionOptions) cpe.ActionResponse {
	resp := s.actionResponse
	if resp.IP == "" {
		resp.IP = ip
	}
	if resp.Port == 0 {
		resp.Port = port
	}
	if resp.Model == "" {
		resp.Model = options.Model
	}
	if resp.Action == "" {
		resp.Action = options.Action
	}
	if resp.Params == nil {
		resp.Params = options.Params
	}
	if resp.Timestamp.IsZero() {
		resp.Timestamp = time.Date(2026, 3, 6, 0, 0, 0, 0, time.UTC)
	}
	return resp
}

func newTestConfig() config.Config {
	return config.Config{
		APIKey:         "secret-token",
		Concurrency:    1,
		RequestTimeout: 2 * time.Second,
	}
}

func newTestServer(t *testing.T, cfg config.Config, model *stubModel, metrics *observability.Registry) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracer := otel.Tracer("test")
	application := &app.Application{
		Commands: app.Commands{
			PerformCpeAction: command.NewPerformCpeActionHandler(model, logger, tracer),
		},
		Queries: app.Queries{
			CollectCpeInfo: query.NewCollectCpeInfoHandler(model, logger, tracer),
		},
	}
	return NewHttpServer(application, cfg, logger, metrics)
}

func decodeErrorEnvelope(t *testing.T, body *bytes.Buffer) tcerr.ErrorEnvelope {
	t.Helper()
	var envelope tcerr.ErrorEnvelope
	if err := json.Unmarshal(body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v, body=%s", err, body.String())
	}
	return envelope
}

func TestHandleCollectErrorContract(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		target         string
		body           string
		apiKeyEnabled  bool
		authHeader     string
		allowed        bool
		response       cpe.CollectResponse
		wantStatus     int
		wantCode       string
		wantRetryable  bool
		wantDetailKey  string
		wantMessageSub string
	}{
		{
			name:          "method not allowed",
			method:        http.MethodDelete,
			target:        "/v1/cpe/collect",
			allowed:       true,
			wantStatus:    http.StatusMethodNotAllowed,
			wantCode:      "method_not_allowed",
			wantRetryable: false,
		},
		{
			name:           "missing bearer token",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=10.0.0.1",
			apiKeyEnabled:  true,
			allowed:        true,
			wantStatus:     http.StatusUnauthorized,
			wantCode:       "unauthorized",
			wantMessageSub: "missing bearer token",
		},
		{
			name:           "forbidden target",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=10.0.0.1",
			apiKeyEnabled:  true,
			authHeader:     "Bearer secret-token",
			allowed:        false,
			wantStatus:     http.StatusForbidden,
			wantCode:       "forbidden",
			wantMessageSub: "target ip not allowed",
		},
		{
			name:           "invalid ip details",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=not-an-ip",
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantDetailKey:  "field",
			wantMessageSub: "invalid ip",
		},
		{
			name:           "unknown json field rejected",
			method:         http.MethodPost,
			target:         "/v1/cpe/collect",
			body:           `{"ip":"10.0.0.1","bogus":true}`,
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantMessageSub: "unknown field",
		},
		{
			name:           "request body too large",
			method:         http.MethodPost,
			target:         "/v1/cpe/collect",
			allowed:        true,
			body:           "{" + strings.Repeat(`"x":"0123456789",`, 70000) + `"ip":"10.0.0.1"}`,
			wantStatus:     http.StatusRequestEntityTooLarge,
			wantCode:       "request_body_too_large",
			wantMessageSub: "request body too large",
		},
		{
			name:       "ssh failed is passthrough response",
			method:     http.MethodGet,
			target:     "/v1/cpe/collect?ip=10.0.0.1&model=EX",
			allowed:    true,
			response:   cpe.CollectResponse{SSHFailed: true, Errors: []string{"ssh dial: timeout"}},
			wantStatus: http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig()
			if !tt.apiKeyEnabled {
				cfg.APIKey = ""
			}
			model := &stubModel{allowed: tt.allowed, response: tt.response}
			handler := newTestServer(t, cfg, model, observability.NewRegistry())

			req := httptest.NewRequest(tt.method, tt.target, bytes.NewBufferString(tt.body))
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			if tt.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			if tt.wantStatus == http.StatusBadGateway {
				var response cpe.CollectResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode collect response: %v", err)
				}
				if !response.SSHFailed {
					t.Fatalf("expected sshFailed true")
				}
				return
			}

			envelope := decodeErrorEnvelope(t, rec.Body)
			if envelope.Error.Code != tt.wantCode {
				t.Fatalf("error.code = %q, want %q", envelope.Error.Code, tt.wantCode)
			}
			if envelope.Error.Status != tt.wantStatus {
				t.Fatalf("error.status = %d, want %d", envelope.Error.Status, tt.wantStatus)
			}
			if envelope.Error.Retryable != tt.wantRetryable {
				t.Fatalf("error.retryable = %v, want %v", envelope.Error.Retryable, tt.wantRetryable)
			}
			if envelope.Error.RequestID == "" {
				t.Fatalf("expected requestId to be populated")
			}
			if tt.wantMessageSub != "" && !strings.Contains(envelope.Error.Message, tt.wantMessageSub) {
				t.Fatalf("error.message = %q, want substring %q", envelope.Error.Message, tt.wantMessageSub)
			}
			if tt.wantDetailKey != "" {
				if _, ok := envelope.Error.Details[tt.wantDetailKey]; !ok {
					t.Fatalf("expected details[%q] to exist, got %#v", tt.wantDetailKey, envelope.Error.Details)
				}
			}
		})
	}
}

func TestConcurrencyLimitRejects(t *testing.T) {
	cfg := newTestConfig()
	cfg.APIKey = ""
	started := make(chan struct{})
	release := make(chan struct{})
	model := &stubModel{allowed: true, collectStarted: started, collectRelease: release}
	metrics := observability.NewRegistry()
	handler := newTestServer(t, cfg, model, metrics)

	var wg sync.WaitGroup
	wg.Add(1)
	firstRec := httptest.NewRecorder()
	go func() {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodGet, "/v1/cpe/collect?ip=10.0.0.1", nil)
		handler.ServeHTTP(firstRec, req)
	}()

	<-started

	secondRec := httptest.NewRecorder()
	handler.ServeHTTP(secondRec, httptest.NewRequest(http.MethodGet, "/v1/cpe/collect?ip=10.0.0.2", nil))
	if secondRec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429, body=%s", secondRec.Code, secondRec.Body.String())
	}
	envelope := decodeErrorEnvelope(t, secondRec.Body)
	if envelope.Error.Code != "too_many_requests" {
		t.Fatalf("error.code = %q, want too_many_requests", envelope.Error.Code)
	}
	if !envelope.Error.Retryable {
		t.Fatalf("expected retryable true")
	}

	close(release)
	wg.Wait()
	if firstRec.Code != http.StatusOK {
		t.Fatalf("first request status = %d, want 200, body=%s", firstRec.Code, firstRec.Body.String())
	}
}

func TestMetricsEndpointExposesHTTPMetrics(t *testing.T) {
	cfg := newTestConfig()
	cfg.APIKey = ""
	model := &stubModel{allowed: true}
	metrics := observability.NewRegistry()
	handler := newTestServer(t, cfg, model, metrics)

	collectRec := httptest.NewRecorder()
	handler.ServeHTTP(collectRec, httptest.NewRequest(http.MethodGet, "/v1/cpe/collect?ip=10.0.0.1&model=EX", nil))
	if collectRec.Code != http.StatusOK {
		t.Fatalf("collect status = %d, want 200, body=%s", collectRec.Code, collectRec.Body.String())
	}

	metricsRec := httptest.NewRecorder()
	handler.ServeHTTP(metricsRec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metricsRec.Code)
	}

	body := metricsRec.Body.String()
	for _, fragment := range []string{
		"cpe_api_http_requests_total",
		"cpe_api_http_request_duration_seconds",
		`route="/v1/cpe/collect"`,
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("metrics output missing %q", fragment)
		}
	}
}

func TestHealthAndRequestIDEcho(t *testing.T) {
	cfg := newTestConfig()
	model := &stubModel{allowed: true}
	handler := newTestServer(t, cfg, model, observability.NewRegistry())

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-Id", "test-id-123")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "test-id-123" {
		t.Fatalf("X-Request-Id = %q, want echo of test-id-123", got)
	}
}

func TestHandleAction(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		body           string
		apiKeyEnabled  bool
		authHeader     string
		allowed        bool
		actionResponse cpe.ActionResponse
		wantStatus     int
		wantCode       string
		wantMessageSub string
	}{
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			body:       `{}`,
			allowed:    true,
			wantStatus: http.StatusMethodNotAllowed,
			wantCode:   "method_not_allowed",
		},
		{
			name:           "missing action",
			method:         http.MethodPost,
			body:           `{"ip":"10.0.0.1","model":"EX5401"}`,
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantMessageSub: "missing action",
		},
		{
			name:           "forbidden target",
			method:         http.MethodPost,
			body:           `{"ip":"10.0.0.1","model":"EX5401","action":"reboot"}`,
			apiKeyEnabled:  true,
			authHeader:     "Bearer secret-token",
			allowed:        false,
			wantStatus:     http.StatusForbidden,
			wantCode:       "forbidden",
			wantMessageSub: "target ip not allowed",
		},
		{
			name:           "unsupported action",
			method:         http.MethodPost,
			body:           `{"ip":"10.0.0.1","model":"EX5401","action":"semi_reset"}`,
			allowed:        true,
			actionResponse: cpe.ActionResponse{Success: false, Profile: "zyxel-v1", Errors: []string{"action \"semi_reset\" is not supported for profile \"zyxel-v1\""}},
			wantStatus:     http.StatusBadRequest,
			wantCode:       "unsupported_action",
			wantMessageSub: "not supported",
		},
		{
			name:           "ssh failure passthrough",
			method:         http.MethodPost,
			body:           `{"ip":"10.0.0.1","model":"EX5401","action":"reboot"}`,
			allowed:        true,
			actionResponse: cpe.ActionResponse{SSHFailed: true, Errors: []string{"ssh dial: timeout"}, Retryable: true},
			wantStatus:     http.StatusBadGateway,
		},
		{
			name:           "success",
			method:         http.MethodPost,
			body:           `{"ip":"10.0.0.1","model":"F01","action":"reboot","dryRun":true}`,
			allowed:        true,
			actionResponse: cpe.ActionResponse{Success: true, Profile: "vantiva-openwrt-v1", Command: "reboot", DryRun: true},
			wantStatus:     http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig()
			if !tt.apiKeyEnabled {
				cfg.APIKey = ""
			}
			model := &stubModel{allowed: tt.allowed, actionResponse: tt.actionResponse}
			handler := newTestServer(t, cfg, model, observability.NewRegistry())

			req := httptest.NewRequest(tt.method, "/v1/cpe/actions", bytes.NewBufferString(tt.body))
			req.Header.Set("Content-Type", "application/json")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}

			if tt.wantStatus == http.StatusBadGateway {
				var response cpe.ActionResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode action response: %v", err)
				}
				if !response.SSHFailed {
					t.Fatalf("expected sshFailed true")
				}
				return
			}

			if tt.wantStatus == http.StatusOK {
				var response cpe.ActionResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatalf("decode success action response: %v", err)
				}
				if !response.Success {
					t.Fatalf("expected success true")
				}
				if response.RequestID == "" {
					t.Fatalf("expected requestId on success response")
				}
				return
			}

			envelope := decodeErrorEnvelope(t, rec.Body)
			if envelope.Error.Code != tt.wantCode {
				t.Fatalf("error.code = %q, want %q", envelope.Error.Code, tt.wantCode)
			}
			if tt.wantMessageSub != "" && !strings.Contains(envelope.Error.Message, tt.wantMessageSub) {
				t.Fatalf("error.message = %q, want substring %q", envelope.Error.Message, tt.wantMessageSub)
			}
		})
	}
}
