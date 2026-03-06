package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cpe-api/internal/config"
	"cpe-api/internal/cpe"
	"cpe-api/internal/observability"
)

type stubCollector struct {
	allowed  bool
	response cpe.CollectResponse
	calls    int
}

func (s *stubCollector) Collect(_ context.Context, ip string, port int, options cpe.CollectOptions) cpe.CollectResponse {
	s.calls++
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

func (s *stubCollector) IsAllowedTarget(_ string) bool {
	return s.allowed
}

func newTestConfig() config.Config {
	return config.Config{
		APIKey:         "secret-token",
		Concurrency:    1,
		RequestTimeout: 2 * time.Second,
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func decodeErrorEnvelope(t *testing.T, body *bytes.Buffer) apiErrorEnvelope {
	t.Helper()
	var envelope apiErrorEnvelope
	if err := json.Unmarshal(body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
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
		prefillSem     bool
		response       cpe.CollectResponse
		wantStatus     int
		wantCode       string
		wantRetryable  bool
		wantDetailKey  string
		wantMessageSub string
	}{
		{
			name:           "method not allowed",
			method:         http.MethodDelete,
			target:         "/v1/cpe/collect",
			apiKeyEnabled:  false,
			allowed:        true,
			wantStatus:     http.StatusMethodNotAllowed,
			wantCode:       "method_not_allowed",
			wantRetryable:  false,
			wantMessageSub: "use GET or POST",
		},
		{
			name:           "missing bearer token",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=10.0.0.1",
			apiKeyEnabled:  true,
			allowed:        true,
			wantStatus:     http.StatusUnauthorized,
			wantCode:       "unauthorized",
			wantRetryable:  false,
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
			wantRetryable:  false,
			wantMessageSub: "target ip not allowed",
		},
		{
			name:           "invalid ip details",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=not-an-ip",
			apiKeyEnabled:  false,
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantRetryable:  false,
			wantDetailKey:  "field",
			wantMessageSub: "invalid ip",
		},
		{
			name:           "request body too large",
			method:         http.MethodPost,
			target:         "/v1/cpe/collect",
			apiKeyEnabled:  false,
			allowed:        true,
			body:           "{" + strings.Repeat(`"x":"0123456789",`, 70000) + `"ip":"10.0.0.1"}`,
			wantStatus:     http.StatusRequestEntityTooLarge,
			wantCode:       "request_body_too_large",
			wantRetryable:  false,
			wantMessageSub: "request body too large",
		},
		{
			name:           "too many requests",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=10.0.0.1",
			apiKeyEnabled:  false,
			allowed:        true,
			prefillSem:     true,
			wantStatus:     http.StatusTooManyRequests,
			wantCode:       "too_many_requests",
			wantRetryable:  true,
			wantMessageSub: "server is at max concurrency",
		},
		{
			name:           "ssh failed is passthrough response",
			method:         http.MethodGet,
			target:         "/v1/cpe/collect?ip=10.0.0.1&model=EX",
			apiKeyEnabled:  false,
			allowed:        true,
			response:       cpe.CollectResponse{SSHFailed: true, Errors: []string{"ssh dial: timeout"}},
			wantStatus:     http.StatusBadGateway,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig()
			if !tt.apiKeyEnabled {
				cfg.APIKey = ""
			}
			collector := &stubCollector{allowed: tt.allowed, response: tt.response}
			metrics := observability.NewRegistry()
			server := &Server{
				cfg:       cfg,
				log:       newTestLogger(),
				collector: collector,
				metrics:   metrics,
				sem:       make(chan struct{}, cfg.Concurrency),
				mux:       http.NewServeMux(),
			}
			server.routes()
			handler := server.recoverMiddleware(server.requestIDMiddleware(server.authMiddleware(server.metricsMiddleware(server.loggingMiddleware(server.mux)))))
			if tt.prefillSem {
				server.sem <- struct{}{}
			}
			body := bytes.NewBufferString(tt.body)
			req := httptest.NewRequest(tt.method, tt.target, body)
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

func TestMetricsEndpointExposesHTTPAndCollectorMetrics(t *testing.T) {
	collector := &stubCollector{
		allowed: true,
		response: cpe.CollectResponse{
			Errors: []string{"wifi24: Process exited with status 127"},
		},
	}
	cfg := newTestConfig()
	cfg.APIKey = ""
	metrics := observability.NewRegistry()
	handler := NewServer(cfg, newTestLogger(), collector, metrics)

	collectReq := httptest.NewRequest(http.MethodGet, "/v1/cpe/collect?ip=10.0.0.1&model=EX", nil)
	collectRec := httptest.NewRecorder()
	handler.ServeHTTP(collectRec, collectReq)
	if collectRec.Code != http.StatusOK {
		t.Fatalf("collect status = %d, want 200, body=%s", collectRec.Code, collectRec.Body.String())
	}

	metricsReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	metricsRec := httptest.NewRecorder()
	handler.ServeHTTP(metricsRec, metricsReq)
	if metricsRec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", metricsRec.Code)
	}

	body := metricsRec.Body.String()
	for _, fragment := range []string{
		"cpe_api_http_requests_total",
		"cpe_api_http_request_duration_seconds",
		"cpe_api_collector_requests_total",
	} {
		if !strings.Contains(body, fragment) {
			t.Fatalf("metrics output missing %q", fragment)
		}
	}
	if !strings.Contains(body, `result="partial_success"`) {
		t.Fatalf("metrics output missing partial_success collector label: %s", body)
	}
}
