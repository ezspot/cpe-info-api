package ports

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"device-api/internal/app"
	"device-api/internal/app/query"
	"device-api/internal/config"
	"device-api/internal/observability"
	"device-api/internal/snmp"

	"go.opentelemetry.io/otel"
)

type stubSwitchModel struct {
	allowed  bool
	response snmp.PortResponse
}

func (s *stubSwitchModel) IsAllowedTarget(string) bool { return s.allowed }

func (s *stubSwitchModel) CollectPorts(_ context.Context, q snmp.PortQuery) snmp.PortResponse {
	resp := s.response
	if resp.Host == "" {
		resp.Host = q.Host
	}
	if resp.PollTime.IsZero() {
		resp.PollTime = time.Date(2026, 7, 2, 18, 59, 0, 0, time.UTC)
	}
	return resp
}

func newSwitchTestServer(t *testing.T, cfg config.Config, model *stubSwitchModel) http.Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tracer := otel.Tracer("test")
	application := &app.Application{
		Queries: app.Queries{
			CollectSwitchPort: query.NewCollectSwitchPortHandler(model, logger, tracer),
		},
	}
	return NewHttpServer(application, cfg, logger, observability.NewRegistry(), nil)
}

func TestSwitchPortsEndpoint(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		target         string
		body           string
		allowed        bool
		response       snmp.PortResponse
		wantStatus     int
		wantCode       string
		wantMessageSub string
	}{
		{
			name:           "missing host",
			method:         http.MethodGet,
			target:         "/v1/switch/ports",
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantMessageSub: "missing host",
		},
		{
			name:           "host not an ip",
			method:         http.MethodGet,
			target:         "/v1/switch/ports?host=switch.local",
			allowed:        true,
			wantStatus:     http.StatusBadRequest,
			wantCode:       "bad_request",
			wantMessageSub: "host must be an IP",
		},
		{
			name:           "forbidden target",
			method:         http.MethodGet,
			target:         "/v1/switch/ports?host=10.0.0.5",
			allowed:        false,
			wantStatus:     http.StatusForbidden,
			wantCode:       "forbidden",
			wantMessageSub: "not allowed",
		},
		{
			name:       "snmp failed passthrough",
			method:     http.MethodGet,
			target:     "/v1/switch/ports?host=10.0.0.5",
			allowed:    true,
			response:   snmp.PortResponse{SNMPFailed: true, Errors: []string{"snmp connect: timeout"}},
			wantStatus: http.StatusBadGateway,
		},
		{
			name:           "port not found",
			method:         http.MethodGet,
			target:         "/v1/switch/ports?host=10.0.0.5&port=9/9",
			allowed:        true,
			response:       snmp.PortResponse{Errors: []string{`port "9/9" not found on device`}},
			wantStatus:     http.StatusNotFound,
			wantCode:       "not_found",
			wantMessageSub: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newTestConfig()
			cfg.APIKey = ""
			model := &stubSwitchModel{allowed: tt.allowed, response: tt.response}
			handler := newSwitchTestServer(t, cfg, model)

			req := httptest.NewRequest(tt.method, tt.target, bytes.NewBufferString(tt.body))
			if tt.method == http.MethodPost {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantStatus == http.StatusBadGateway {
				var resp snmp.PortResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode response: %v", err)
				}
				if !resp.SNMPFailed {
					t.Fatalf("expected snmpFailed true")
				}
				return
			}
			envelope := decodeErrorEnvelope(t, rec.Body)
			if envelope.Error.Code != tt.wantCode {
				t.Fatalf("error.code = %q, want %q", envelope.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestSwitchPortsSuccess(t *testing.T) {
	cfg := newTestConfig()
	cfg.APIKey = ""
	rx := -8.0
	model := &stubSwitchModel{
		allowed: true,
		response: snmp.PortResponse{
			Switch: "TAF-SJE-SKODJE-AR3",
			Ports: []snmp.PortStatus{{
				IfIndex:    602,
				Port:       "GigabitEthernet6/2",
				OperStatus: "down",
				SpeedMbps:  1000,
				Duplex:     "full",
				Optics:     &snmp.Optics{RxPowerDbm: &rx},
			}},
		},
	}
	handler := newSwitchTestServer(t, cfg, model)

	req := httptest.NewRequest(http.MethodPost, "/v1/switch/ports", bytes.NewBufferString(`{"host":"10.0.0.5","port":"6/2"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp snmp.PortResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Ports) != 1 || resp.Ports[0].Optics == nil || resp.Ports[0].Optics.RxPowerDbm == nil {
		t.Fatalf("expected one port with optics, got %+v", resp.Ports)
	}
}
