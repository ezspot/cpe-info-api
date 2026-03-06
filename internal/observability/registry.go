package observability

import (
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type Registry struct {
	registry *prometheus.Registry

	httpRequestsTotal      *prometheus.CounterVec
	httpRequestDuration    *prometheus.HistogramVec
	httpInFlight           *prometheus.GaugeVec
	collectorRequestsTotal *prometheus.CounterVec
	sshDialFailuresTotal   *prometheus.CounterVec
	commandDuration        *prometheus.HistogramVec
	concurrencyRejects     *prometheus.CounterVec
}

func NewRegistry() *Registry {
	registry := prometheus.NewRegistry()

	r := &Registry{
		registry: registry,
		httpRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cpe_api",
			Subsystem: "http",
			Name:      "requests_total",
			Help:      "Total number of HTTP requests processed by route, method, and status.",
		}, []string{"route", "method", "status"}),
		httpRequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "cpe_api",
			Subsystem: "http",
			Name:      "request_duration_seconds",
			Help:      "HTTP request duration by route and method.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"route", "method"}),
		httpInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "cpe_api",
			Subsystem: "http",
			Name:      "in_flight_requests",
			Help:      "Current number of in-flight HTTP requests by route.",
		}, []string{"route"}),
		collectorRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cpe_api",
			Subsystem: "collector",
			Name:      "requests_total",
			Help:      "Total number of collector requests by normalized model and result.",
		}, []string{"model", "result"}),
		sshDialFailuresTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cpe_api",
			Subsystem: "collector",
			Name:      "ssh_dial_failures_total",
			Help:      "Total number of SSH dial failures by normalized model and classified reason.",
		}, []string{"model", "reason"}),
		commandDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "cpe_api",
			Subsystem: "collector",
			Name:      "command_duration_seconds",
			Help:      "Collector command duration by profile, command key, and result.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30},
		}, []string{"profile", "command", "result"}),
		concurrencyRejects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "cpe_api",
			Subsystem: "runtime",
			Name:      "concurrency_rejections_total",
			Help:      "Total number of requests rejected by concurrency control.",
		}, []string{"limiter"}),
	}

	registry.MustRegister(
		r.httpRequestsTotal,
		r.httpRequestDuration,
		r.httpInFlight,
		r.collectorRequestsTotal,
		r.sshDialFailuresTotal,
		r.commandDuration,
		r.concurrencyRejects,
	)

	return r
}

func (r *Registry) PrometheusGatherer() prometheus.Gatherer {
	return r.registry
}

func (r *Registry) ObserveHTTPRequest(route, method string, status int, duration time.Duration, _ int) {
	r.httpRequestsTotal.WithLabelValues(normalizeRoute(route), normalizeMethod(method), normalizeStatus(status)).Inc()
	r.httpRequestDuration.WithLabelValues(normalizeRoute(route), normalizeMethod(method)).Observe(duration.Seconds())
}

func (r *Registry) ObserveHTTPInFlight(route string, delta int) {
	g := r.httpInFlight.WithLabelValues(normalizeRoute(route))
	if delta >= 0 {
		g.Add(float64(delta))
		return
	}
	g.Sub(float64(-delta))
}

func (r *Registry) ObserveCollectorRequest(model, result string) {
	r.collectorRequestsTotal.WithLabelValues(NormalizeModelLabel(model), normalizeCollectorResult(result)).Inc()
}

func (r *Registry) ObserveSSHDialFailure(model, reason string) {
	r.sshDialFailuresTotal.WithLabelValues(NormalizeModelLabel(model), normalizeSSHDialReason(reason)).Inc()
}

func (r *Registry) ObserveCommandDuration(profile, command, result string, duration time.Duration) {
	r.commandDuration.WithLabelValues(normalizeProfile(profile), normalizeCommand(command), normalizeCommandResult(result)).Observe(duration.Seconds())
}

func (r *Registry) ObserveConcurrencyReject(limiter string) {
	r.concurrencyRejects.WithLabelValues(normalizeLimiter(limiter)).Inc()
}

func NormalizeModelLabel(model string) string {
	upper := strings.ToUpper(strings.TrimSpace(model))
	switch {
	case upper == "":
		return "unspecified"
	case upper == "VANTIVA":
		return "vantiva"
	case strings.Contains(upper, "P2812"):
		return "p2812"
	case strings.Contains(upper, "FMG"):
		return "fmg"
	case strings.Contains(upper, "VMG"):
		return "vmg"
	case strings.Contains(upper, "AX"):
		return "ax"
	case strings.Contains(upper, "EX"):
		return "ex"
	default:
		return "other"
	}
}

func normalizeRoute(route string) string {
	route = strings.TrimSpace(route)
	if route == "" {
		return "unknown"
	}
	return route
}

func normalizeMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		return "UNKNOWN"
	}
	return method
}

func normalizeStatus(status int) string {
	if status < 100 || status > 999 {
		return "000"
	}
	return strconv.Itoa(status)
}

func normalizeCollectorResult(result string) string {
	switch strings.TrimSpace(result) {
	case "success", "partial_success", "ssh_failed":
		return result
	default:
		return "unknown"
	}
}

func normalizeSSHDialReason(reason string) string {
	switch strings.TrimSpace(reason) {
	case "connection_refused", "timeout", "unreachable", "auth_failed", "config", "other":
		return reason
	default:
		return "other"
	}
}

func normalizeProfile(profile string) string {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return "unknown"
	}
	return profile
}

func normalizeCommand(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return "unknown"
	}
	return command
}

func normalizeCommandResult(result string) string {
	switch strings.TrimSpace(result) {
	case "success", "error", "timeout", "skipped":
		return result
	default:
		return "unknown"
	}
}

func normalizeLimiter(limiter string) string {
	limiter = strings.TrimSpace(limiter)
	if limiter == "" {
		return "unknown"
	}
	return limiter
}
