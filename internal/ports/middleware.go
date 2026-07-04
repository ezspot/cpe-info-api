package ports

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"device-api/internal/observability"
	"device-api/internal/tcerr"

	"github.com/gin-gonic/gin"
)

const (
	requestIDHeader = "X-Request-Id"
	maxBodyBytes    = 1 << 20
)

func requestID(c *gin.Context) string {
	return c.Writer.Header().Get(requestIDHeader)
}

func writeAPIError(c *gin.Context, err *tcerr.APIError) {
	c.Abort()
	c.JSON(err.Status, tcerr.NewEnvelope(err, requestID(c)))
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := strings.TrimSpace(c.GetHeader(requestIDHeader))
		if id == "" {
			id = newRequestID()
		}
		c.Writer.Header().Set(requestIDHeader, id)
		c.Next()
	}
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err == nil {
		return hex.EncodeToString(b[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.Writer.Header()
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		c.Next()
	}
}

func recovery(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if rec := recover(); rec != nil {
				logger.Error("panic recovered",
					"panic", rec,
					"request_id", requestID(c),
					"path", c.Request.URL.Path,
				)
				if !c.Writer.Written() {
					writeAPIError(c, tcerr.NewInternal("unexpected server error"))
				} else {
					c.Abort()
				}
			}
		}()
		c.Next()
	}
}

func metricsMiddleware(metrics *observability.Registry) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		route := c.FullPath()
		if route == "" {
			route = "unknown"
		}
		metrics.ObserveHTTPInFlight(route, 1)
		defer func() {
			metrics.ObserveHTTPRequest(route, c.Request.Method, c.Writer.Status(), time.Since(start))
			metrics.ObserveHTTPInFlight(route, -1)
		}()
		c.Next()
	}
}

func requestLogger(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("http_request",
			"request_id", requestID(c),
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"bytes", c.Writer.Size(),
			"duration_ms", time.Since(start).Milliseconds(),
			"remote_addr", c.ClientIP(),
			"user_agent", c.Request.UserAgent(),
		)
	}
}

// errorHandler maps errors attached via c.Error to the JSON error envelope.
// It must run inside otelgin/metrics middleware so they observe the final status.
func errorHandler(logger *slog.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) == 0 || c.Writer.Written() {
			return
		}
		lastErr := c.Errors.Last().Err
		apiErr := tcerr.From(lastErr)
		if apiErr.Status >= http.StatusInternalServerError {
			logger.Error("request_failed",
				"request_id", requestID(c),
				"path", c.Request.URL.Path,
				"error", lastErr.Error(),
			)
		}
		writeAPIError(c, apiErr)
	}
}

func bearerAuth(apiKey string) gin.HandlerFunc {
	if apiKey == "" {
		return func(c *gin.Context) { c.Next() }
	}
	key := []byte(apiKey)
	return func(c *gin.Context) {
		header := strings.TrimSpace(c.GetHeader("Authorization"))
		if header == "" {
			_ = c.Error(tcerr.NewUnauthorized("missing authorization token"))
			c.Abort()
			return
		}
		// Accept both "Bearer <key>" and the raw key (matches the apikey scheme).
		token := header
		if len(token) >= 7 && strings.EqualFold(token[:7], "Bearer ") {
			token = strings.TrimSpace(token[7:])
		}
		if subtle.ConstantTimeCompare([]byte(token), key) != 1 {
			_ = c.Error(tcerr.NewUnauthorized("invalid authorization token"))
			c.Abort()
			return
		}
		c.Next()
	}
}

func bodySizeLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}

func concurrencyLimit(limit int, metrics *observability.Registry) gin.HandlerFunc {
	sem := make(chan struct{}, limit)
	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
			c.Next()
		default:
			metrics.ObserveConcurrencyReject("http_semaphore")
			_ = c.Error(tcerr.NewTooManyRequests("server is at max concurrency"))
			c.Abort()
		}
	}
}
