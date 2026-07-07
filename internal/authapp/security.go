/*
 * MIT License
 *
 * Copyright (c) 2022-2026 Anton Stremovskyy <stremovskyy@me.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package authapp

import (
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/server"
)

const (
	defaultTokenRateLimit  = 60
	defaultReadyzRateLimit = 300
	defaultRateLimitWindow = time.Minute
)

type runtimeSecurity struct {
	limiter      *fixedWindowRateLimiter
	tokenLimit   effectiveRateLimit
	readyzLimit  effectiveRateLimit
	auditEnabled bool
}

type effectiveRateLimit struct {
	enabled bool
	limit   int
	window  time.Duration
}

func mountAuthRoutes(r *gin.Engine, auth *server.Server, cfg Config) error {
	security, err := newRuntimeSecurity(cfg)
	if err != nil {
		return err
	}

	basePath, err := normalizeBasePath(cfg.BasePath)
	if err != nil {
		return err
	}

	routes := r.Group(basePath)
	routes.POST("/oauth/token", security.handlers("token", security.tokenLimit, gin.WrapF(auth.TokenHTTP))...)
	routes.GET("/.well-known/jwks.json", gin.WrapF(auth.JWKSHTTP))
	routes.GET("/.well-known/openid-configuration", gin.WrapF(auth.DiscoveryHTTP))
	routes.GET("/healthz", gin.WrapF(auth.HealthHTTP))
	routes.GET("/readyz", security.handlers("readyz", security.readyzLimit, gin.WrapF(auth.HealthHTTP))...)

	return nil
}

func normalizeBasePath(value string) (string, error) {
	basePath := strings.TrimSpace(value)
	if basePath == "" || basePath == "/" {
		return "", nil
	}

	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	basePath = strings.TrimRight(basePath, "/")

	if strings.Contains(basePath, "//") {
		return "", errors.New("base_path must not contain empty path segments")
	}

	return basePath, nil
}

func newRuntimeSecurity(cfg Config) (*runtimeSecurity, error) {
	tokenLimit, err := normalizeRateLimit(cfg.RateLimits.Token, defaultTokenRateLimit, defaultRateLimitWindow)
	if err != nil {
		return nil, err
	}

	readyzLimit, err := normalizeRateLimit(cfg.RateLimits.Readyz, defaultReadyzRateLimit, defaultRateLimitWindow)
	if err != nil {
		return nil, err
	}

	return &runtimeSecurity{
		limiter:      newFixedWindowRateLimiter(time.Now),
		tokenLimit:   tokenLimit,
		readyzLimit:  readyzLimit,
		auditEnabled: boolDefault(cfg.AuditLogs.Enabled, true),
	}, nil
}

func normalizeRateLimit(
	cfg EndpointRateLimitConfig,
	defaultLimit int,
	defaultWindow time.Duration,
) (effectiveRateLimit, error) {
	limit := cfg.Limit

	if limit <= 0 {
		limit = defaultLimit
	}

	window := defaultWindow

	if strings.TrimSpace(cfg.Window) != "" {
		parsed, err := time.ParseDuration(cfg.Window)
		if err != nil {
			return effectiveRateLimit{}, err
		}

		window = parsed
	}

	if window <= 0 {
		window = defaultWindow
	}

	return effectiveRateLimit{
		enabled: boolDefault(cfg.Enabled, true),
		limit:   limit,
		window:  window,
	}, nil
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}

	return *value
}

func (s *runtimeSecurity) handlers(
	endpoint string,
	limit effectiveRateLimit,
	handler gin.HandlerFunc,
) []gin.HandlerFunc {
	handlers := make([]gin.HandlerFunc, 0, 3)

	if s.auditEnabled {
		handlers = append(handlers, s.audit(endpoint))
	}

	if limit.enabled {
		handlers = append(handlers, s.rateLimit(endpoint, limit))
	}

	handlers = append(handlers, handler)

	return handlers
}

func (s *runtimeSecurity) rateLimit(endpoint string, limit effectiveRateLimit) gin.HandlerFunc {
	return func(c *gin.Context) {
		remoteIP := remoteIPFromRequest(c.Request)
		ok, retryAfter := s.limiter.allow(endpoint+"|"+remoteIP, limit.limit, limit.window)

		if ok {
			c.Next()

			return
		}

		c.Header("Retry-After", strconv.Itoa(retryAfterSeconds(retryAfter)))
		c.AbortWithStatusJSON(
			http.StatusTooManyRequests,
			gin.H{"error": "rate_limited", "error_description": "too many requests"},
		)
	}
}

func (s *runtimeSecurity) audit(endpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		startedAt := time.Now()
		c.Next()

		status := c.Writer.Status()

		if status == 0 {
			status = http.StatusOK
		}

		attrs := []any{
			"endpoint", endpoint,
			"method", c.Request.Method,
			"path", requestPath(c),
			"status", status,
			"outcome", auditOutcome(status),
			"duration_ms", time.Since(startedAt).Milliseconds(),
			"remote_ip", remoteIPFromRequest(c.Request),
		}

		if endpoint == "token" {
			if clientID := safeAuditClientID(c.Request); clientID != "" {
				attrs = append(attrs, "client_id", clientID)
			}
		}

		slog.InfoContext(c.Request.Context(), "orionis auth request", attrs...)
	}
}

func requestPath(c *gin.Context) string {
	if path := c.FullPath(); path != "" {
		return path
	}

	return c.Request.URL.Path
}

func auditOutcome(status int) string {
	switch {
	case status == http.StatusTooManyRequests:
		return "rate_limited"
	case status >= 200 && status < 300:
		return "success"
	case status >= 500:
		return "error"
	default:
		return "rejected"
	}
}

func safeAuditClientID(r *http.Request) string {
	if id, _, ok := r.BasicAuth(); ok {
		return strings.TrimSpace(id)
	}

	if r.Form != nil {
		return strings.TrimSpace(r.Form.Get("client_id"))
	}

	return ""
}

func remoteIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}

	return strings.TrimSpace(r.RemoteAddr)
}

func retryAfterSeconds(retryAfter time.Duration) int {
	if retryAfter <= 0 {
		return 1
	}

	seconds := int(math.Ceil(retryAfter.Seconds()))

	if seconds < 1 {
		return 1
	}

	return seconds
}

type fixedWindowRateLimiter struct {
	mu sync.Mutex

	now func() time.Time

	windows map[string]rateWindow
}

type rateWindow struct {
	resetAt time.Time
	count   int
}

func newFixedWindowRateLimiter(now func() time.Time) *fixedWindowRateLimiter {
	if now == nil {
		now = time.Now
	}

	return &fixedWindowRateLimiter{
		now:     now,
		windows: make(map[string]rateWindow),
	}
}

func (l *fixedWindowRateLimiter) allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	if limit <= 0 || window <= 0 {
		return true, 0
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	current := l.windows[key]

	if current.resetAt.IsZero() || !now.Before(current.resetAt) {
		current = rateWindow{resetAt: now.Add(window)}
	}

	current.count++
	l.windows[key] = current

	if current.count <= limit {
		return true, 0
	}

	return false, current.resetAt.Sub(now)
}
