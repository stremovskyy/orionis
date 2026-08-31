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
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type runtimeSecurity struct {
	limiter      *fixedWindowRateLimiter
	auditEnabled bool
}

func newRuntimeSecurity(cfg resolvedConfig) *runtimeSecurity {
	return &runtimeSecurity{
		limiter:      newFixedWindowRateLimiter(time.Now),
		auditEnabled: cfg.auditEnabled,
	}
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

	return append(handlers, handler)
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

	if r.PostForm != nil {
		return strings.TrimSpace(r.PostForm.Get("client_id"))
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
