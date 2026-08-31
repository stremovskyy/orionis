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
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const maxLimiterSweepInterval = time.Minute

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

	windows   map[string]rateWindow
	nextSweep time.Time
}

type rateWindow struct {
	resetAt time.Time
	count   int
}

func newFixedWindowRateLimiter(now func() time.Time) *fixedWindowRateLimiter {
	if now == nil {
		now = time.Now
	}

	return &fixedWindowRateLimiter{now: now, windows: make(map[string]rateWindow)}
}

func (l *fixedWindowRateLimiter) allow(key string, limit int, window time.Duration) (bool, time.Duration) {
	if limit <= 0 || window <= 0 {
		return true, 0
	}

	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepExpired(now, window)
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

func (l *fixedWindowRateLimiter) sweepExpired(now time.Time, window time.Duration) {
	if !l.nextSweep.IsZero() && now.Before(l.nextSweep) {
		return
	}

	for key, current := range l.windows {
		if !now.Before(current.resetAt) {
			delete(l.windows, key)
		}
	}

	interval := min(window, maxLimiterSweepInterval)
	l.nextSweep = now.Add(interval)
}
