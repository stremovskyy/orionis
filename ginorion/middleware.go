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

package ginorion

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis"
)

// Config is retained for source compatibility.
// Deprecated: use Builder and Guard.
type Config struct {
	Verifier       *orionis.Verifier
	RequiredScopes []string
	ClaimsKey      string
	ErrorHandler   ErrorHandler
}

// Option is retained for source compatibility.
// Deprecated: use Builder methods.
type Option func(*Config)

// WithScopes is retained for source compatibility.
// Deprecated: use Builder.Scopes or Guard.Require.
func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.RequiredScopes = orionis.NormalizeScopes(scopes) }
}

// WithClaimsKey is retained for source compatibility.
// Deprecated: use Builder.ClaimsKey.
func WithClaimsKey(key string) Option {
	return func(c *Config) {
		if key != "" {
			c.ClaimsKey = key
		}
	}
}

// WithErrorHandler is retained for source compatibility.
// Deprecated: use Builder.ErrorHandler.
func WithErrorHandler(handler ErrorHandler) Option {
	return func(c *Config) {
		if handler != nil {
			c.ErrorHandler = handler
		}
	}
}

// Middleware is retained for source compatibility.
// Deprecated: use FromVerifier(verifier).Scopes(...).MustHandler().
func Middleware(verifier *orionis.Verifier, opts ...Option) gin.HandlerFunc {
	cfg := Config{Verifier: verifier, ClaimsKey: DefaultClaimsKey, ErrorHandler: defaultErrorHandler}

	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return middlewareFromConfig(cfg)
}

func middlewareFromConfig(cfg Config) gin.HandlerFunc {
	guard := newGuard(cfg.Verifier, cfg.RequiredScopes, cfg.ClaimsKey, cfg.ErrorHandler)

	return func(c *gin.Context) {
		tokenString, err := orionis.BearerToken(c.GetHeader("Authorization"))
		if err != nil {
			guard.reject(c, http.StatusUnauthorized, "missing_bearer_token", err)

			return
		}

		if guard.verifier == nil {
			guard.reject(
				c,
				http.StatusInternalServerError,
				"auth_misconfigured",
				errors.New("ginorion: nil verifier"),
			)

			return
		}

		verified, err := guard.verifier.Verify(c.Request.Context(), tokenString)
		if err != nil {
			guard.reject(c, http.StatusUnauthorized, "invalid_token", err)

			return
		}

		if !verified.Claims.HasAllScopes(guard.requiredScopes...) {
			guard.reject(c, http.StatusForbidden, "insufficient_scope", orionis.ErrInsufficientScope)

			return
		}

		c.Set(guard.claimsKey, verified.Claims)
		c.Set(DefaultClaimsKey, verified.Claims)
		c.Next()
	}
}

func (g *Guard) reject(c *gin.Context, status int, code string, err error) {
	g.errorHandler(c, status, code, err)
	c.Abort()
}

// BearerToken is retained for source compatibility.
func BearerToken(header string) (string, error) {
	return orionis.BearerToken(header)
}
