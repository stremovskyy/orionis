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
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

const DefaultClaimsKey = "orionis.claims"

type ErrorHandler func(c *gin.Context, status int, code string, err error)

type Builder struct {
	verifier       *orionis.Verifier
	provider       orionis.KeyProvider
	issuer         string
	audience       string
	jwksURL        string
	httpClient     *http.Client
	refreshEvery   time.Duration
	maxStale       time.Duration
	requiredScopes []string
	claimsKey      string
	errorHandler   ErrorHandler
	err            error
}

func New() *Builder {
	return &Builder{claimsKey: DefaultClaimsKey, errorHandler: defaultErrorHandler}
}

func FromVerifier(verifier *orionis.Verifier) *Builder {
	return New().Verifier(verifier)
}

func (b *Builder) Verifier(verifier *orionis.Verifier) *Builder {
	if b == nil {
		return nil
	}

	b.verifier = verifier

	return b
}

func (b *Builder) Issuer(issuer string) *Builder {
	if b == nil {
		return nil
	}

	b.issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")

	return b
}

func (b *Builder) Audience(audience string) *Builder {
	if b == nil {
		return nil
	}

	b.audience = strings.TrimSpace(audience)

	return b
}

func (b *Builder) JWKS(url string) *Builder {
	if b == nil {
		return nil
	}

	b.jwksURL = strings.TrimSpace(url)

	return b
}

func (b *Builder) KeyProvider(provider orionis.KeyProvider) *Builder {
	if b == nil {
		return nil
	}

	b.provider = provider

	return b
}

func (b *Builder) HTTPClient(hc *http.Client) *Builder {
	if b == nil {
		return nil
	}

	b.httpClient = hc

	return b
}

func (b *Builder) RefreshEvery(interval time.Duration) *Builder {
	if b == nil {
		return nil
	}

	if interval > 0 {
		b.refreshEvery = interval
	}

	return b
}

func (b *Builder) MaxStale(maxStale time.Duration) *Builder {
	if b == nil {
		return nil
	}

	if maxStale > 0 {
		b.maxStale = maxStale
	}

	return b
}

func (b *Builder) Scope(scope string) *Builder {
	return b.Scopes(scope)
}

func (b *Builder) Scopes(scopes ...string) *Builder {
	if b == nil {
		return nil
	}

	b.requiredScopes = append(b.requiredScopes, scopes...)

	return b
}

func (b *Builder) ClaimsKey(key string) *Builder {
	if b == nil {
		return nil
	}

	if strings.TrimSpace(key) != "" {
		b.claimsKey = strings.TrimSpace(key)
	}

	return b
}

func (b *Builder) ErrorHandler(handler ErrorHandler) *Builder {
	if b == nil {
		return nil
	}

	if handler != nil {
		b.errorHandler = handler
	}

	return b
}

func (b *Builder) Build() (*Guard, error) {
	if b == nil {
		return nil, errors.New("ginorion: nil builder")
	}

	if b.err != nil {
		return nil, b.err
	}

	verifier := b.verifier
	if verifier == nil {
		if strings.TrimSpace(b.issuer) == "" {
			return nil, errors.New("ginorion: issuer is required")
		}

		if strings.TrimSpace(b.audience) == "" {
			return nil, errors.New("ginorion: audience is required")
		}

		provider := b.provider
		if provider == nil {
			if strings.TrimSpace(b.jwksURL) == "" {
				return nil, errors.New("ginorion: verifier, key provider, or jwks url is required")
			}

			remote, err := jwk.Remote(b.jwksURL).
				HTTPClient(b.httpClient).
				RefreshEvery(b.refreshEvery).
				MaxStale(b.maxStale).
				Build()
			if err != nil {
				return nil, err
			}

			provider = remote
		}

		verifier = orionis.NewVerifier().Issuer(b.issuer).Audience(b.audience).Keys(provider)
	}

	claimsKey := b.claimsKey

	if claimsKey == "" {
		claimsKey = DefaultClaimsKey
	}

	errorHandler := b.errorHandler
	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}

	return &Guard{
		verifier:       verifier,
		claimsKey:      claimsKey,
		errorHandler:   errorHandler,
		requiredScopes: orionis.NormalizeScopes(b.requiredScopes),
	}, nil
}

func (b *Builder) Must() *Guard {
	guard, err := b.Build()
	if err != nil {
		panic(err)
	}

	return guard
}

func (b *Builder) Handler() (gin.HandlerFunc, error) {
	guard, err := b.Build()
	if err != nil {
		return nil, err
	}

	return guard.Handler(), nil
}

func (b *Builder) MustHandler() gin.HandlerFunc {
	guard := b.Must()

	return guard.Handler()
}

type Guard struct {
	verifier       *orionis.Verifier
	claimsKey      string
	errorHandler   ErrorHandler
	requiredScopes []string
}

func (g *Guard) Handler() gin.HandlerFunc {
	return g.Require()
}

func (g *Guard) Scope(scope string) gin.HandlerFunc {
	return g.Require(scope)
}

func (g *Guard) Require(scopes ...string) gin.HandlerFunc {
	cfg := Config{
		Verifier:       g.verifier,
		RequiredScopes: firstScopes(scopes, g.requiredScopes),
		ClaimsKey:      g.claimsKey,
		ErrorHandler:   g.errorHandler,
	}

	return middlewareFromConfig(cfg)
}

type Config struct {
	Verifier       *orionis.Verifier
	RequiredScopes []string
	ClaimsKey      string
	ErrorHandler   ErrorHandler
}

type Option func(*Config)

func WithScopes(scopes ...string) Option {
	return func(c *Config) { c.RequiredScopes = orionis.NormalizeScopes(scopes) }
}

func WithClaimsKey(key string) Option {
	return func(c *Config) {
		if key != "" {
			c.ClaimsKey = key
		}
	}
}

func WithErrorHandler(handler ErrorHandler) Option {
	return func(c *Config) {
		if handler != nil {
			c.ErrorHandler = handler
		}
	}
}

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
	if cfg.ClaimsKey == "" {
		cfg.ClaimsKey = DefaultClaimsKey
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultErrorHandler
	}

	cfg.RequiredScopes = orionis.NormalizeScopes(cfg.RequiredScopes)

	return func(c *gin.Context) {
		tokenString, err := orionis.BearerToken(c.GetHeader("Authorization"))
		if err != nil {
			cfg.ErrorHandler(c, http.StatusUnauthorized, "missing_bearer_token", err)
			c.Abort()

			return
		}

		if cfg.Verifier == nil {
			cfg.ErrorHandler(
				c,
				http.StatusInternalServerError,
				"auth_misconfigured",
				errors.New("ginorion: nil verifier"),
			)
			c.Abort()

			return
		}

		verified, err := cfg.Verifier.Verify(c.Request.Context(), tokenString)
		if err != nil {
			cfg.ErrorHandler(c, http.StatusUnauthorized, "invalid_token", err)
			c.Abort()

			return
		}

		if !verified.Claims.HasAllScopes(cfg.RequiredScopes...) {
			cfg.ErrorHandler(c, http.StatusForbidden, "insufficient_scope", orionis.ErrInsufficientScope)
			c.Abort()

			return
		}

		c.Set(cfg.ClaimsKey, verified.Claims)
		c.Set(DefaultClaimsKey, verified.Claims)
		c.Next()
	}
}

func BearerToken(header string) (string, error) {
	return orionis.BearerToken(header)
}

func Claims(c *gin.Context) (*orionis.Claims, bool) {
	v, ok := c.Get(DefaultClaimsKey)

	if !ok {
		return nil, false
	}

	claims, ok := v.(*orionis.Claims)

	return claims, ok
}

func MustClaims(c *gin.Context) *orionis.Claims {
	claims, ok := Claims(c)

	if !ok {
		panic("orionis claims missing from gin context")
	}

	return claims
}

type AuthRoutes struct {
	auth          *server.Server
	tokenPath     string
	jwksPath      string
	discoveryPath string
	healthPath    string
}

func Auth(auth *server.Server) *AuthRoutes {
	return &AuthRoutes{
		auth:          auth,
		tokenPath:     "/oauth/token",
		jwksPath:      "/.well-known/jwks.json",
		discoveryPath: "/.well-known/openid-configuration",
		healthPath:    "/healthz",
	}
}

func (r *AuthRoutes) TokenPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.tokenPath = path
	}

	return r
}

func (r *AuthRoutes) JWKSPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.jwksPath = path
	}

	return r
}

func (r *AuthRoutes) DiscoveryPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.discoveryPath = path
	}

	return r
}

func (r *AuthRoutes) HealthPath(path string) *AuthRoutes {
	if r == nil {
		return nil
	}

	if path != "" {
		r.healthPath = path
	}

	return r
}

func (r *AuthRoutes) Mount(routes gin.IRoutes) gin.IRoutes {
	if r == nil || r.auth == nil {
		return routes
	}

	routes.POST(r.tokenPath, gin.WrapF(r.auth.TokenHTTP))
	routes.GET(r.jwksPath, gin.WrapF(r.auth.JWKSHTTP))
	routes.GET(r.discoveryPath, gin.WrapF(r.auth.DiscoveryHTTP))
	routes.GET(r.healthPath, gin.WrapF(r.auth.HealthHTTP))

	return routes
}

func RegisterAuthRoutes(routes gin.IRoutes, auth *server.Server) {
	Auth(auth).Mount(routes)
}

func defaultErrorHandler(c *gin.Context, status int, code string, err error) {
	attrs := []any{"status", status, "code", code}
	if err != nil {
		attrs = append(attrs, "error", err)
	}

	if status >= http.StatusInternalServerError {
		slog.ErrorContext(c.Request.Context(), "orionis auth middleware error", attrs...)
	} else {
		slog.WarnContext(c.Request.Context(), "orionis auth request rejected", attrs...)
	}

	c.JSON(
		status, gin.H{
			"error":   code,
			"message": publicErrorMessage(status, code),
		},
	)
}

func publicErrorMessage(status int, code string) string {
	switch code {
	case "missing_bearer_token":
		return "missing bearer token"
	case "invalid_token":
		return "invalid token"
	case "insufficient_scope":
		return "insufficient scope"
	case "auth_misconfigured":
		return "authentication service unavailable"
	default:
		if status >= http.StatusInternalServerError {
			return "authentication service unavailable"
		}

		return "authentication request rejected"
	}
}

func firstScopes(primary []string, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}

	return fallback
}
