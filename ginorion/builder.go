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
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
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

	if key = strings.TrimSpace(key); key != "" {
		b.claimsKey = key
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

	verifier, err := b.buildVerifier()
	if err != nil {
		return nil, err
	}

	return newGuard(verifier, b.requiredScopes, b.claimsKey, b.errorHandler), nil
}

func (b *Builder) buildVerifier() (*orionis.Verifier, error) {
	if b.verifier != nil {
		return b.verifier, nil
	}

	if b.issuer == "" {
		return nil, errors.New("ginorion: issuer is required")
	}

	if b.audience == "" {
		return nil, errors.New("ginorion: audience is required")
	}

	provider := b.provider

	if provider == nil {
		if b.jwksURL == "" {
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

	return orionis.NewVerifier().Issuer(b.issuer).Audience(b.audience).KeyProvider(provider), nil
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
	return b.Must().Handler()
}

type Guard struct {
	verifier       *orionis.Verifier
	claimsKey      string
	errorHandler   ErrorHandler
	requiredScopes []string
}

func newGuard(
	verifier *orionis.Verifier,
	requiredScopes []string,
	claimsKey string,
	errorHandler ErrorHandler,
) *Guard {
	if claimsKey == "" {
		claimsKey = DefaultClaimsKey
	}

	if errorHandler == nil {
		errorHandler = defaultErrorHandler
	}

	return &Guard{
		verifier:       verifier,
		claimsKey:      claimsKey,
		errorHandler:   errorHandler,
		requiredScopes: orionis.NormalizeScopes(requiredScopes),
	}
}

func (g *Guard) Handler() gin.HandlerFunc {
	return g.Require()
}

func (g *Guard) Scope(scope string) gin.HandlerFunc {
	return g.Require(scope)
}

func (g *Guard) Require(scopes ...string) gin.HandlerFunc {
	return middlewareFromConfig(Config{
		Verifier:       g.verifier,
		RequiredScopes: firstScopes(scopes, g.requiredScopes),
		ClaimsKey:      g.claimsKey,
		ErrorHandler:   g.errorHandler,
	})
}

func firstScopes(primary []string, fallback []string) []string {
	if len(primary) > 0 {
		return primary
	}

	return fallback
}
