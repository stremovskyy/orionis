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

package client

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/stremovskyy/orionis"
)

type Config struct {
	TokenURL      string
	ClientID      string
	ClientSecret  string
	Audience      string
	Scopes        []string
	HTTPClient    *http.Client
	Authenticator Authenticator
	RefreshSkew   time.Duration
}

type Builder struct {
	cfg Config
}

func New() *Builder {
	return &Builder{}
}

func FromConfig(cfg Config) *Builder {
	return &Builder{cfg: cloneConfig(cfg)}
}

func NewProvider(cfg Config) (*Provider, error) {
	return buildProvider(cfg)
}

func (b *Builder) TokenURL(tokenURL string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.TokenURL = strings.TrimSpace(tokenURL)

	return b
}

func (b *Builder) As(clientID, clientSecret string) *Builder {
	return b.ClientSecret(clientID, clientSecret)
}

// Deprecated: use ClientSecret.
func (b *Builder) Credentials(clientID, clientSecret string) *Builder {
	return b.ClientSecret(clientID, clientSecret)
}

func (b *Builder) ClientSecret(clientID, clientSecret string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.ClientID = strings.TrimSpace(clientID)
	b.cfg.ClientSecret = clientSecret

	return b
}

func (b *Builder) For(audience string, scopes ...string) *Builder {
	return b.Audience(audience).Scopes(scopes...)
}

func (b *Builder) Audience(audience string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.Audience = strings.TrimSpace(audience)

	return b
}

func (b *Builder) Scope(scope string) *Builder {
	return b.Scopes(scope)
}

func (b *Builder) Scopes(scopes ...string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.Scopes = append(b.cfg.Scopes, scopes...)

	return b
}

func (b *Builder) TokenHTTPClient(hc *http.Client) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.HTTPClient = hc

	return b
}

func (b *Builder) Authenticator(authenticator Authenticator) *Builder {
	if b == nil {
		return nil
	}

	if authenticator != nil {
		b.cfg.Authenticator = authenticator
	}

	return b
}

func (b *Builder) RefreshSkew(skew time.Duration) *Builder {
	if b == nil {
		return nil
	}

	if skew > 0 {
		b.cfg.RefreshSkew = skew
	}

	return b
}

func (b *Builder) Build() (*Provider, error) {
	if b == nil {
		return nil, errors.New("orionis client: nil builder")
	}

	return buildProvider(b.cfg)
}

func (b *Builder) Must() *Provider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

func (b *Builder) BuildHTTPClient(base *http.Client) (*http.Client, error) {
	provider, err := b.Build()
	if err != nil {
		return nil, err
	}

	return provider.HTTPClient(base), nil
}

func (b *Builder) MustHTTPClient(base *http.Client) *http.Client {
	hc, err := b.BuildHTTPClient(base)
	if err != nil {
		panic(err)
	}

	return hc
}

func buildProvider(raw Config) (*Provider, error) {
	cfg, err := normalizeConfig(raw)
	if err != nil {
		return nil, err
	}

	return newProvider(cfg), nil
}

func normalizeConfig(raw Config) (Config, error) {
	cfg := cloneConfig(raw)
	cfg.TokenURL = strings.TrimSpace(cfg.TokenURL)
	cfg.ClientID = strings.TrimSpace(cfg.ClientID)
	cfg.Audience = strings.TrimSpace(cfg.Audience)
	cfg.Scopes = orionis.NormalizeScopes(cfg.Scopes)

	if cfg.TokenURL == "" {
		return Config{}, errors.New("orionis client: token url is required")
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultTokenHTTPClient()
	}

	if cfg.RefreshSkew <= 0 {
		cfg.RefreshSkew = defaultRefreshSkew
	}

	if cfg.Authenticator == nil {
		cfg.Authenticator = ClientSecretBasic{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret}
	}

	return cfg, nil
}

func cloneConfig(cfg Config) Config {
	cfg.Scopes = cloneStrings(cfg.Scopes)

	return cfg
}

func cloneStrings(values []string) []string {
	return append([]string(nil), values...)
}

func defaultTokenHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultTokenHTTPTimeout}
}
