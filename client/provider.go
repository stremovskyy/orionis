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
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stremovskyy/orionis"
)

type Provider struct {
	tokenURL      string
	audience      string
	scopes        []string
	httpClient    *http.Client
	authenticator Authenticator
	refreshSkew   time.Duration

	mu       sync.Mutex
	cache    map[tokenCacheKey]cachedToken
	inflight map[tokenCacheKey]*inflightCall
}

func newProvider(cfg Config) *Provider {
	return &Provider{
		tokenURL:      cfg.TokenURL,
		audience:      cfg.Audience,
		scopes:        cloneStrings(cfg.Scopes),
		httpClient:    cfg.HTTPClient,
		authenticator: cfg.Authenticator,
		refreshSkew:   cfg.RefreshSkew,
		cache:         make(map[tokenCacheKey]cachedToken),
		inflight:      make(map[tokenCacheKey]*inflightCall),
	}
}

func (p *Provider) For(audience string, scopes ...string) Target {
	return Target{provider: p, audience: audience, scopes: orionis.NormalizeScopes(scopes)}
}

func (p *Provider) Token(ctx context.Context, audience string, scopes []string) (string, error) {
	resp, err := p.TokenResponse(ctx, audience, scopes)
	if err != nil {
		return "", err
	}

	return resp.AccessToken, nil
}

func (p *Provider) TokenResponse(
	ctx context.Context,
	audience string,
	scopes []string,
) (orionis.TokenResponse, error) {
	if p == nil {
		return orionis.TokenResponse{}, errors.New("orionis client: nil provider")
	}

	audience, scopes, err := p.target(audience, scopes)
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	return p.tokenResponse(ctx, audience, scopes)
}

func (p *Provider) AuthorizeRequest(
	ctx context.Context,
	req *http.Request,
	audience string,
	scopes []string,
) error {
	if req == nil {
		return errors.New("orionis client: nil request")
	}

	token, err := p.Token(ctx, audience, scopes)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return nil
}

func (p *Provider) HTTPClient(base *http.Client) *http.Client {
	return NewHTTPClient(base, p, "", nil)
}

func (p *Provider) Transport(base http.RoundTripper) http.RoundTripper {
	return &Transport{Base: base, Provider: p}
}

func (p *Provider) target(audience string, scopes []string) (string, []string, error) {
	if strings.TrimSpace(audience) == "" {
		audience = p.audience
	}

	if len(scopes) == 0 {
		scopes = p.scopes
	}

	audience = strings.TrimSpace(audience)
	scopes = orionis.NormalizeScopes(scopes)

	if audience == "" {
		return "", nil, errors.New("orionis client: audience is required")
	}

	return audience, scopes, nil
}
