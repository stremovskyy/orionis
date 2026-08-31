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
	"net/http"

	"github.com/stremovskyy/orionis"
)

type Target struct {
	provider *Provider
	audience string
	scopes   []string
}

func (t Target) Scopes(scopes ...string) Target {
	t.scopes = orionis.NormalizeScopes(scopes)

	return t
}

func (t Target) Token(ctx context.Context) (string, error) {
	return t.provider.Token(ctx, t.audience, t.scopes)
}

func (t Target) TokenResponse(ctx context.Context) (orionis.TokenResponse, error) {
	return t.provider.TokenResponse(ctx, t.audience, t.scopes)
}

func (t Target) AuthorizeRequest(ctx context.Context, req *http.Request) error {
	return t.provider.AuthorizeRequest(ctx, req, t.audience, t.scopes)
}

func (t Target) HTTPClient(base *http.Client) *http.Client {
	return NewHTTPClient(base, t.provider, t.audience, t.scopes)
}

func (t Target) Transport(base http.RoundTripper) http.RoundTripper {
	return &Transport{
		Base:     base,
		Provider: t.provider,
		Audience: t.audience,
		Scopes:   cloneStrings(t.scopes),
	}
}
