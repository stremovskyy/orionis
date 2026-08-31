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
	"strings"
	"time"

	"github.com/stremovskyy/orionis"
)

type cachedToken struct {
	response  orionis.TokenResponse
	expiresAt time.Time
}

type tokenCacheKey struct {
	audience string
	scope    string
}

type inflightCall struct {
	done      chan struct{}
	cancel    context.CancelFunc
	waiters   int
	token     cachedToken
	err       error
	completed bool
	abandoned bool
}

func (p *Provider) tokenResponse(
	ctx context.Context,
	audience string,
	scopes []string,
) (orionis.TokenResponse, error) {
	key := cacheKey(audience, scopes)

	if token, ok := p.cached(key); ok {
		return token.response, nil
	}

	if ctx == nil {
		return orionis.TokenResponse{}, errors.New("net/http: nil Context")
	}

	if err := ctx.Err(); err != nil {
		return orionis.TokenResponse{}, err
	}

	call, token, cached := p.joinOrStartCall(ctx, key, audience, scopes)

	if cached {
		return token.response, nil
	}

	return p.waitForCall(ctx, key, call)
}

func (p *Provider) cached(key tokenCacheKey) (cachedToken, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.purgeStaleLocked(time.Now())
	token, ok := p.cache[key]

	return token, ok
}

func (p *Provider) joinOrStartCall(
	parent context.Context,
	key tokenCacheKey,
	audience string,
	scopes []string,
) (*inflightCall, cachedToken, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.purgeStaleLocked(time.Now())

	if token, ok := p.cache[key]; ok {
		return nil, token, true
	}

	if call, ok := p.inflight[key]; ok {
		call.waiters++

		return call, cachedToken{}, false
	}

	requestCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	call := &inflightCall{
		done:    make(chan struct{}),
		cancel:  cancel,
		waiters: 1,
	}
	p.inflight[key] = call

	go p.runCall(requestCtx, key, audience, cloneStrings(scopes), call)

	return call, cachedToken{}, false
}

func (p *Provider) waitForCall(
	ctx context.Context,
	key tokenCacheKey,
	call *inflightCall,
) (orionis.TokenResponse, error) {
	select {
	case <-call.done:
		if call.err != nil {
			return orionis.TokenResponse{}, call.err
		}

		return call.token.response, nil
	case <-ctx.Done():
		p.releaseWaiter(key, call)

		return orionis.TokenResponse{}, ctx.Err()
	}
}

func (p *Provider) runCall(
	ctx context.Context,
	key tokenCacheKey,
	audience string,
	scopes []string,
	call *inflightCall,
) {
	token, err := p.requestToken(ctx, audience, scopes)

	p.mu.Lock()
	defer p.mu.Unlock()

	call.token = token
	call.err = err
	call.completed = true
	call.cancel()

	if current, ok := p.inflight[key]; ok && current == call {
		if err == nil && !call.abandoned {
			p.cache[key] = token
		}

		delete(p.inflight, key)
	}

	close(call.done)
}

func (p *Provider) releaseWaiter(key tokenCacheKey, call *inflightCall) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if call.completed || call.abandoned {
		return
	}

	current, ok := p.inflight[key]

	if !ok || current != call {
		return
	}

	call.waiters--

	if call.waiters > 0 {
		return
	}

	call.abandoned = true
	delete(p.inflight, key)
	call.cancel()
}

func (p *Provider) purgeStaleLocked(now time.Time) {
	for key, token := range p.cache {
		if !p.freshAt(token, now) {
			delete(p.cache, key)
		}
	}
}

func (p *Provider) freshAt(token cachedToken, now time.Time) bool {
	if token.response.ExpiresIn <= 0 {
		return false
	}

	skew := p.refreshSkew
	ttl := time.Duration(token.response.ExpiresIn) * time.Second

	if skew >= ttl {
		skew = ttl / 10
	}

	return token.expiresAt.Sub(now) > skew
}

func cacheKey(audience string, scopes []string) tokenCacheKey {
	return tokenCacheKey{
		audience: strings.TrimSpace(audience),
		scope:    orionis.ScopeString(scopes),
	}
}
