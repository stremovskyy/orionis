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

package jwk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/stremovskyy/orionis/internal/httpjson"
)

const (
	defaultRemoteHTTPTimeout = 10 * time.Second
	defaultRefreshInterval   = 10 * time.Minute
	defaultMaxStale          = time.Hour
	maxJWKSResponseBody      = 1 << 20
)

var errUninitializedRemoteProvider = errors.New("orionis jwk: uninitialized remote provider")

type RemoteConfig struct {
	URL             string
	HTTPClient      *http.Client
	RefreshInterval time.Duration
	MaxStale        time.Duration
}

type RemoteBuilder struct {
	cfg RemoteConfig
}

func Remote(url ...string) *RemoteBuilder {
	b := &RemoteBuilder{}

	if len(url) > 0 {
		b.URL(url[0])
	}

	return b
}

func (b *RemoteBuilder) URL(url string) *RemoteBuilder {
	if b == nil {
		return nil
	}

	b.cfg.URL = strings.TrimSpace(url)

	return b
}

func (b *RemoteBuilder) HTTPClient(hc *http.Client) *RemoteBuilder {
	if b == nil {
		return nil
	}

	b.cfg.HTTPClient = hc

	return b
}

func (b *RemoteBuilder) RefreshEvery(interval time.Duration) *RemoteBuilder {
	if b == nil {
		return nil
	}

	if interval > 0 {
		b.cfg.RefreshInterval = interval
	}

	return b
}

func (b *RemoteBuilder) MaxStale(maxStale time.Duration) *RemoteBuilder {
	if b == nil {
		return nil
	}

	if maxStale > 0 {
		b.cfg.MaxStale = maxStale
	}

	return b
}

func (b *RemoteBuilder) Build() (*RemoteProvider, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil remote builder")
	}

	return NewRemoteProvider(b.cfg)
}

func (b *RemoteBuilder) Must() *RemoteProvider {
	provider, err := b.Build()
	if err != nil {
		panic(err)
	}

	return provider
}

type RemoteProvider struct {
	url             string
	httpClient      *http.Client
	refreshInterval time.Duration
	maxStale        time.Duration

	refreshGate chan struct{}
	mu          sync.RWMutex
	keys        map[string]decodedKey
	expiresAt   time.Time
	fetchedAt   time.Time

	generation                  uint64
	refreshVersion              uint64
	lastRefreshErr              error
	lastRefreshCanceledByCaller bool
}

type remoteSnapshot struct {
	key            decodedKey
	found          bool
	fresh          bool
	staleOK        bool
	generation     uint64
	refreshVersion uint64
}

func NewRemoteProvider(cfg RemoteConfig) (*RemoteProvider, error) {
	cfg.URL = strings.TrimSpace(cfg.URL)

	if cfg.URL == "" {
		return nil, errors.New("jwks url is required")
	}

	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultRemoteHTTPClient()
	}

	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = defaultRefreshInterval
	}

	if cfg.MaxStale <= 0 {
		cfg.MaxStale = defaultMaxStale
	}

	return &RemoteProvider{
		url:             cfg.URL,
		httpClient:      cfg.HTTPClient,
		refreshInterval: cfg.RefreshInterval,
		maxStale:        cfg.MaxStale,
		refreshGate:     make(chan struct{}, 1),
		keys:            make(map[string]decodedKey),
	}, nil
}

func (p *RemoteProvider) Key(ctx context.Context, kid string, alg string) (any, error) {
	if p == nil || p.refreshGate == nil {
		return nil, errUninitializedRemoteProvider
	}

	snapshot := p.snapshot(kid, time.Now())

	if snapshot.found && snapshot.fresh {
		return snapshot.key.forAlgorithm(kid, alg)
	}

	err := p.refreshIfUnchanged(ctx, snapshot.generation, snapshot.refreshVersion)
	if err != nil {
		stale := p.snapshot(kid, time.Now())

		if stale.found && stale.staleOK {
			return stale.key.forAlgorithm(kid, alg)
		}

		return nil, err
	}

	refreshed := p.snapshot(kid, time.Now())

	if !refreshed.found {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, kid)
	}

	return refreshed.key.forAlgorithm(kid, alg)
}

func (p *RemoteProvider) Refresh(ctx context.Context) error {
	if err := p.lockRefresh(ctx); err != nil {
		return err
	}

	defer p.unlockRefresh()

	return p.refreshLocked(ctx)
}

func (p *RemoteProvider) refreshIfUnchanged(
	ctx context.Context,
	generation uint64,
	refreshVersion uint64,
) error {
	if err := p.lockRefresh(ctx); err != nil {
		return err
	}

	defer p.unlockRefresh()

	p.mu.RLock()
	currentGeneration := p.generation
	currentRefreshVersion := p.refreshVersion
	lastRefreshErr := p.lastRefreshErr
	lastRefreshCanceledByCaller := p.lastRefreshCanceledByCaller
	p.mu.RUnlock()

	if currentGeneration != generation {
		return nil
	}

	if currentRefreshVersion != refreshVersion {
		if lastRefreshCanceledByCaller && ctx.Err() == nil {
			return p.refreshLocked(ctx)
		}

		return lastRefreshErr
	}

	return p.refreshLocked(ctx)
}

func (p *RemoteProvider) lockRefresh(ctx context.Context) error {
	if ctx == nil {
		return errors.New("net/http: nil Context")
	}

	if p == nil || p.refreshGate == nil {
		return errUninitializedRemoteProvider
	}

	select {
	case p.refreshGate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *RemoteProvider) unlockRefresh() {
	<-p.refreshGate
}

func (p *RemoteProvider) refreshLocked(ctx context.Context) error {
	decoded, err := p.fetch(ctx)
	now := time.Now()
	canceledByCaller := err != nil && ctx.Err() != nil && errors.Is(err, ctx.Err())

	p.mu.Lock()
	p.refreshVersion++
	p.lastRefreshErr = err
	p.lastRefreshCanceledByCaller = canceledByCaller

	if err == nil {
		p.keys = decoded
		p.fetchedAt = now
		p.expiresAt = now.Add(p.refreshInterval)
		p.generation++
	}

	p.mu.Unlock()

	return err
}

func (p *RemoteProvider) fetch(ctx context.Context) (map[string]decodedKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	res, err := p.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("fetch jwks: %w", ctxErr)
		}

		return nil, fmt.Errorf("fetch jwks: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks: unexpected status %d", res.StatusCode)
	}

	var set Set

	if err := httpjson.Decode(res.Body, maxJWKSResponseBody, &set); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}

	decoded, err := decodeSet(set)
	if err != nil {
		if errors.Is(err, errNoKeys) {
			return nil, errors.New("jwks has no usable signing keys")
		}

		return nil, err
	}

	return decoded, nil
}

func (p *RemoteProvider) snapshot(kid string, now time.Time) remoteSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()

	key, found := p.keys[kid]

	return remoteSnapshot{
		key:            key,
		found:          found,
		fresh:          now.Before(p.expiresAt),
		staleOK:        !p.fetchedAt.IsZero() && now.Sub(p.fetchedAt) <= p.maxStale,
		generation:     p.generation,
		refreshVersion: p.refreshVersion,
	}
}

func defaultRemoteHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultRemoteHTTPTimeout}
}
