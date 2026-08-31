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

package server

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	DefaultMaxTokenRequestBody = 1 << 20
	defaultAccessTokenTTL      = 15 * time.Minute
)

type Config struct {
	Issuer              string
	Store               ClientStore
	Signers             []Signer
	ActiveKID           string
	AccessTokenTTL      time.Duration
	MaxTokenRequestBody int64

	Now func() time.Time

	Clients []Client
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

func NewServer(cfg Config) (*Server, error) {
	return buildServer(cfg)
}

func (b *Builder) Issuer(issuer string) *Builder {
	if b != nil {
		b.cfg.Issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	}

	return b
}

func (b *Builder) Store(store ClientStore) *Builder {
	if b != nil && store != nil {
		b.cfg.Store = store
	}

	return b
}

func (b *Builder) Client(client Client) *Builder {
	if b != nil {
		b.cfg.Clients = append(b.cfg.Clients, cloneClient(client))
	}

	return b
}

func (b *Builder) Clients(clients ...Client) *Builder {
	if b != nil {
		for _, client := range clients {
			b.Client(client)
		}
	}

	return b
}

func (b *Builder) Signer(signer Signer) *Builder {
	if b != nil && signer != nil {
		b.cfg.Signers = append(b.cfg.Signers, signer)
	}

	return b
}

func (b *Builder) Signers(signers ...Signer) *Builder {
	if b != nil {
		for _, signer := range signers {
			b.Signer(signer)
		}
	}

	return b
}

func (b *Builder) ActiveKID(kid string) *Builder {
	if b != nil {
		b.cfg.ActiveKID = strings.TrimSpace(kid)
	}

	return b
}

// TTL sets the access-token lifetime.
//
// Deprecated: use AccessTokenTTL.
func (b *Builder) TTL(ttl time.Duration) *Builder {
	return b.AccessTokenTTL(ttl)
}

func (b *Builder) AccessTokenTTL(ttl time.Duration) *Builder {
	if b != nil && ttl > 0 {
		b.cfg.AccessTokenTTL = ttl
	}

	return b
}

func (b *Builder) MaxBody(size int64) *Builder {
	if b != nil && size > 0 {
		b.cfg.MaxTokenRequestBody = size
	}

	return b
}

func (b *Builder) Clock(now func() time.Time) *Builder {
	if b != nil && now != nil {
		b.cfg.Now = now
	}

	return b
}

func (b *Builder) Build() (*Server, error) {
	if b == nil {
		return nil, errors.New("orionis server: nil builder")
	}

	return buildServer(b.cfg)
}

func (b *Builder) Must() *Server {
	server, err := b.Build()
	if err != nil {
		panic(err)
	}

	return server
}

func buildServer(input Config) (*Server, error) {
	cfg := normalizeConfig(input)
	activeSigner, err := validateConfig(cfg)
	if err != nil {
		return nil, err
	}

	if cfg.Store == nil {
		cfg.Store = NewMemoryClientStore(cfg.Clients...)
	}

	return &Server{
		issuer:              cfg.Issuer,
		maxTokenRequestBody: cfg.MaxTokenRequestBody,
		signers:             slices.Clone(cfg.Signers),
		activeSigner:        activeSigner,
		tokens: tokenService{
			issuer:         cfg.Issuer,
			store:          cfg.Store,
			signer:         activeSigner,
			accessTokenTTL: cfg.AccessTokenTTL,
			now:            cfg.Now,
		},
	}, nil
}

func normalizeConfig(cfg Config) Config {
	cfg = cloneConfig(cfg)
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	cfg.ActiveKID = strings.TrimSpace(cfg.ActiveKID)

	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}

	if cfg.MaxTokenRequestBody <= 0 {
		cfg.MaxTokenRequestBody = DefaultMaxTokenRequestBody
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	for index := range cfg.Clients {
		cfg.Clients[index] = cfg.Clients[index].Normalize()
	}

	return cfg
}

func validateConfig(cfg Config) (Signer, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("issuer is required")
	}

	if len(cfg.Signers) == 0 {
		return nil, errors.New("at least one signer is required")
	}

	seenKIDs := make(map[string]struct{}, len(cfg.Signers))
	var active Signer

	for _, signer := range cfg.Signers {
		if signer == nil {
			return nil, errors.New("nil signer is not allowed")
		}

		kid := strings.TrimSpace(signer.KeyID())

		if kid == "" {
			return nil, errors.New("signer kid is required")
		}

		if _, exists := seenKIDs[kid]; exists {
			return nil, fmt.Errorf("duplicate signer kid %q", kid)
		}

		seenKIDs[kid] = struct{}{}

		if cfg.ActiveKID == kid {
			active = signer
		}
	}

	if cfg.ActiveKID != "" && active == nil {
		return nil, fmt.Errorf("active signer %q was not added", cfg.ActiveKID)
	}

	if active == nil {
		active = cfg.Signers[0]
	}

	if cfg.Store != nil && len(cfg.Clients) > 0 {
		return nil, errors.New("use either Store(...) or Client(...), not both")
	}

	if cfg.Store == nil && len(cfg.Clients) == 0 {
		return nil, errors.New("at least one client or client store is required")
	}

	seenClients := make(map[string]struct{}, len(cfg.Clients))

	for index, client := range cfg.Clients {
		if err := client.Validate(); err != nil {
			return nil, fmt.Errorf("clients[%d]: %w", index, err)
		}

		if _, exists := seenClients[client.ID]; exists {
			return nil, fmt.Errorf("clients[%d]: duplicate client id %q", index, client.ID)
		}

		seenClients[client.ID] = struct{}{}
	}

	return active, nil
}

func cloneConfig(cfg Config) Config {
	cfg.Signers = slices.Clone(cfg.Signers)

	if cfg.Clients != nil {
		clients := make([]Client, len(cfg.Clients))

		for index, client := range cfg.Clients {
			clients[index] = cloneClient(client)
		}

		cfg.Clients = clients
	}

	return cfg
}
