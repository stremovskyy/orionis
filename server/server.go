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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
)

const DefaultMaxTokenRequestBody = 1 << 20

var (
	ErrClientNotFound = errors.New("orionis server: client not found")
	ErrUnauthorized   = errors.New("orionis server: unauthorized client")
)

type Signer interface {
	KeyID() string
	Algorithm() string
	Sign(claims *orionis.Claims) (string, error)
	PublicJWK() jwk.Key
}

type Client struct {
	ID               string   `json:"id"`
	Secrets          []string `json:"secrets,omitempty"`
	SecretSHA256Hex  []string `json:"secret_sha256_hex,omitempty"`
	AllowedAudiences []string `json:"allowed_audiences"`
	AllowedScopes    []string `json:"allowed_scopes"`
	DefaultScopes    []string `json:"default_scopes,omitempty"`
	Disabled         bool     `json:"disabled,omitempty"`
}

func NewClient(id string) Client {
	return Client{ID: strings.TrimSpace(id)}
}

func (c Client) Secret(secret string) Client {
	if secret != "" {
		c.Secrets = append(c.Secrets, secret)
	}

	return c
}

func (c Client) SecretSHA256(hexValue string) Client {
	if strings.TrimSpace(hexValue) != "" {
		c.SecretSHA256Hex = append(c.SecretSHA256Hex, strings.TrimSpace(hexValue))
	}

	return c
}

func (c Client) Audience(audience string) Client {
	return c.Audiences(audience)
}

func (c Client) Audiences(audiences ...string) Client {
	c.AllowedAudiences = append(c.AllowedAudiences, normalizePlain(audiences)...)

	return c
}

func (c Client) Scope(scope string) Client {
	return c.Scopes(scope)
}

func (c Client) Scopes(scopes ...string) Client {
	c.AllowedScopes = append(c.AllowedScopes, scopes...)

	return c
}

func (c Client) Defaults(scopes ...string) Client {
	c.DefaultScopes = append(c.DefaultScopes, scopes...)

	return c
}

func (c Client) Disable() Client {
	c.Disabled = true

	return c
}

func (c Client) Normalize() Client {
	c.ID = strings.TrimSpace(c.ID)
	c.AllowedAudiences = normalizePlain(c.AllowedAudiences)
	c.AllowedScopes = orionis.NormalizeScopes(c.AllowedScopes)
	c.DefaultScopes = orionis.NormalizeScopes(c.DefaultScopes)

	return c
}

func (c Client) ValidateScopePolicy() error {
	c = c.Normalize()

	for _, scope := range c.AllowedScopes {
		if err := orionis.ValidateScopeWildcard(scope); err != nil {
			return fmt.Errorf("allowed_scopes: %w", err)
		}
	}

	for _, scope := range c.DefaultScopes {
		if containsScopeWildcard(scope) {
			return fmt.Errorf("default_scopes: wildcard scope %q is not allowed", scope)
		}
	}

	return nil
}

func (c Client) VerifySecret(secret string) bool {
	if secret == "" {
		return false
	}

	provided := sha256.Sum256([]byte(secret))

	for _, plain := range c.Secrets {
		stored := sha256.Sum256([]byte(plain))

		if subtle.ConstantTimeCompare(provided[:], stored[:]) == 1 {
			return true
		}
	}

	for _, h := range c.SecretSHA256Hex {
		decoded, err := hex.DecodeString(strings.TrimSpace(h))

		if err != nil || len(decoded) != sha256.Size {
			continue
		}

		if subtle.ConstantTimeCompare(provided[:], decoded) == 1 {
			return true
		}
	}

	return false
}

type ClientStore interface {
	FindClient(ctx context.Context, id string) (Client, error)
}

type MemoryClientStore struct {
	mu      sync.RWMutex
	clients map[string]Client
}

func MemoryStore(clients ...Client) *MemoryClientStore {
	return NewMemoryClientStore(clients...)
}

func NewMemoryClientStore(clients ...Client) *MemoryClientStore {
	store := &MemoryClientStore{clients: make(map[string]Client, len(clients))}

	for _, c := range clients {
		store.Upsert(c)
	}

	return store
}

func (s *MemoryClientStore) Upsert(c Client) {
	c = c.Normalize()

	if c.ID == "" {
		return
	}

	s.mu.Lock()
	s.clients[c.ID] = c
	s.mu.Unlock()
}

func (s *MemoryClientStore) FindClient(ctx context.Context, id string) (Client, error) {
	_ = ctx

	s.mu.RLock()
	defer s.mu.RUnlock()

	c, ok := s.clients[strings.TrimSpace(id)]

	if !ok || c.Disabled {
		return Client{}, ErrClientNotFound
	}

	return c, nil
}

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
	cfg     Config
	clients []Client
	err     error
}

func New() *Builder {
	return &Builder{
		cfg: Config{AccessTokenTTL: 15 * time.Minute, MaxTokenRequestBody: DefaultMaxTokenRequestBody, Now: time.Now},
	}
}

func FromConfig(cfg Config) *Builder {
	return New().
		Issuer(cfg.Issuer).
		Store(cfg.Store).
		Signers(cfg.Signers...).
		ActiveKID(cfg.ActiveKID).
		AccessTokenTTL(cfg.AccessTokenTTL).
		MaxBody(cfg.MaxTokenRequestBody).
		Clock(cfg.Now).
		Clients(cfg.Clients...)
}

func NewServer(cfg Config) (*Server, error) {
	return FromConfig(cfg).Build()
}

func (b *Builder) Issuer(issuer string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.Issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")

	return b
}

func (b *Builder) Store(store ClientStore) *Builder {
	if b == nil {
		return nil
	}

	if store != nil {
		b.cfg.Store = store
	}

	return b
}

func (b *Builder) Client(client Client) *Builder {
	if b == nil {
		return nil
	}

	b.clients = append(b.clients, client)

	return b
}

func (b *Builder) Clients(clients ...Client) *Builder {
	if b == nil {
		return nil
	}

	b.clients = append(b.clients, clients...)

	return b
}

func (b *Builder) Signer(signer Signer) *Builder {
	if b == nil {
		return nil
	}

	if signer != nil {
		b.cfg.Signers = append(b.cfg.Signers, signer)
	}

	return b
}

func (b *Builder) Signers(signers ...Signer) *Builder {
	if b == nil {
		return nil
	}

	for _, signer := range signers {
		b.Signer(signer)
	}

	return b
}

func (b *Builder) ActiveKID(kid string) *Builder {
	if b == nil {
		return nil
	}

	b.cfg.ActiveKID = strings.TrimSpace(kid)

	return b
}

func (b *Builder) TTL(ttl time.Duration) *Builder {
	return b.AccessTokenTTL(ttl)
}

func (b *Builder) AccessTokenTTL(ttl time.Duration) *Builder {
	if b == nil {
		return nil
	}

	if ttl > 0 {
		b.cfg.AccessTokenTTL = ttl
	}

	return b
}

func (b *Builder) MaxBody(size int64) *Builder {
	if b == nil {
		return nil
	}

	if size > 0 {
		b.cfg.MaxTokenRequestBody = size
	}

	return b
}

func (b *Builder) Clock(now func() time.Time) *Builder {
	if b == nil {
		return nil
	}

	if now != nil {
		b.cfg.Now = now
	}

	return b
}

func (b *Builder) Build() (*Server, error) {
	if b == nil {
		return nil, errors.New("orionis server: nil builder")
	}

	if b.err != nil {
		return nil, b.err
	}

	cfg := b.cfg

	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, errors.New("issuer is required")
	}

	if len(cfg.Signers) == 0 {
		return nil, errors.New("at least one signer is required")
	}

	for _, signer := range cfg.Signers {
		if signer == nil {
			return nil, errors.New("nil signer is not allowed")
		}

		if strings.TrimSpace(signer.KeyID()) == "" {
			return nil, errors.New("signer kid is required")
		}
	}

	if cfg.ActiveKID != "" && !hasSigner(cfg.Signers, cfg.ActiveKID) {
		return nil, fmt.Errorf("active signer %q was not added", cfg.ActiveKID)
	}

	if cfg.AccessTokenTTL <= 0 {
		cfg.AccessTokenTTL = 15 * time.Minute
	}

	if cfg.MaxTokenRequestBody <= 0 {
		cfg.MaxTokenRequestBody = DefaultMaxTokenRequestBody
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	if cfg.Store != nil && len(b.clients) > 0 {
		return nil, errors.New("use either Store(...) or Client(...), not both")
	}

	if cfg.Store == nil {
		if len(b.clients) == 0 {
			return nil, errors.New("at least one client or client store is required")
		}

		for i, client := range b.clients {
			if err := client.ValidateScopePolicy(); err != nil {
				return nil, fmt.Errorf("clients[%d]: %w", i, err)
			}
		}

		cfg.Store = NewMemoryClientStore(b.clients...)
	}

	return &Server{
		issuer:              strings.TrimRight(cfg.Issuer, "/"),
		store:               cfg.Store,
		signers:             cfg.Signers,
		activeKID:           cfg.ActiveKID,
		accessTokenTTL:      cfg.AccessTokenTTL,
		maxTokenRequestBody: cfg.MaxTokenRequestBody,
		now:                 cfg.Now,
	}, nil
}

func (b *Builder) Must() *Server {
	server, err := b.Build()
	if err != nil {
		panic(err)
	}

	return server
}

type Server struct {
	issuer              string
	store               ClientStore
	signers             []Signer
	activeKID           string
	accessTokenTTL      time.Duration
	maxTokenRequestBody int64

	now func() time.Time
}

func (s *Server) Issuer() string        { return s.issuer }
func (s *Server) JWKSURI() string       { return s.issuer + "/.well-known/jwks.json" }
func (s *Server) TokenEndpoint() string { return s.issuer + "/oauth/token" }

func (s *Server) TokenHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")

		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, s.maxTokenRequestBody)

	if err := r.ParseForm(); err != nil {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")

		return
	}

	if grant := r.Form.Get("grant_type"); grant != "client_credentials" {
		s.writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be client_credentials")

		return
	}

	client, err := s.authenticateClient(r.Context(), r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Basic realm="orionis"`)
		s.writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "invalid client credentials")

		return
	}

	audience := firstNonEmpty(r.Form.Get("audience"), r.Form.Get("resource"))

	if audience == "" {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_request", "audience is required")

		return
	}

	if !contains(client.AllowedAudiences, audience) {
		s.writeOAuthError(w, http.StatusForbidden, "invalid_target", "client is not allowed to request this audience")

		return
	}

	requestedScopes := orionis.NormalizeScopes([]string{r.Form.Get("scope")})

	if len(requestedScopes) == 0 {
		requestedScopes = client.DefaultScopes
	}

	if containsInvalidScopeWildcard(requestedScopes) || !isScopeSetAllowed(requestedScopes, client.AllowedScopes) {
		s.writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "client requested a scope that is not allowed")

		return
	}

	resp, err := s.issueAccessToken(client, audience, requestedScopes)
	if err != nil {
		s.writeOAuthError(w, http.StatusInternalServerError, "server_error", "cannot issue token")

		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) JWKSHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})

		return
	}

	set := jwk.Set{Keys: make([]jwk.Key, 0, len(s.signers))}

	for _, signer := range s.signers {
		set.Keys = append(set.Keys, signer.PublicJWK())
	}

	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, set)
}

func (s *Server) DiscoveryHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})

		return
	}

	writeJSON(
		w, http.StatusOK, map[string]any{
			"issuer":                                s.issuer,
			"token_endpoint":                        s.TokenEndpoint(),
			"jwks_uri":                              s.JWKSURI(),
			"grant_types_supported":                 []string{"client_credentials"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
			"response_types_supported":              []string{"token"},
			"id_token_signing_alg_values_supported": []string{s.activeSigner().Algorithm()},
		},
	)
}

func (s *Server) HealthHTTP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "orionis-auth"})
}

func (s *Server) authenticateClient(ctx context.Context, r *http.Request) (Client, error) {
	id, secret, ok := r.BasicAuth()

	if !ok {
		id = r.Form.Get("client_id")
		secret = r.Form.Get("client_secret")
	}

	id = strings.TrimSpace(id)

	if id == "" || secret == "" {
		return Client{}, ErrUnauthorized
	}

	client, err := s.store.FindClient(ctx, id)
	if err != nil {
		return Client{}, err
	}

	if !client.VerifySecret(secret) {
		return Client{}, ErrUnauthorized
	}

	return client, nil
}

func (s *Server) issueAccessToken(client Client, audience string, scopes []string) (orionis.TokenResponse, error) {
	now := s.now().UTC()
	jti, err := randomID()
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	claims := &orionis.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   client.ID,
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(s.accessTokenTTL)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		ClientID: client.ID,
		Scope:    orionis.ScopeString(scopes),
		TokenUse: orionis.TokenUseAccess,
	}

	signed, err := s.activeSigner().Sign(claims)
	if err != nil {
		return orionis.TokenResponse{}, err
	}

	return orionis.TokenResponse{
		AccessToken: signed,
		TokenType:   orionis.TokenTypeBearer,
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       claims.Scope,
	}, nil
}

func (s *Server) activeSigner() Signer {
	if s.activeKID != "" {
		for _, signer := range s.signers {
			if signer.KeyID() == s.activeKID {
				return signer
			}
		}
	}

	return s.signers[0]
}

func (s *Server) writeOAuthError(w http.ResponseWriter, status int, code string, description string) {
	writeJSON(
		w, status, map[string]string{
			"error":             code,
			"error_description": description,
		},
	)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func randomID() (string, error) {
	var b [16]byte

	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("random jti: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hasSigner(signers []Signer, kid string) bool {
	for _, signer := range signers {
		if signer != nil && signer.KeyID() == kid {
			return true
		}
	}

	return false
}

func contains(items []string, needle string) bool {
	return slices.Contains(items, strings.TrimSpace(needle))
}

func isScopeSetAllowed(requested []string, allowed []string) bool {
	for _, item := range requested {
		if !isScopeAllowed(item, allowed) {
			return false
		}
	}

	return true
}

func isScopeAllowed(requested string, allowed []string) bool {
	for _, pattern := range allowed {
		if orionis.ScopeCovers(pattern, requested) {
			return true
		}
	}

	return false
}

func containsInvalidScopeWildcard(scopes []string) bool {
	for _, scope := range scopes {
		if err := orionis.ValidateScopeWildcard(scope); err != nil {
			return true
		}
	}

	return false
}

func containsScopeWildcard(scope string) bool {
	return strings.Contains(scope, "*")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}

	return ""
}

func normalizePlain(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))

	for _, value := range values {
		for _, part := range strings.Fields(value) {
			part = strings.TrimSpace(part)

			if part == "" {
				continue
			}

			if _, ok := seen[part]; ok {
				continue
			}

			seen[part] = struct{}{}
			out = append(out, part)
		}
	}

	slices.Sort(out)

	return out
}
