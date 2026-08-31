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

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

type clientStoreFunc func(context.Context, string) (server.Client, error)

func (f clientStoreFunc) FindClient(ctx context.Context, id string) (server.Client, error) {
	return f(ctx, id)
}

type mutableSigner struct {
	mu  sync.RWMutex
	kid string
	alg string
	key jwk.Key
}

func (s *mutableSigner) KeyID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.kid
}

func (s *mutableSigner) Algorithm() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.alg
}

func (s *mutableSigner) Sign(*orionis.Claims) (string, error) {
	return "signed", nil
}

func (s *mutableSigner) PublicJWK() jwk.Key {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.key
}

func (s *mutableSigner) rotate(alg string, key jwk.Key) {
	s.mu.Lock()
	s.alg = alg
	s.key = key
	s.mu.Unlock()
}

func TestMemoryClientStoreOwnsInputAndOutput(t *testing.T) {
	input := server.Client{
		ID:               "service",
		Secrets:          []string{"secret"},
		AllowedAudiences: []string{"api"},
		AllowedScopes:    []string{"items.read"},
	}
	store := server.NewMemoryClientStore(input)

	input.Secrets[0] = "changed"
	input.AllowedAudiences[0] = "changed"
	first, err := store.FindClient(context.Background(), "service")
	if err != nil {
		t.Fatal(err)
	}

	if !first.VerifySecret("secret") || !reflect.DeepEqual(first.AllowedAudiences, []string{"api"}) {
		t.Fatalf("store changed with input: %+v", first)
	}

	first.Secrets[0] = "changed-again"
	first.AllowedScopes[0] = "changed-again"
	second, err := store.FindClient(context.Background(), "service")
	if err != nil {
		t.Fatal(err)
	}

	if !second.VerifySecret("secret") || !reflect.DeepEqual(second.AllowedScopes, []string{"items.read"}) {
		t.Fatalf("store changed with returned client: %+v", second)
	}
}

func TestBuildRejectsDuplicateSignerKID(t *testing.T) {
	first, err := jwk.Ed25519().KID("duplicate").Build()
	if err != nil {
		t.Fatal(err)
	}

	second, err := jwk.Ed25519().KID("duplicate").Build()
	if err != nil {
		t.Fatal(err)
	}

	_, err = server.New().
		Issuer("https://auth.orionis.test").
		Signers(first, second).
		Client(validStaticClient()).
		Build()

	if err == nil || !strings.Contains(err.Error(), "duplicate signer kid") {
		t.Fatalf("duplicate signer error = %v", err)
	}
}

func TestServerReadsLiveSignerMetadataAndOwnsSignerSlice(t *testing.T) {
	signer := &mutableSigner{
		kid: "live-key",
		alg: "EdDSA",
		key: jwk.Key{Kty: jwk.KtyOKP, Kid: "live-key", Alg: "EdDSA", Crv: jwk.CrvEd, X: "before"},
	}
	replacement := &mutableSigner{
		kid: "replacement",
		alg: "RS256",
		key: jwk.Key{Kty: jwk.KtyRSA, Kid: "replacement", Alg: "RS256", N: "replacement", E: "AQAB"},
	}
	signers := []server.Signer{signer}
	auth, err := server.NewServer(server.Config{
		Issuer:  "https://auth.orionis.test",
		Signers: signers,
		Clients: []server.Client{validStaticClient()},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Replacing an element in the caller's slice must not change the built server.
	signers[0] = replacement
	signer.rotate(
		"ES256",
		jwk.Key{Kty: jwk.KtyEC, Kid: "live-key", Alg: "ES256", Crv: jwk.CrvP256, X: "after", Y: "after"},
	)

	jwksResponse := httptest.NewRecorder()
	auth.JWKSHTTP(jwksResponse, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	var set jwk.Set

	if err := json.Unmarshal(jwksResponse.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}

	if len(set.Keys) != 1 || set.Keys[0].Kid != "live-key" || set.Keys[0].Alg != "ES256" || set.Keys[0].X != "after" {
		t.Fatalf("JWKS did not use live original signer: %+v", set.Keys)
	}

	discoveryResponse := httptest.NewRecorder()
	auth.DiscoveryHTTP(
		discoveryResponse,
		httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil),
	)

	var discovery struct {
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}

	if err := json.Unmarshal(discoveryResponse.Body.Bytes(), &discovery); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(discovery.Algorithms, []string{"ES256"}) {
		t.Fatalf("discovery algorithms = %v, want live signer algorithm", discovery.Algorithms)
	}
}

func TestStaticClientValidation(t *testing.T) {
	validHash := strings.Repeat("00", 32)
	tests := []struct {
		name   string
		client server.Client
		want   string
	}{
		{
			name:   "missing id",
			client: server.Client{Secrets: []string{"secret"}, AllowedAudiences: []string{"api"}},
			want:   "id is required",
		},
		{
			name:   "missing credential",
			client: server.Client{ID: "service", AllowedAudiences: []string{"api"}},
			want:   "client secret",
		},
		{
			name: "invalid hash",
			client: server.Client{
				ID:               "service",
				SecretSHA256Hex:  []string{"invalid"},
				AllowedAudiences: []string{"api"},
			},
			want: "secret_sha256_hex",
		},
		{
			name:   "missing audience",
			client: server.Client{ID: "service", SecretSHA256Hex: []string{validHash}},
			want:   "allowed audience",
		},
		{
			name: "default not allowed",
			client: server.Client{
				ID:               "service",
				Secrets:          []string{"secret"},
				AllowedAudiences: []string{"api"},
				AllowedScopes:    []string{"items.read"},
				DefaultScopes:    []string{"items.write"},
			},
			want: "default_scopes",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.client.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestValidateScopePolicyRemainsScopeOnly(t *testing.T) {
	client := server.Client{
		AllowedScopes: []string{"items.read"},
		DefaultScopes: []string{"items.write"},
	}

	if err := client.ValidateScopePolicy(); err != nil {
		t.Fatalf("scope-only validation rejected a concrete default: %v", err)
	}
}

func TestTokenStoreFailuresAreServerErrors(t *testing.T) {
	backendErr := errors.New("database unavailable")
	auth := newServerWithStore(t, clientStoreFunc(func(context.Context, string) (server.Client, error) {
		return server.Client{}, backendErr
	}))

	res := issueTokenRequest(auth, "service", "secret")

	if res.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	if res.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("backend error advertised as credential failure: %q", res.Header().Get("WWW-Authenticate"))
	}

	assertOAuthError(t, res, "server_error")
}

func TestTokenCredentialMissesRemainUnauthorized(t *testing.T) {
	auth := newServerWithStore(t, clientStoreFunc(func(context.Context, string) (server.Client, error) {
		return server.Client{}, server.ErrClientNotFound
	}))

	res := issueTokenRequest(auth, "service", "secret")

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}

	if got := res.Header().Get("WWW-Authenticate"); got != `Basic realm="orionis"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	assertOAuthError(t, res, "invalid_client")
}

func TestTokenCredentialsAreNotReadFromQuery(t *testing.T) {
	auth, _ := newTestServer(t)
	form := url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"billing-api"},
		"scope":      {"billing.invoice.read"},
	}
	req := httptest.NewRequest(
		http.MethodPost,
		"/oauth/token?client_id=orders-service&client_secret=secret",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusUnauthorized {
		t.Fatalf("query credentials accepted: status = %d, body = %s", res.Code, res.Body.String())
	}
}

func validStaticClient() server.Client {
	return server.NewClient("service").
		Secret("secret").
		Audience("api").
		Scopes("items.read").
		Defaults("items.read")
}

func newServerWithStore(t *testing.T, store server.ClientStore) *server.Server {
	t.Helper()
	signer, err := jwk.Ed25519().KID("test-key").Build()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := server.New().
		Issuer("https://auth.orionis.test").
		Signer(signer).
		Store(store).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	return auth
}

func issueTokenRequest(auth *server.Server, id, secret string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"api"},
		"scope":      {"items.read"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	return res
}

func assertOAuthError(t *testing.T, res *httptest.ResponseRecorder, want string) {
	t.Helper()
	var payload map[string]string

	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}

	if payload["error"] != want {
		t.Fatalf("error = %q, want %q", payload["error"], want)
	}
}
