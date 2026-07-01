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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

func TestClientCredentialsIssueAndVerify(t *testing.T) {
	auth, signer := newTestServer(t)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", "billing-api")
	form.Set("scope", "billing.invoice.create")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("orders-service", "secret")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}

	var tr orionis.TokenResponse

	if err := json.Unmarshal(res.Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}

	if tr.AccessToken == "" || tr.TokenType != orionis.TokenTypeBearer {
		t.Fatalf("unexpected token response: %+v", tr)
	}

	provider, err := signer.StaticProvider()
	if err != nil {
		t.Fatal(err)
	}

	verifier := orionis.NewVerifier().
		Issuer("https://auth.orionis.test").
		Audience("billing-api").
		Keys(provider)
	verified, err := verifier.Verify(context.Background(), tr.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	if verified.Claims.ClientID != "orders-service" {
		t.Fatalf("unexpected client_id: %s", verified.Claims.ClientID)
	}

	if !verified.Claims.HasScope("billing.invoice.create") {
		t.Fatalf("missing scope: %s", verified.Claims.Scope)
	}
}

func TestInvalidScopeRejected(t *testing.T) {
	auth, _ := newTestServer(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", "billing-api")
	form.Set("scope", "billing.invoice.cancel")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("orders-service", "secret")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestTokenRequestBodyLimitRejected(t *testing.T) {
	auth, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(strings.Repeat("a", server.DefaultMaxTokenRequestBody+1)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestClientSecretPostAuthentication(t *testing.T) {
	auth, _ := newTestServer(t)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", "billing-api")
	form.Set("scope", "billing.invoice.create")
	form.Set("client_id", "orders-service")
	form.Set("client_secret", "secret")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
}

func newTestServer(t *testing.T) (*server.Server, *jwk.Ed25519Signer) {
	t.Helper()
	signer, err := jwk.Ed25519().KID("test-ed25519").Build()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := server.New().
		Issuer("https://auth.orionis.test").
		Signer(signer).
		AccessTokenTTL(15 * time.Minute).
		Client(
			server.NewClient("orders-service").
				Secret("secret").
				Audience("billing-api").
				Scopes("billing.invoice.create", "billing.invoice.read").
				Defaults("billing.invoice.read"),
		).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	return auth, signer
}
