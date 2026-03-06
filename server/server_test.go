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
