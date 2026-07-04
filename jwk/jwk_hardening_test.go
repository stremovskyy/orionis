package jwk

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRemoteProviderUsesTimeoutHTTPClientByDefault(t *testing.T) {
	provider, err := Remote("http://127.0.0.1/.well-known/jwks.json").Build()
	if err != nil {
		t.Fatal(err)
	}

	if provider.httpClient == http.DefaultClient {
		t.Fatalf("expected a timeout-bound default client, got http.DefaultClient")
	}

	if provider.httpClient.Timeout <= 0 {
		t.Fatalf("expected default remote JWKS client timeout to be positive")
	}
}

func TestRemoteProviderPreservesCustomHTTPClient(t *testing.T) {
	custom := &http.Client{}

	provider, err := Remote("http://127.0.0.1/.well-known/jwks.json").
		HTTPClient(custom).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if provider.httpClient != custom {
		t.Fatalf("expected custom HTTP client to be preserved")
	}
}

func TestRemoteProviderRejectsOversizedJWKSBody(t *testing.T) {
	jwks := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[]}`))
				_, _ = w.Write([]byte(strings.Repeat(" ", maxJWKSResponseBody+1)))
			},
		),
	)
	defer jwks.Close()

	provider, err := Remote(jwks.URL).Build()
	if err != nil {
		t.Fatal(err)
	}

	err = provider.Refresh(context.Background())
	if err == nil {
		t.Fatalf("expected oversized JWKS response to be rejected")
	}

	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large error, got %v", err)
	}
}

func TestLoadEd25519SignerPEMParsesPKCS8PrivateKey(t *testing.T) {
	signer, err := LoadEd25519SignerPEM(testEd25519PEM(t), "secret-kid")
	if err != nil {
		t.Fatal(err)
	}

	if signer.KeyID() != "secret-kid" {
		t.Fatalf("unexpected kid: %q", signer.KeyID())
	}

	if signer.PublicJWK().Kid != "secret-kid" {
		t.Fatalf("unexpected public jwk kid: %q", signer.PublicJWK().Kid)
	}
}

func TestLoadEd25519SignerPEMRejectsEmptyInput(t *testing.T) {
	_, err := LoadEd25519SignerPEM(nil, "secret-kid")
	if err == nil {
		t.Fatalf("expected empty pem to be rejected")
	}

	if !strings.Contains(err.Error(), "empty pem") {
		t.Fatalf("expected empty pem error, got %v", err)
	}
}

func TestLoadEd25519SignerPEMRejectsInvalidPEM(t *testing.T) {
	_, err := LoadEd25519SignerPEM([]byte("not pem"), "secret-kid")
	if err == nil {
		t.Fatalf("expected invalid pem to be rejected")
	}

	if !strings.Contains(err.Error(), "decode pem") {
		t.Fatalf("expected decode pem error, got %v", err)
	}
}

func TestLoadEd25519SignerPEMRejectsNonEd25519PrivateKey(t *testing.T) {
	_, err := LoadEd25519SignerPEM(testRSAPEM(t), "secret-kid")
	if err == nil {
		t.Fatalf("expected non-ed25519 private key to be rejected")
	}

	if !strings.Contains(err.Error(), "expected ed25519.PrivateKey") {
		t.Fatalf("expected ed25519 type error, got %v", err)
	}
}

func testEd25519PEM(t *testing.T) []byte {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func testRSAPEM(t *testing.T) []byte {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
