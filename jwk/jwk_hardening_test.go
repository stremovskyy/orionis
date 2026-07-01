package jwk

import (
	"context"
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
