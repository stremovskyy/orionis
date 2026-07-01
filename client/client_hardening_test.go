package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuilderUsesTimeoutHTTPClientByDefault(t *testing.T) {
	provider, err := New().
		TokenURL("http://127.0.0.1/oauth/token").
		As("orders-service", "secret").
		For("billing-api", "billing.invoice.create").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if provider.httpClient == http.DefaultClient {
		t.Fatalf("expected a timeout-bound default client, got http.DefaultClient")
	}

	if provider.httpClient.Timeout <= 0 {
		t.Fatalf("expected default client timeout to be positive")
	}
}

func TestBuilderPreservesCustomHTTPClient(t *testing.T) {
	custom := &http.Client{}

	provider, err := New().
		TokenURL("http://127.0.0.1/oauth/token").
		As("orders-service", "secret").
		For("billing-api", "billing.invoice.create").
		TokenHTTPClient(custom).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	if provider.httpClient != custom {
		t.Fatalf("expected custom HTTP client to be preserved")
	}
}

func TestTokenResponseRejectsOversizedBody(t *testing.T) {
	hugeToken := strings.Repeat("a", maxTokenResponseBody+1)
	auth := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(
					w,
					`{"access_token":%q,"token_type":"Bearer","expires_in":900}`,
					hugeToken,
				)
			},
		),
	)
	defer auth.Close()

	provider, err := New().
		TokenURL(auth.URL).
		As("orders-service", "secret").
		For("billing-api", "billing.invoice.create").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.TokenResponse(context.Background(), "", nil)
	if err == nil {
		t.Fatalf("expected oversized token response to be rejected")
	}

	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large error, got %v", err)
	}
}

func TestTokenResponseNonJSONErrorFallsBackToStatus(t *testing.T) {
	auth := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte("upstream unavailable"))
			},
		),
	)
	defer auth.Close()

	provider, err := New().
		TokenURL(auth.URL).
		As("orders-service", "secret").
		For("billing-api", "billing.invoice.create").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.TokenResponse(context.Background(), "", nil)
	if err == nil {
		t.Fatalf("expected non-200 token response to fail")
	}

	if !strings.Contains(err.Error(), "status=502") {
		t.Fatalf("expected status fallback error, got %v", err)
	}

	if strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("expected clean status fallback error, got %v", err)
	}
}
