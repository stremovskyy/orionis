package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stremovskyy/orionis/client"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

func TestProviderCachesToken(t *testing.T) {
	signer, err := jwk.Ed25519().KID("test-ed25519").Build()
	if err != nil {
		t.Fatal(err)
	}

	auth, err := server.New().
		Issuer("https://auth.orionis.test").
		Signer(signer).
		AccessTokenTTL(time.Minute).
		Client(
			server.NewClient("orders-service").
				Secret("secret").
				Audience("billing-api").
				Scope("billing.invoice.create"),
		).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	var hits int
	hs := httptest.NewServer(
		http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				hits++
				auth.TokenHTTP(w, r)
			},
		),
	)
	defer hs.Close()

	provider, err := client.New().
		TokenURL(hs.URL).
		As("orders-service", "secret").
		For("billing-api", "billing.invoice.create").
		Build()
	if err != nil {
		t.Fatal(err)
	}

	first, err := provider.Token(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}

	second, err := provider.Token(context.Background(), "", nil)
	if err != nil {
		t.Fatal(err)
	}

	if first == "" || first != second {
		t.Fatalf("provider did not cache token")
	}

	if hits != 1 {
		t.Fatalf("expected 1 token endpoint hit, got %d", hits)
	}
}
