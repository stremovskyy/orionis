package orionis_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/jwk"
)

func TestVerifierRejectsMissingTokenUse(t *testing.T) {
	signer, err := jwk.Ed25519().KID("test-ed25519").Build()
	if err != nil {
		t.Fatal(err)
	}

	claims := &orionis.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.orionis.test",
			Subject:   "orders-service",
			Audience:  jwt.ClaimStrings{"billing-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientID: "orders-service",
		Scope:    "billing.invoice.create",
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := signer.StaticProvider()
	if err != nil {
		t.Fatal(err)
	}

	_, err = orionis.NewVerifier().
		Issuer("https://auth.orionis.test").
		Audience("billing-api").
		Keys(provider).
		Verify(context.Background(), token)
	if err == nil {
		t.Fatalf("expected missing token_use to be rejected")
	}

	if !strings.Contains(err.Error(), "token_use") {
		t.Fatalf("expected token_use error, got %v", err)
	}
}

func TestVerifierRejectsWrongAudience(t *testing.T) {
	signer, err := jwk.Ed25519().KID("test-ed25519").Build()
	if err != nil {
		t.Fatal(err)
	}

	claims := &orionis.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.orionis.test",
			Subject:   "orders-service",
			Audience:  jwt.ClaimStrings{"dispatch-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientID: "orders-service",
		Scope:    "billing.invoice.create",
		TokenUse: orionis.TokenUseAccess,
	}

	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	provider, err := signer.StaticProvider()
	if err != nil {
		t.Fatal(err)
	}

	_, err = orionis.NewVerifier().
		Issuer("https://auth.orionis.test").
		Audience("billing-api").
		Keys(provider).
		Verify(context.Background(), token)
	if err == nil {
		t.Fatalf("expected wrong audience to be rejected")
	}
}
