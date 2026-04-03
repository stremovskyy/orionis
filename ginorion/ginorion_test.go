package ginorion_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/ginorion"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

func TestGuardAllowsValidScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
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

	verifier := orionis.NewVerifier().Issuer("https://auth.orionis.test").Audience("billing-api").Keys(provider)

	if _, err := verifier.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	guard, err := ginorion.New().Verifier(verifier).Build()
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET(
		"/protected", guard.Require("billing.invoice.create"), func(c *gin.Context) {
			claims := ginorion.MustClaims(c)
			c.JSON(http.StatusOK, gin.H{"client_id": claims.ClientID})
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
}

var _ server.Signer = (*jwk.Ed25519Signer)(nil)
