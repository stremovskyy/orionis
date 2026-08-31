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
	token, verifier := signedTestToken(t, "billing.invoice.create")

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

func TestGuardAllowsRecursiveWildcardScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	token, verifier := signedTestToken(t, "target.webhooks.**")

	guard, err := ginorion.New().Verifier(verifier).Build()
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET(
		"/protected", guard.Require("target.webhooks.admin.delete"), func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)

	if res.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", res.Code, res.Body.String())
	}
}

func TestGuardRejectsSingleSegmentWildcardForDeepScope(t *testing.T) {
	gin.SetMode(gin.TestMode)
	token, verifier := signedTestToken(t, "target.webhooks.*")

	guard, err := ginorion.New().Verifier(verifier).Build()
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()
	r.GET(
		"/protected", guard.Require("target.webhooks.admin.delete"), func(c *gin.Context) {
			c.Status(http.StatusNoContent)
		},
	)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", res.Code, res.Body.String())
	}
}

func signedTestToken(t *testing.T, scope string) (string, *orionis.Verifier) {
	t.Helper()
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
		Scope:    scope,
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

	verifier := orionis.NewVerifier().Issuer("https://auth.orionis.test").Audience("billing-api").KeyProvider(provider)

	return token, verifier
}

var _ server.Signer = (*jwk.Ed25519Signer)(nil)
