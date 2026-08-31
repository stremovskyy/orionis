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

package jwk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
)

func TestEd25519SignerSignsVerifiableToken(t *testing.T) {
	t.Parallel()

	signer, err := GenerateEd25519Signer("  signing-key  ")
	if err != nil {
		t.Fatal(err)
	}

	if signer.KeyID() != "signing-key" || signer.Algorithm() != jwt.SigningMethodEdDSA.Alg() {
		t.Fatalf("signer identity = %q/%q", signer.KeyID(), signer.Algorithm())
	}

	now := time.Now()
	claims := &orionis.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://issuer.example",
			Subject:   "service",
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClientID: "service",
		TokenUse: orionis.TokenUseAccess,
	}

	rawToken, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}

	parsedClaims := new(orionis.Claims)
	token, err := jwt.ParseWithClaims(
		rawToken,
		parsedClaims,
		func(token *jwt.Token) (any, error) {
			if token.Header["kid"] != signer.KeyID() {
				t.Fatalf("token kid = %v, want %q", token.Header["kid"], signer.KeyID())
			}

			return signer.PrivateKey.Public(), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
	)

	if err != nil || !token.Valid {
		t.Fatalf("parse signed token: valid=%v err=%v", token.Valid, err)
	}

	provider, err := signer.StaticProvider()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Key(context.Background(), signer.KeyID(), signer.Algorithm()); err != nil {
		t.Fatal(err)
	}

	publicJWK := signer.PublicJWK()

	if publicJWK.Kid != signer.KeyID() || publicJWK.Alg != signer.Algorithm() {
		t.Fatalf("public JWK = %#v", publicJWK)
	}
}

func TestEd25519BuilderPersistsAndReloadsKey(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "signing.pem")
	first, err := Ed25519().KID("  persisted  ").Path("  " + path + "  ").Build()
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o, want 600", info.Mode().Perm())
	}

	second := Ed25519().KID("persisted").Path(path).Must()

	if !bytes.Equal(first.PrivateKey, second.PrivateKey) {
		t.Fatal("reloaded private key differs")
	}

	ephemeral := Ed25519().KID(" ").Path(" ").Must()

	if ephemeral.KeyID() != defaultEd25519KID {
		t.Fatalf("default kid = %q", ephemeral.KeyID())
	}
}

func TestEd25519SignerNilAndInvalidValuesAreSafe(t *testing.T) {
	t.Parallel()

	var signer *Ed25519Signer

	if signer.KeyID() != "" {
		t.Fatalf("nil signer kid = %q", signer.KeyID())
	}

	if signer.PublicJWK() != (Key{}) {
		t.Fatalf("nil signer public JWK = %#v", signer.PublicJWK())
	}

	if _, err := signer.StaticProvider(); err == nil {
		t.Fatal("nil signer StaticProvider must fail")
	}

	if _, err := signer.Sign(&orionis.Claims{}); err == nil {
		t.Fatal("nil signer Sign must fail")
	}

	invalid := &Ed25519Signer{Kid: "invalid", PrivateKey: ed25519.PrivateKey{1}}

	if invalid.PublicJWK() != (Key{}) {
		t.Fatalf("invalid signer public JWK = %#v", invalid.PublicJWK())
	}

	if _, err := invalid.Sign(&orionis.Claims{}); err == nil {
		t.Fatal("invalid signer Sign must fail")
	}

	if _, err := invalid.StaticProvider(); err == nil {
		t.Fatal("invalid signer StaticProvider must fail")
	}
}

func TestEd25519BuilderNilSafety(t *testing.T) {
	t.Parallel()

	var builder *Ed25519Builder

	if builder.KID("kid") != nil || builder.Path("path") != nil {
		t.Fatal("nil builder mutator must return nil")
	}

	if _, err := builder.Build(); err == nil {
		t.Fatal("nil builder Build must fail")
	}

	assertPanics(t, func() { builder.Must() })
}

func TestLoadOrCreateEd25519SignerRejectsBadExistingFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	badPEMPath := filepath.Join(directory, "bad.pem")

	if err := os.WriteFile(badPEMPath, []byte("not pem"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateEd25519Signer(badPEMPath, "kid"); err == nil ||
		!strings.Contains(err.Error(), "empty pem") {
		t.Fatalf("invalid PEM error = %v", err)
	}

	badDERPath := filepath.Join(directory, "bad-der.pem")
	badDER := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad der")})

	if err := os.WriteFile(badDERPath, badDER, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateEd25519Signer(badDERPath, "kid"); err == nil ||
		!strings.Contains(err.Error(), "parse pkcs8") {
		t.Fatalf("invalid DER error = %v", err)
	}

	rsaPath := filepath.Join(directory, "rsa.pem")

	if err := os.WriteFile(rsaPath, testRSAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrCreateEd25519Signer(rsaPath, "kid"); err == nil ||
		!strings.Contains(err.Error(), "at "+rsaPath) {
		t.Fatalf("wrong key type error = %v", err)
	}

	if _, err := LoadOrCreateEd25519Signer(directory, "kid"); err == nil {
		t.Fatal("reading a directory as a private key must fail")
	}
}

func TestLoadEd25519SignerPEMDefaultsKID(t *testing.T) {
	t.Parallel()

	signer, err := LoadEd25519SignerPEM(testEd25519PEM(t), " ")
	if err != nil {
		t.Fatal(err)
	}

	if signer.KeyID() != defaultEd25519KID {
		t.Fatalf("kid = %q, want default", signer.KeyID())
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pemBlockBytes(t, testEd25519PEM(t)))

	if err != nil || privateKey == nil {
		t.Fatalf("test PEM is invalid: key=%T err=%v", privateKey, err)
	}
}

func pemBlockBytes(t *testing.T, raw []byte) []byte {
	t.Helper()

	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("missing PEM block")
	}

	return block.Bytes
}
