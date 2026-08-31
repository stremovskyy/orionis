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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis"
)

const defaultEd25519KID = "orionis-ed25519-1"

type Ed25519Builder struct {
	kid  string
	path string
}

func Ed25519() *Ed25519Builder {
	return &Ed25519Builder{kid: defaultEd25519KID}
}

func (b *Ed25519Builder) KID(kid string) *Ed25519Builder {
	if b == nil {
		return nil
	}

	if strings.TrimSpace(kid) != "" {
		b.kid = strings.TrimSpace(kid)
	}

	return b
}

func (b *Ed25519Builder) Path(path string) *Ed25519Builder {
	if b == nil {
		return nil
	}

	b.path = strings.TrimSpace(path)

	return b
}

func (b *Ed25519Builder) Build() (*Ed25519Signer, error) {
	if b == nil {
		return nil, errors.New("orionis jwk: nil ed25519 builder")
	}

	return LoadOrCreateEd25519Signer(b.path, b.kid)
}

func (b *Ed25519Builder) Must() *Ed25519Signer {
	signer, err := b.Build()
	if err != nil {
		panic(err)
	}

	return signer
}

type Ed25519Signer struct {
	Kid        string
	PrivateKey ed25519.PrivateKey
}

func GenerateEd25519Signer(kid string) (*Ed25519Signer, error) {
	kid = defaultKID(kid)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &Ed25519Signer{Kid: kid, PrivateKey: privateKey}, nil
}

func (s *Ed25519Signer) Algorithm() string { return jwt.SigningMethodEdDSA.Alg() }

func (s *Ed25519Signer) KeyID() string {
	if s == nil {
		return ""
	}

	return s.Kid
}

func (s *Ed25519Signer) PublicJWK() Key {
	if s == nil || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return Key{}
	}

	publicKey := s.PrivateKey.Public().(ed25519.PublicKey)

	return NewEd25519Key(s.Kid, publicKey)
}

func (s *Ed25519Signer) StaticProvider() (*StaticProvider, error) {
	if s == nil {
		return nil, errors.New("nil ed25519 signer")
	}

	return Static(s.PublicJWK()).Build()
}

func (s *Ed25519Signer) Sign(claims *orionis.Claims) (string, error) {
	if s == nil || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return "", errors.New("invalid ed25519 signer")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.Kid

	return token.SignedString(s.PrivateKey)
}

func LoadOrCreateEd25519Signer(path string, kid string) (*Ed25519Signer, error) {
	kid = defaultKID(kid)
	path = strings.TrimSpace(path)

	if path == "" {
		return GenerateEd25519Signer(kid)
	}

	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("decode pem %s: empty pem", path)
		}

		return ed25519SignerFromPKCS8(block.Bytes, kid, "at "+path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	signer, err := GenerateEd25519Signer(kid)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(signer.PrivateKey)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}

	return signer, nil
}

func LoadEd25519SignerPEM(raw []byte, kid string) (*Ed25519Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("decode pem: empty pem")
	}

	return ed25519SignerFromPKCS8(block.Bytes, defaultKID(kid), "")
}

func ed25519SignerFromPKCS8(der []byte, kid string, location string) (*Ed25519Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}

	privateKey, ok := key.(ed25519.PrivateKey)

	if !ok {
		if strings.TrimSpace(location) != "" {
			return nil, fmt.Errorf(
				"private key %s is %T, expected ed25519.PrivateKey",
				location,
				key,
			)
		}

		return nil, fmt.Errorf("private key is %T, expected ed25519.PrivateKey", key)
	}

	return &Ed25519Signer{Kid: strings.TrimSpace(kid), PrivateKey: privateKey}, nil
}

func defaultKID(kid string) string {
	if strings.TrimSpace(kid) == "" {
		return defaultEd25519KID
	}

	return strings.TrimSpace(kid)
}
