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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestDecodePublicKeySupportsSigningKeyTypes(t *testing.T) {
	t.Parallel()

	edKey, edPublic := testEd25519JWK(t, "ed")
	ecKey, ecPublic := testP256JWK(t, "ec")
	rsaKey := testRSAJWK("rsa")

	tests := []struct {
		name  string
		key   Key
		check func(*testing.T, any)
	}{
		{
			name: "Ed25519",
			key:  edKey,
			check: func(t *testing.T, decoded any) {
				t.Helper()
				publicKey, ok := decoded.(ed25519.PublicKey)

				if !ok || !publicKey.Equal(edPublic) {
					t.Fatalf("decoded key = %#v, want Ed25519 key", decoded)
				}
			},
		},
		{
			name: "RSA",
			key:  rsaKey,
			check: func(t *testing.T, decoded any) {
				t.Helper()
				publicKey, ok := decoded.(*rsa.PublicKey)

				if !ok || publicKey.N.Cmp(big.NewInt(3233)) != 0 || publicKey.E != 17 {
					t.Fatalf("decoded key = %#v, want RSA n=3233 e=17", decoded)
				}
			},
		},
		{
			name: "P-256",
			key:  ecKey,
			check: func(t *testing.T, decoded any) {
				t.Helper()
				publicKey, ok := decoded.(*ecdsa.PublicKey)

				if !ok || !publicKey.Equal(ecPublic) {
					t.Fatalf("decoded key = %#v, want P-256 key", decoded)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			decoded, err := DecodePublicKey(test.key)
			if err != nil {
				t.Fatal(err)
			}

			test.check(t, decoded)
		})
	}
}

func TestDecodePublicKeyRejectsUnsafeOrMalformedMaterial(t *testing.T) {
	t.Parallel()

	validEd, _ := testEd25519JWK(t, "ed")
	validEC, _ := testP256JWK(t, "ec")
	validRSA := testRSAJWK("rsa")

	tests := []struct {
		name      string
		key       Key
		wantError string
	}{
		{name: "unsupported type", key: Key{Kty: "oct"}, wantError: "unsupported kty"},
		{
			name:      "unsupported OKP curve",
			key:       mutateKey(validEd, func(k *Key) { k.Crv = "X25519" }),
			wantError: "unsupported OKP curve",
		},
		{
			name:      "invalid Ed25519 base64",
			key:       mutateKey(validEd, func(k *Key) { k.X = "***" }),
			wantError: "decode ed25519 x",
		},
		{
			name:      "wrong Ed25519 size",
			key:       mutateKey(validEd, func(k *Key) { k.X = rawBase64([]byte{1}) }),
			wantError: "public key size",
		},
		{name: "empty RSA modulus", key: mutateKey(validRSA, func(k *Key) { k.N = "" }), wantError: "empty rsa n"},
		{
			name:      "invalid RSA modulus base64",
			key:       mutateKey(validRSA, func(k *Key) { k.N = "=" }),
			wantError: "decode rsa n",
		},
		{
			name:      "zero RSA modulus",
			key:       mutateKey(validRSA, func(k *Key) { k.N = rawBase64([]byte{0}) }),
			wantError: "invalid rsa modulus",
		},
		{name: "empty RSA exponent", key: mutateKey(validRSA, func(k *Key) { k.E = "" }), wantError: "empty rsa e"},
		{
			name:      "invalid RSA exponent base64",
			key:       mutateKey(validRSA, func(k *Key) { k.E = "=" }),
			wantError: "decode rsa e",
		},
		{
			name:      "oversized RSA exponent",
			key:       mutateKey(validRSA, func(k *Key) { k.E = rawBase64(make([]byte, 9)) }),
			wantError: "overflows uint64",
		},
		{
			name:      "overflowing RSA exponent",
			key:       mutateKey(validRSA, func(k *Key) { k.E = rawBase64([]byte{0x80, 0, 0, 0, 0, 0, 0, 1}) }),
			wantError: "overflows int",
		},
		{
			name:      "even RSA exponent",
			key:       mutateKey(validRSA, func(k *Key) { k.E = rawBase64([]byte{4}) }),
			wantError: "invalid rsa exponent",
		},
		{
			name:      "unsupported EC curve",
			key:       mutateKey(validEC, func(k *Key) { k.Crv = "P-384" }),
			wantError: "unsupported EC curve",
		},
		{name: "invalid EC x base64", key: mutateKey(validEC, func(k *Key) { k.X = "=" }), wantError: "decode ec x"},
		{name: "invalid EC y base64", key: mutateKey(validEC, func(k *Key) { k.Y = "=" }), wantError: "decode ec y"},
		{
			name:      "short EC coordinate",
			key:       mutateKey(validEC, func(k *Key) { k.X = rawBase64([]byte{1}) }),
			wantError: "coordinate size",
		},
		{name: "EC point off curve", key: mutateKey(validEC, func(k *Key) {
			k.X = rawBase64(make([]byte, 32))
			k.Y = rawBase64(make([]byte, 32))
		}), wantError: "not on curve"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodePublicKey(test.key)

			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestDecodeSetAppliesOneMetadataPolicy(t *testing.T) {
	t.Parallel()

	valid, _ := testEd25519JWK(t, "first")
	withoutMetadata := valid
	withoutMetadata.Use = ""
	withoutMetadata.Alg = ""

	tests := []struct {
		name      string
		set       Set
		wantError string
	}{
		{name: "empty", set: Set{}, wantError: errNoKeys.Error()},
		{
			name:      "blank kid",
			set:       Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Kid = "  " })}},
			wantError: "without kid",
		},
		{name: "duplicate kid", set: Set{Keys: []Key{valid, valid}}, wantError: "duplicate jwk kid"},
		{
			name:      "encryption use",
			set:       Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Use = "enc" })}},
			wantError: "unsupported use",
		},
		{
			name:      "Ed25519 declared as RS256",
			set:       Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Alg = jwt.SigningMethodRS256.Alg() })}},
			wantError: "incompatible",
		},
		{
			name:      "unknown declared algorithm",
			set:       Set{Keys: []Key{mutateKey(valid, func(k *Key) { k.Alg = "custom" })}},
			wantError: "incompatible",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := decodeSet(test.set)

			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
		})
	}

	decoded, err := decodeSet(Set{Keys: []Key{withoutMetadata}})
	if err != nil {
		t.Fatalf("empty use/alg must remain valid: %v", err)
	}

	if _, ok := decoded[withoutMetadata.Kid]; !ok {
		t.Fatalf("decoded set does not contain %q", withoutMetadata.Kid)
	}
}

func TestDecodeSetAcceptsCompatibleDeclaredAlgorithms(t *testing.T) {
	t.Parallel()

	ed, _ := testEd25519JWK(t, "ed")
	ec, _ := testP256JWK(t, "ec")
	rsaKey := testRSAJWK("rsa")
	rsaKey.Alg = jwt.SigningMethodPS256.Alg()

	decoded, err := decodeSet(Set{Keys: []Key{ed, ec, rsaKey}})
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != 3 {
		t.Fatalf("decoded key count = %d, want 3", len(decoded))
	}
}

func TestErrNoKeysSupportsErrorsIs(t *testing.T) {
	t.Parallel()

	_, err := decodeSet(Set{})

	if !errors.Is(err, errNoKeys) {
		t.Fatalf("error = %v, want errNoKeys", err)
	}
}

func testEd25519JWK(t *testing.T, kid string) (Key, ed25519.PublicKey) {
	t.Helper()

	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return NewEd25519Key(kid, publicKey), publicKey
}

func testRSAJWK(kid string) Key {
	return Key{
		Kty: KtyRSA,
		Use: UseSig,
		Kid: kid,
		Alg: jwt.SigningMethodRS256.Alg(),
		N:   rawBase64(big.NewInt(3233).Bytes()),
		E:   rawBase64([]byte{17}),
	}
}

func testP256JWK(t *testing.T, kid string) (Key, *ecdsa.PublicKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	coordinateSize := (privateKey.Curve.Params().BitSize + 7) / 8

	return Key{
		Kty: KtyEC,
		Use: UseSig,
		Kid: kid,
		Alg: jwt.SigningMethodES256.Alg(),
		Crv: CrvP256,
		X:   rawBase64(privateKey.X.FillBytes(make([]byte, coordinateSize))),
		Y:   rawBase64(privateKey.Y.FillBytes(make([]byte, coordinateSize))),
	}, &privateKey.PublicKey
}

func rawBase64(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

func mutateKey(key Key, mutate func(*Key)) Key {
	mutate(&key)

	return key
}
