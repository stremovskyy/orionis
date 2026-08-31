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
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestStaticBuilderAndProvider(t *testing.T) {
	t.Parallel()

	first, firstPublic := testEd25519JWK(t, "first")
	second, _ := testEd25519JWK(t, "second")

	provider, err := Static().
		Key(second).
		Keys(second).
		Set(Set{Keys: []Key{first}}).
		Build()
	if err != nil {
		t.Fatal(err)
	}

	key, err := provider.Key(context.Background(), "first", jwt.SigningMethodEdDSA.Alg())
	if err != nil {
		t.Fatal(err)
	}

	publicKey, ok := key.(ed25519.PublicKey)

	if !ok || !bytes.Equal(publicKey, firstPublic) {
		t.Fatalf("provider returned a different public key")
	}

	if _, err := provider.Key(context.Background(), "first", ""); err != nil {
		t.Fatalf("an empty requested algorithm must remain compatible: %v", err)
	}

	_, err = provider.Key(context.Background(), "first", jwt.SigningMethodRS256.Alg())

	if err == nil || !strings.Contains(err.Error(), "declared for algorithm") {
		t.Fatalf("algorithm mismatch error = %v", err)
	}

	_, err = provider.Key(context.Background(), "missing", jwt.SigningMethodEdDSA.Alg())

	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing key error = %v, want ErrKeyNotFound", err)
	}
}

func TestStaticMustAndValidation(t *testing.T) {
	t.Parallel()

	key, _ := testEd25519JWK(t, "key")

	if Static(key).Must() == nil {
		t.Fatal("Must returned nil provider")
	}

	assertPanics(t, func() { Static().Must() })

	if _, err := NewStaticProvider(Set{}); err == nil || !strings.Contains(err.Error(), "no keys") {
		t.Fatalf("empty set error = %v", err)
	}
}

func TestNilStaticBuilderIsSafe(t *testing.T) {
	t.Parallel()

	var builder *StaticBuilder
	key, _ := testEd25519JWK(t, "key")

	if builder.Key(key) != nil || builder.Keys(key) != nil || builder.Set(Set{}) != nil {
		t.Fatal("nil builder mutator must return nil")
	}

	if _, err := builder.Build(); err == nil {
		t.Fatal("nil builder Build must fail")
	}

	assertPanics(t, func() { builder.Must() })
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()

	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()

	fn()
}
