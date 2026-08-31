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

package orionis_test

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/stremovskyy/orionis"
)

func TestScopeNormalizationContract(t *testing.T) {
	got := orionis.NormalizeScopes([]string{" write read ", "read", "admin"})
	want := []string{"admin", "read", "write"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeScopes() = %v, want %v", got, want)
	}

	if got := orionis.ScopeString([]string{"write read", "read"}); got != "read write" {
		t.Fatalf("ScopeString() = %q", got)
	}

	if got := orionis.NormalizeScopes(nil); got != nil {
		t.Fatalf("NormalizeScopes(nil) = %#v, want nil", got)
	}

	empty := orionis.NormalizeScopes([]string{" ", "\t"})

	if empty == nil || len(empty) != 0 {
		t.Fatalf("NormalizeScopes(blank values) = %#v, want non-nil empty slice", empty)
	}

	encoded, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}

	if string(encoded) != "[]" {
		t.Fatalf("json.Marshal(NormalizeScopes(blank values)) = %s, want []", encoded)
	}
}

func TestScopeWildcardContract(t *testing.T) {
	tests := []struct {
		name     string
		owned    string
		required string
		want     bool
	}{
		{name: "exact", owned: "orders.read", required: "orders.read", want: true},
		{name: "one segment", owned: "orders.*", required: "orders.read", want: true},
		{name: "one segment too deep", owned: "orders.*", required: "orders.admin.read"},
		{name: "recursive", owned: "orders.**", required: "orders.admin.read", want: true},
		{name: "different prefix", owned: "orders.**", required: "billing.read"},
		{name: "empty", owned: "", required: "orders.read"},
		{name: "invalid owned", owned: "orders.*.read", required: "orders.admin.read"},
		{name: "invalid required", owned: "orders.**", required: "orders.*.read"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := orionis.ScopeCovers(test.owned, test.required); got != test.want {
				t.Fatalf("ScopeCovers(%q, %q) = %v", test.owned, test.required, got)
			}
		})
	}

	if err := orionis.ValidateScopeWildcard("orders.**"); err != nil {
		t.Fatalf("valid wildcard rejected: %v", err)
	}

	if err := orionis.ValidateScopeWildcard("orders.*.read"); err == nil {
		t.Fatal("invalid wildcard accepted")
	}
}

func TestClaimsScopeContractForNilAndEmptyRequirements(t *testing.T) {
	var claims *orionis.Claims

	if claims.HasScope("orders.read") {
		t.Fatal("nil claims unexpectedly have a scope")
	}

	if !claims.HasAnyScope() || !claims.HasAllScopes() {
		t.Fatal("empty requirements must be satisfied")
	}

	if claims.HasAnyScope("orders.read") || claims.HasAllScopes("orders.read") {
		t.Fatal("nil claims must not satisfy non-empty requirements")
	}

	claims = &orionis.Claims{Scope: "orders.read billing.**"}

	if !claims.HasAnyScope("missing", "orders.read") {
		t.Fatal("HasAnyScope did not match exact scope")
	}

	if claims.HasAllScopes("orders.read", "missing") {
		t.Fatal("HasAllScopes matched a missing scope")
	}
}

func TestBearerTokenErrorsRemainClassifiable(t *testing.T) {
	if _, err := orionis.BearerToken("  "); !errors.Is(err, orionis.ErrMissingToken) {
		t.Fatalf("empty header error = %v", err)
	}

	if _, err := orionis.BearerToken("Basic abc"); !errors.Is(err, orionis.ErrInvalidToken) {
		t.Fatalf("invalid scheme error = %v", err)
	}

	if token, err := orionis.BearerToken("bearer abc"); err != nil || token != "abc" {
		t.Fatalf("BearerToken() = %q, %v", token, err)
	}
}

func TestVerifierConfigurationErrorsRemainClassifiable(t *testing.T) {
	if _, err := (*orionis.Verifier)(nil).Verify(context.Background(), "token"); !errors.Is(
		err,
		orionis.ErrInvalidToken,
	) {
		t.Fatalf("nil verifier error = %v", err)
	}

	if _, err := orionis.NewVerifier().Verify(context.Background(), "token"); !errors.Is(err, orionis.ErrInvalidToken) {
		t.Fatalf("missing provider error = %v", err)
	}

	if _, err := orionis.NewVerifier().Verify(context.Background(), ""); !errors.Is(err, orionis.ErrMissingToken) {
		t.Fatalf("missing token error = %v", err)
	}
}
