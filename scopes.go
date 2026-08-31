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

package orionis

import (
	"fmt"
	"strings"

	"github.com/stremovskyy/orionis/internal/stringset"
)

func NormalizeScopes(scopes []string) []string {
	return stringset.Normalize(scopes)
}

func ScopeString(scopes []string) string {
	return strings.Join(NormalizeScopes(scopes), " ")
}

func ScopeCovers(owned string, required string) bool {
	owned = strings.TrimSpace(owned)
	required = strings.TrimSpace(required)

	if owned == "" || required == "" {
		return false
	}

	if owned == required {
		return true
	}

	if containsScopeWildcard(required) {
		if _, _, ok := wildcardScopeParts(required); !ok {
			return false
		}
	}

	prefix, recursive, ok := wildcardScopeParts(owned)

	if !ok {
		return false
	}

	requiredPrefix := prefix + "."

	if !strings.HasPrefix(required, requiredPrefix) {
		return false
	}

	suffix := strings.TrimPrefix(required, requiredPrefix)

	if suffix == "" {
		return false
	}

	if recursive {
		return true
	}

	return !strings.Contains(suffix, ".") && !containsScopeWildcard(suffix)
}

func ValidateScopeWildcard(scope string) error {
	if !containsScopeWildcard(scope) {
		return nil
	}

	if _, _, ok := wildcardScopeParts(scope); ok {
		return nil
	}

	return fmt.Errorf(
		"invalid wildcard scope %q; only suffix patterns like \"prefix.*\" or \"prefix.**\" are allowed",
		scope,
	)
}

func scopeSetCovers(owned []string, required string) bool {
	for _, scope := range owned {
		if ScopeCovers(scope, required) {
			return true
		}
	}

	return false
}

func wildcardScopeParts(scope string) (prefix string, recursive bool, ok bool) {
	switch {
	case strings.Count(scope, "*") == 1 && strings.HasSuffix(scope, ".*"):
		prefix = strings.TrimSuffix(scope, ".*")

	case strings.Count(scope, "*") == 2 && strings.HasSuffix(scope, ".**"):
		prefix = strings.TrimSuffix(scope, ".**")
		recursive = true

	default:
		return "", false, false
	}

	if strings.TrimSpace(prefix) == "" {
		return "", false, false
	}

	return prefix, recursive, true
}

func containsScopeWildcard(scope string) bool {
	return strings.Contains(scope, "*")
}
