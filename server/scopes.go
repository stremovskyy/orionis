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

package server

import (
	"slices"
	"strings"

	"github.com/stremovskyy/orionis"
)

func contains(items []string, needle string) bool {
	return slices.Contains(items, strings.TrimSpace(needle))
}

func isScopeAllowed(requested string, allowed []string) bool {
	for _, pattern := range allowed {
		if orionis.ScopeCovers(pattern, requested) {
			return true
		}
	}

	return false
}

func resolveRequestedScopes(requested, allowed []string) ([]string, bool) {
	if containsInvalidScopeWildcard(requested) {
		return nil, false
	}

	issued := make([]string, 0, len(requested))

	for _, scope := range requested {
		if containsScopeWildcard(scope) {
			expanded := expandWildcardScopeRequest(scope, allowed)

			if len(expanded) == 0 {
				return nil, false
			}

			issued = append(issued, expanded...)

			continue
		}

		if !isScopeAllowed(scope, allowed) {
			return nil, false
		}

		issued = append(issued, scope)
	}

	return orionis.NormalizeScopes(issued), true
}

func expandWildcardScopeRequest(requested string, allowed []string) []string {
	expanded := make([]string, 0, len(allowed))

	for _, scope := range allowed {
		if !containsScopeWildcard(scope) && orionis.ScopeCovers(requested, scope) {
			expanded = append(expanded, scope)
		}
	}

	return orionis.NormalizeScopes(expanded)
}

func containsInvalidScopeWildcard(scopes []string) bool {
	for _, scope := range scopes {
		if err := orionis.ValidateScopeWildcard(scope); err != nil {
			return true
		}
	}

	return false
}

func containsScopeWildcard(scope string) bool {
	return strings.Contains(scope, "*")
}
