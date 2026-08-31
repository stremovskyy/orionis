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
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims is the service-to-service JWT shape used by Orionis.
//
// RegisteredClaims carries standard JWT claims such as iss, sub, aud, exp, iat,
// nbf, and jti. ClientID, Scope, and TokenUse are the compact OAuth-oriented
// fields Orionis adds for service identity and authorization decisions.
type Claims struct {
	jwt.RegisteredClaims

	ClientID string `json:"client_id,omitempty"`
	Scope    string `json:"scope,omitempty"`
	TokenUse string `json:"token_use,omitempty"`
}

func (c *Claims) Scopes() []string {
	if c == nil || strings.TrimSpace(c.Scope) == "" {
		return nil
	}

	return strings.Fields(c.Scope)
}

func (c *Claims) HasScope(scope string) bool {
	if c == nil {
		return false
	}

	return scopeSetCovers(c.Scopes(), scope)
}

func (c *Claims) HasAnyScope(required ...string) bool {
	required = NormalizeScopes(required)

	if len(required) == 0 {
		return true
	}

	if c == nil {
		return false
	}

	owned := c.Scopes()

	for _, scope := range required {
		if scopeSetCovers(owned, scope) {
			return true
		}
	}

	return false
}

func (c *Claims) HasAllScopes(required ...string) bool {
	required = NormalizeScopes(required)

	if len(required) == 0 {
		return true
	}

	if c == nil {
		return false
	}

	owned := c.Scopes()

	for _, scope := range required {
		if !scopeSetCovers(owned, scope) {
			return false
		}
	}

	return true
}
