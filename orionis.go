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
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenTypeBearer = "Bearer"
	TokenUseAccess  = "access"
)

var (
	ErrMissingToken      = errors.New("orionis: missing bearer token")
	ErrInvalidToken      = errors.New("orionis: invalid token")
	ErrInsufficientScope = errors.New("orionis: insufficient scope")
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

	return slices.Contains(c.Scopes(), scope)
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
		if slices.Contains(owned, scope) {
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
		if !slices.Contains(owned, scope) {
			return false
		}
	}

	return true
}

func NormalizeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))

	for _, scope := range scopes {
		for _, part := range strings.Fields(scope) {
			part = strings.TrimSpace(part)

			if part == "" {
				continue
			}

			if _, ok := seen[part]; ok {
				continue
			}

			seen[part] = struct{}{}
			out = append(out, part)
		}
	}

	slices.Sort(out)

	return out
}

func ScopeString(scopes []string) string {
	return strings.Join(NormalizeScopes(scopes), " ")
}

func BearerToken(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", ErrMissingToken
	}

	parts := strings.Fields(header)

	if len(parts) != 2 || !strings.EqualFold(parts[0], TokenTypeBearer) || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("%w: authorization header must be Bearer token", ErrInvalidToken)
	}

	return parts[1], nil
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type VerifiedToken struct {
	Raw    string
	Claims *Claims
}

type KeyProvider interface {
	Key(ctx context.Context, kid string, alg string) (any, error)
}

// Verifier validates service access tokens. It is intentionally independent of
// GIN and server packages, so it can be embedded into any Go HTTP stack.
type Verifier struct {
	issuer     string
	audience   string
	provider   KeyProvider
	leeway     time.Duration
	validAlgs  []string
	requireUse string
}

func NewVerifier() *Verifier {
	return &Verifier{
		leeway:     30 * time.Second,
		validAlgs:  DefaultAlgorithms(),
		requireUse: TokenUseAccess,
	}
}

func VerifierFor(issuer, audience string, provider KeyProvider) *Verifier {
	return NewVerifier().Issuer(issuer).Audience(audience).Keys(provider)
}

func DefaultAlgorithms() []string {
	return []string{
		jwt.SigningMethodEdDSA.Alg(),
		jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodES256.Alg(),
	}
}

func (v *Verifier) Issuer(issuer string) *Verifier {
	if v == nil {
		return nil
	}

	v.issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")

	return v
}

func (v *Verifier) Audience(audience string) *Verifier {
	if v == nil {
		return nil
	}

	v.audience = strings.TrimSpace(audience)

	return v
}

func (v *Verifier) Keys(provider KeyProvider) *Verifier {
	if v == nil {
		return nil
	}

	v.provider = provider

	return v
}

func (v *Verifier) KeyProvider(provider KeyProvider) *Verifier {
	return v.Keys(provider)
}

func (v *Verifier) Leeway(leeway time.Duration) *Verifier {
	if v == nil {
		return nil
	}

	v.leeway = leeway

	return v
}

func (v *Verifier) Algorithms(algs ...string) *Verifier {
	if v == nil {
		return nil
	}

	v.validAlgs = normalizeStrings(algs)

	return v
}

func (v *Verifier) TokenUse(tokenUse string) *Verifier {
	if v == nil {
		return nil
	}

	v.requireUse = strings.TrimSpace(tokenUse)

	return v
}

func (v *Verifier) WithoutTokenUseCheck() *Verifier {
	if v == nil {
		return nil
	}

	v.requireUse = ""

	return v
}

func (v *Verifier) Verify(ctx context.Context, tokenString string) (*VerifiedToken, error) {
	if strings.TrimSpace(tokenString) == "" {
		return nil, ErrMissingToken
	}

	if v == nil {
		return nil, fmt.Errorf("%w: nil verifier", ErrInvalidToken)
	}

	if v.provider == nil {
		return nil, fmt.Errorf("%w: nil key provider", ErrInvalidToken)
	}

	claims := new(Claims)
	validAlgs := v.validAlgs

	if len(validAlgs) == 0 {
		validAlgs = DefaultAlgorithms()
	}

	options := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithValidMethods(validAlgs),
	}

	if v.issuer != "" {
		options = append(options, jwt.WithIssuer(v.issuer))
	}

	if v.audience != "" {
		options = append(options, jwt.WithAudience(v.audience))
	}

	if v.leeway > 0 {
		options = append(options, jwt.WithLeeway(v.leeway))
	}

	parser := jwt.NewParser(options...)
	tok, err := parser.ParseWithClaims(
		tokenString, claims, func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)

			if strings.TrimSpace(kid) == "" {
				return nil, fmt.Errorf("%w: missing kid", ErrInvalidToken)
			}

			return v.provider.Key(ctx, kid, token.Method.Alg())
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if tok == nil || !tok.Valid {
		return nil, ErrInvalidToken
	}

	if v.requireUse != "" && claims.TokenUse != v.requireUse {
		return nil, fmt.Errorf("%w: unexpected token_use %q", ErrInvalidToken, claims.TokenUse)
	}

	if claims.Subject == "" || claims.ClientID == "" {
		return nil, fmt.Errorf("%w: missing service identity", ErrInvalidToken)
	}

	return &VerifiedToken{Raw: tokenString, Claims: claims}, nil
}

func normalizeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))

	for _, value := range values {
		for _, item := range strings.Fields(value) {
			item = strings.TrimSpace(item)

			if item == "" {
				continue
			}

			if _, ok := seen[item]; ok {
				continue
			}

			seen[item] = struct{}{}
			out = append(out, item)
		}
	}

	return out
}
