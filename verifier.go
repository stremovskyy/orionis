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
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stremovskyy/orionis/internal/stringset"
)

type KeyProvider interface {
	Key(ctx context.Context, kid string, alg string) (any, error)
}

// Verifier validates service access tokens. It is intentionally independent of
// Gin and server packages, so it can be embedded into any Go HTTP stack.
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
	return NewVerifier().Issuer(issuer).Audience(audience).KeyProvider(provider)
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

// Keys sets the verifier's public key provider.
//
// Deprecated: use KeyProvider.
func (v *Verifier) Keys(provider KeyProvider) *Verifier {
	return v.KeyProvider(provider)
}

func (v *Verifier) KeyProvider(provider KeyProvider) *Verifier {
	if v == nil {
		return nil
	}

	v.provider = provider

	return v
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

	v.validAlgs = stringset.Normalize(algs)

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
	return v.TokenUse("")
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

	token, err := jwt.NewParser(options...).ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)

			if strings.TrimSpace(kid) == "" {
				return nil, fmt.Errorf("%w: missing kid", ErrInvalidToken)
			}

			return v.provider.Key(ctx, kid, token.Method.Alg())
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}

	if token == nil || !token.Valid {
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
