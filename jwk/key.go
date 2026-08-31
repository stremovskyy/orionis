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
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	KtyOKP  = "OKP"
	KtyRSA  = "RSA"
	KtyEC   = "EC"
	UseSig  = "sig"
	CrvEd   = "Ed25519"
	CrvP256 = "P-256"
)

var ErrKeyNotFound = errors.New("orionis jwk: key not found")

type Key struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type Set struct {
	Keys []Key `json:"keys"`
}

type decodedKey struct {
	publicKey   any
	declaredAlg string
}

func NewEd25519Key(kid string, pub ed25519.PublicKey) Key {
	return Key{
		Kty: KtyOKP,
		Use: UseSig,
		Kid: strings.TrimSpace(kid),
		Alg: jwt.SigningMethodEdDSA.Alg(),
		Crv: CrvEd,
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

func (k decodedKey) forAlgorithm(kid string, alg string) (any, error) {
	if k.declaredAlg != "" && alg != "" && k.declaredAlg != alg {
		return nil, fmt.Errorf(
			"jwk %q is declared for algorithm %q, not %q",
			kid,
			k.declaredAlg,
			alg,
		)
	}

	return k.publicKey, nil
}
