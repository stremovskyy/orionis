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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

var errNoKeys = errors.New("jwks has no keys")

func DecodePublicKey(k Key) (any, error) {
	switch k.Kty {
	case KtyOKP:
		return decodeEd25519PublicKey(k)
	case KtyRSA:
		return decodeRSAPublicKey(k)
	case KtyEC:
		return decodeECDSAPublicKey(k)
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

func decodeSet(set Set) (map[string]decodedKey, error) {
	if len(set.Keys) == 0 {
		return nil, errNoKeys
	}

	keys := make(map[string]decodedKey, len(set.Keys))

	for _, item := range set.Keys {
		if strings.TrimSpace(item.Kid) == "" {
			return nil, errors.New("jwk without kid")
		}

		if _, exists := keys[item.Kid]; exists {
			return nil, fmt.Errorf("duplicate jwk kid %q", item.Kid)
		}

		if item.Use != "" && item.Use != UseSig {
			return nil, fmt.Errorf("jwk %q has unsupported use %q", item.Kid, item.Use)
		}

		if err := validateDeclaredAlgorithm(item); err != nil {
			return nil, fmt.Errorf("jwk %q: %w", item.Kid, err)
		}

		publicKey, err := DecodePublicKey(item)
		if err != nil {
			return nil, fmt.Errorf("decode key %q: %w", item.Kid, err)
		}

		keys[item.Kid] = decodedKey{publicKey: publicKey, declaredAlg: item.Alg}
	}

	return keys, nil
}

func decodeEd25519PublicKey(k Key) (ed25519.PublicKey, error) {
	if k.Crv != CrvEd {
		return nil, fmt.Errorf("unsupported OKP curve %q", k.Crv)
	}

	raw, err := decodeBase64URL("ed25519 x", k.X)
	if err != nil {
		return nil, err
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key size: %d", len(raw))
	}

	return ed25519.PublicKey(raw), nil
}

func decodeRSAPublicKey(k Key) (*rsa.PublicKey, error) {
	nBytes, err := decodeBase64URL("rsa n", k.N)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)

	if n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("invalid rsa modulus")
	}

	eBytes, err := decodeBase64URL("rsa e", k.E)
	if err != nil {
		return nil, err
	}

	if len(eBytes) > 8 {
		return nil, errors.New("rsa exponent overflows uint64")
	}

	var exponent uint64

	for _, value := range eBytes {
		exponent = exponent<<8 | uint64(value)
	}

	maxInt := uint64(^uint(0) >> 1)

	if exponent > maxInt {
		return nil, errors.New("rsa exponent overflows int")
	}

	if exponent < 3 || exponent%2 == 0 {
		return nil, errors.New("invalid rsa exponent")
	}

	return &rsa.PublicKey{N: n, E: int(exponent)}, nil
}

func decodeECDSAPublicKey(k Key) (*ecdsa.PublicKey, error) {
	if k.Crv != CrvP256 {
		return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
	}

	xBytes, err := decodeBase64URL("ec x", k.X)
	if err != nil {
		return nil, err
	}

	yBytes, err := decodeBase64URL("ec y", k.Y)
	if err != nil {
		return nil, err
	}

	coordinateSize := (elliptic.P256().Params().BitSize + 7) / 8

	if len(xBytes) != coordinateSize || len(yBytes) != coordinateSize {
		return nil, fmt.Errorf(
			"invalid P-256 coordinate size: x=%d y=%d",
			len(xBytes),
			len(yBytes),
		)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()

	encoded := make([]byte, 1+2*coordinateSize)
	encoded[0] = 4
	copy(encoded[1:1+coordinateSize], xBytes)
	copy(encoded[1+coordinateSize:], yBytes)

	if _, err := ecdh.P256().NewPublicKey(encoded); err != nil {
		return nil, errors.New("ec key is not on curve")
	}

	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func decodeBase64URL(name string, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("empty %s", name)
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}

	if len(raw) == 0 {
		return nil, fmt.Errorf("empty %s", name)
	}

	return raw, nil
}

func validateDeclaredAlgorithm(k Key) error {
	if k.Alg == "" {
		return nil
	}

	compatible := false

	switch k.Kty {
	case KtyOKP:
		compatible = k.Crv == CrvEd && k.Alg == jwt.SigningMethodEdDSA.Alg()
	case KtyRSA:
		compatible = isRSAAlgorithm(k.Alg)
	case KtyEC:
		compatible = k.Crv == CrvP256 && k.Alg == jwt.SigningMethodES256.Alg()
	}

	if !compatible {
		return fmt.Errorf("algorithm %q is incompatible with %s key", k.Alg, k.Kty)
	}

	return nil
}

func isRSAAlgorithm(alg string) bool {
	switch alg {
	case jwt.SigningMethodRS256.Alg(),
		jwt.SigningMethodRS384.Alg(),
		jwt.SigningMethodRS512.Alg(),
		jwt.SigningMethodPS256.Alg(),
		jwt.SigningMethodPS384.Alg(),
		jwt.SigningMethodPS512.Alg():
		return true
	default:
		return false
	}
}
