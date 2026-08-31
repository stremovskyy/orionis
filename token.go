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
	"errors"
	"fmt"
	"strings"
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
