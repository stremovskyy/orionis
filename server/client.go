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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/internal/stringset"
)

type Client struct {
	ID               string   `json:"id"`
	Secrets          []string `json:"secrets,omitempty"`
	SecretSHA256Hex  []string `json:"secret_sha256_hex,omitempty"`
	AllowedAudiences []string `json:"allowed_audiences"`
	AllowedScopes    []string `json:"allowed_scopes"`
	DefaultScopes    []string `json:"default_scopes,omitempty"`
	Disabled         bool     `json:"disabled,omitempty"`
}

func NewClient(id string) Client {
	return Client{ID: strings.TrimSpace(id)}
}

func (c Client) Secret(secret string) Client {
	c = cloneClient(c)

	if secret != "" {
		c.Secrets = append(c.Secrets, secret)
	}

	return c
}

func (c Client) SecretSHA256(hexValue string) Client {
	c = cloneClient(c)

	if value := strings.TrimSpace(hexValue); value != "" {
		c.SecretSHA256Hex = append(c.SecretSHA256Hex, value)
	}

	return c
}

func (c Client) Audience(audience string) Client {
	return c.Audiences(audience)
}

func (c Client) Audiences(audiences ...string) Client {
	c = cloneClient(c)
	c.AllowedAudiences = append(c.AllowedAudiences, stringset.Normalize(audiences)...)

	return c
}

func (c Client) Scope(scope string) Client {
	return c.Scopes(scope)
}

func (c Client) Scopes(scopes ...string) Client {
	c = cloneClient(c)
	c.AllowedScopes = append(c.AllowedScopes, scopes...)

	return c
}

func (c Client) Defaults(scopes ...string) Client {
	c = cloneClient(c)
	c.DefaultScopes = append(c.DefaultScopes, scopes...)

	return c
}

func (c Client) Disable() Client {
	c = cloneClient(c)
	c.Disabled = true

	return c
}

func (c Client) Normalize() Client {
	c = cloneClient(c)
	c.ID = strings.TrimSpace(c.ID)
	c.SecretSHA256Hex = normalizeHashes(c.SecretSHA256Hex)
	c.AllowedAudiences = stringset.Normalize(c.AllowedAudiences)
	c.AllowedScopes = orionis.NormalizeScopes(c.AllowedScopes)
	c.DefaultScopes = orionis.NormalizeScopes(c.DefaultScopes)

	return c
}

// Validate performs complete validation for a statically configured client.
func (c Client) Validate() error {
	c = c.Normalize()

	if c.ID == "" {
		return errors.New("id is required")
	}

	if !c.hasCredentials() {
		return errors.New("at least one client secret is required")
	}

	for _, hash := range c.SecretSHA256Hex {
		decoded, err := hex.DecodeString(hash)

		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("secret_sha256_hex: invalid SHA-256 digest %q", hash)
		}
	}

	if len(c.AllowedAudiences) == 0 {
		return errors.New("at least one allowed audience is required")
	}

	if err := c.ValidateScopePolicy(); err != nil {
		return err
	}

	for _, scope := range c.DefaultScopes {
		if !isScopeAllowed(scope, c.AllowedScopes) {
			return fmt.Errorf("default_scopes: scope %q is not allowed", scope)
		}
	}

	return nil
}

// ValidateScopePolicy validates wildcard syntax for allowed and default scopes.
func (c Client) ValidateScopePolicy() error {
	c = c.Normalize()

	for _, scope := range c.AllowedScopes {
		if err := orionis.ValidateScopeWildcard(scope); err != nil {
			return fmt.Errorf("allowed_scopes: %w", err)
		}
	}

	for _, scope := range c.DefaultScopes {
		if containsScopeWildcard(scope) {
			return fmt.Errorf("default_scopes: wildcard scope %q is not allowed", scope)
		}
	}

	return nil
}

func (c Client) VerifySecret(secret string) bool {
	if secret == "" {
		return false
	}

	provided := sha256.Sum256([]byte(secret))

	for _, plain := range c.Secrets {
		stored := sha256.Sum256([]byte(plain))

		if subtle.ConstantTimeCompare(provided[:], stored[:]) == 1 {
			return true
		}
	}

	for _, hash := range c.SecretSHA256Hex {
		decoded, err := hex.DecodeString(strings.TrimSpace(hash))

		if err == nil && len(decoded) == sha256.Size && subtle.ConstantTimeCompare(provided[:], decoded) == 1 {
			return true
		}
	}

	return false
}

func (c Client) hasCredentials() bool {
	for _, secret := range c.Secrets {
		if secret != "" {
			return true
		}
	}

	return len(c.SecretSHA256Hex) > 0
}

func cloneClient(c Client) Client {
	c.Secrets = slices.Clone(c.Secrets)
	c.SecretSHA256Hex = slices.Clone(c.SecretSHA256Hex)
	c.AllowedAudiences = slices.Clone(c.AllowedAudiences)
	c.AllowedScopes = slices.Clone(c.AllowedScopes)
	c.DefaultScopes = slices.Clone(c.DefaultScopes)

	return c
}

func normalizeHashes(values []string) []string {
	if values == nil {
		return nil
	}

	normalized := make([]string, len(values))

	for index, value := range values {
		normalized[index] = strings.TrimSpace(value)
	}

	return normalized
}
