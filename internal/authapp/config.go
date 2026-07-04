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

package authapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stremovskyy/orionis/server"
)

type Config struct {
	Listen         string           `json:"listen"`
	LogLevel       string           `json:"log_level"`
	Issuer         string           `json:"issuer"`
	AccessTokenTTL string           `json:"access_token_ttl"`
	ActiveKID      string           `json:"active_kid,omitempty"`
	Key            KeyConfig        `json:"key"`
	Keys           []KeyConfig      `json:"keys,omitempty"`
	RateLimits     RateLimitsConfig `json:"rate_limits,omitempty"`
	AuditLogs      AuditLogConfig   `json:"audit_logs,omitempty"`
	Clients        []server.Client  `json:"clients"`

	legacyKeySet bool
	keysSet      bool
}

type KeyConfig struct {
	KID              string `json:"kid"`
	PrivateKeyPath   string `json:"private_key_path,omitempty"`
	PrivateKeyPEMEnv string `json:"private_key_pem_env,omitempty"`
}

type RateLimitsConfig struct {
	Token  EndpointRateLimitConfig `json:"token,omitempty"`
	Readyz EndpointRateLimitConfig `json:"readyz,omitempty"`
}

type EndpointRateLimitConfig struct {
	Enabled *bool  `json:"enabled,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Window  string `json:"window,omitempty"`
}

type AuditLogConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var cfg Config

	if path == "" {
		return cfg, errors.New("config path is required")
	}

	raw, err := os.ReadFile(expandPath(path))
	if err != nil {
		return cfg, err
	}

	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}

	var fields map[string]json.RawMessage

	if err := json.Unmarshal(raw, &fields); err != nil {
		return cfg, err
	}

	cfg.legacyKeySet = jsonFieldSet(fields, "key")
	cfg.keysSet = jsonFieldSet(fields, "keys")

	if strings.TrimSpace(cfg.Issuer) == "" {
		return cfg, errors.New("issuer is required")
	}

	if len(cfg.Clients) == 0 {
		return cfg, errors.New("at least one client is required")
	}

	if err := validateSigningConfig(cfg); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func (c Config) ListenAddr() string {
	if strings.TrimSpace(c.Listen) == "" {
		return ":8080"
	}

	return c.Listen
}

func validateSigningConfig(cfg Config) error {
	if cfg.legacyKeySet && cfg.keysSet {
		return errors.New("key and keys are mutually exclusive")
	}

	activeKID := strings.TrimSpace(cfg.ActiveKID)

	if cfg.keysSet || len(cfg.Keys) > 0 {
		if len(cfg.Keys) == 0 {
			return errors.New("keys must contain at least one signing key")
		}

		seen := make(map[string]struct{}, len(cfg.Keys))

		for i, key := range cfg.Keys {
			kid := strings.TrimSpace(key.KID)

			if kid == "" {
				return fmt.Errorf("keys[%d].kid is required", i)
			}

			if _, ok := seen[kid]; ok {
				return fmt.Errorf("duplicate signing kid %q", kid)
			}

			seen[kid] = struct{}{}
		}

		if activeKID != "" {
			if _, ok := seen[activeKID]; !ok {
				return fmt.Errorf("active_kid %q does not match a configured signing key", activeKID)
			}
		}

		return nil
	}

	if activeKID != "" && activeKID != legacyKeyID(cfg.Key) {
		return fmt.Errorf("active_kid %q does not match the configured signing key", activeKID)
	}

	return nil
}

func jsonFieldSet(fields map[string]json.RawMessage, key string) bool {
	raw, ok := fields[key]

	if !ok {
		return false
	}

	value := strings.TrimSpace(string(raw))

	return value != "" && value != "null"
}

func legacyKeyID(cfg KeyConfig) string {
	if kid := strings.TrimSpace(cfg.KID); kid != "" {
		return kid
	}

	return "orionis-ed25519-1"
}

func parseDurationDefault(value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%q: %w", value, err)
	}

	return d, nil
}

func expandPath(path string) string {
	if path == "" || path == "." {
		return path
	}

	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}

	return path
}
