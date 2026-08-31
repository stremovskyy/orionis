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

	"github.com/stremovskyy/orionis/server"
)

type Config struct {
	Listen         string           `json:"listen"`
	LogLevel       string           `json:"log_level"`
	Issuer         string           `json:"issuer"`
	BasePath       string           `json:"base_path,omitempty"`
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

	limitSet  bool
	windowSet bool
}

type AuditLogConfig struct {
	Enabled *bool `json:"enabled,omitempty"`
}

// wireConfig preserves presence for signing-mode and rate-limit fields whose
// omitted values have compatibility defaults.
type wireConfig struct {
	Listen         string          `json:"listen"`
	LogLevel       string          `json:"log_level"`
	Issuer         string          `json:"issuer"`
	BasePath       string          `json:"base_path,omitempty"`
	AccessTokenTTL string          `json:"access_token_ttl"`
	ActiveKID      string          `json:"active_kid,omitempty"`
	Key            *KeyConfig      `json:"key"`
	Keys           *[]KeyConfig    `json:"keys,omitempty"`
	RateLimits     wireRateLimits  `json:"rate_limits,omitempty"`
	AuditLogs      AuditLogConfig  `json:"audit_logs,omitempty"`
	Clients        []server.Client `json:"clients"`
}

type wireRateLimits struct {
	Token  wireEndpointRateLimit `json:"token,omitempty"`
	Readyz wireEndpointRateLimit `json:"readyz,omitempty"`
}

type wireEndpointRateLimit struct {
	Enabled *bool   `json:"enabled,omitempty"`
	Limit   *int    `json:"limit,omitempty"`
	Window  *string `json:"window,omitempty"`
}

func (w wireRateLimits) runtimeConfig() RateLimitsConfig {
	return RateLimitsConfig{
		Token:  w.Token.runtimeConfig(),
		Readyz: w.Readyz.runtimeConfig(),
	}
}

func (w wireEndpointRateLimit) runtimeConfig() EndpointRateLimitConfig {
	cfg := EndpointRateLimitConfig{Enabled: w.Enabled}

	if w.Limit != nil {
		cfg.Limit = *w.Limit
		cfg.limitSet = true
	}

	if w.Window != nil {
		cfg.Window = *w.Window
		cfg.windowSet = true
	}

	return cfg
}

func (w wireConfig) runtimeConfig() Config {
	cfg := Config{
		Listen:         w.Listen,
		LogLevel:       w.LogLevel,
		Issuer:         w.Issuer,
		BasePath:       w.BasePath,
		AccessTokenTTL: w.AccessTokenTTL,
		ActiveKID:      w.ActiveKID,
		RateLimits:     w.RateLimits.runtimeConfig(),
		AuditLogs:      w.AuditLogs,
		Clients:        w.Clients,
		legacyKeySet:   w.Key != nil,
		keysSet:        w.Keys != nil,
	}

	if w.Key != nil {
		cfg.Key = *w.Key
	}

	if w.Keys != nil {
		cfg.Keys = append([]KeyConfig(nil), (*w.Keys)...)
	}

	return cfg
}

func LoadConfig(path string) (Config, error) {
	var cfg Config

	if strings.TrimSpace(path) == "" {
		return cfg, errors.New("config path is required")
	}

	resolvedPath := expandPath(path)
	raw, err := os.ReadFile(resolvedPath)
	if err != nil {
		return cfg, fmt.Errorf("read config %q: %w", resolvedPath, err)
	}

	var wire wireConfig

	if err := json.Unmarshal(raw, &wire); err != nil {
		return cfg, fmt.Errorf("decode config %q: %w", resolvedPath, err)
	}

	cfg = wire.runtimeConfig()

	resolved, err := compileConfig(cfg)
	if err != nil {
		return cfg, err
	}

	return resolved.raw, nil
}

func (c Config) ListenAddr() string {
	if strings.TrimSpace(c.Listen) == "" {
		return ":8080"
	}

	return strings.TrimSpace(c.Listen)
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
