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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

const (
	defaultTokenRateLimit  = 60
	defaultReadyzRateLimit = 300
	defaultRateLimitWindow = time.Minute
	defaultAccessTokenTTL  = 15 * time.Minute
)

type resolvedConfig struct {
	raw            Config
	logLevel       slog.Level
	accessTokenTTL time.Duration
	basePath       string
	tokenLimit     effectiveRateLimit
	readyzLimit    effectiveRateLimit
	auditEnabled   bool
}

type effectiveRateLimit struct {
	enabled bool
	limit   int
	window  time.Duration
}

func resolveConfig(cfg Config) (resolvedConfig, error) {
	resolved, err := compileConfig(cfg)
	if err != nil {
		return resolvedConfig{}, err
	}

	if err := validateKeyMaterials(effectiveKeyConfigs(resolved.raw)); err != nil {
		return resolvedConfig{}, err
	}

	return resolved, nil
}

func compileConfig(cfg Config) (resolvedConfig, error) {
	cfg = normalizeRuntimeConfig(cfg)

	accessTokenTTL, err := parseDurationDefault(cfg.AccessTokenTTL, defaultAccessTokenTTL)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("parse access token ttl: %w", err)
	}

	if accessTokenTTL <= 0 {
		return resolvedConfig{}, errors.New("access token ttl must be greater than zero")
	}

	if accessTokenTTL < time.Second {
		return resolvedConfig{}, errors.New("access token ttl must be at least 1s")
	}

	logLevel, err := ParseLogLevel(cfg.LogLevel)
	if err != nil {
		return resolvedConfig{}, err
	}

	basePath, err := normalizeBasePath(cfg.BasePath)
	if err != nil {
		return resolvedConfig{}, err
	}

	tokenLimit, err := normalizeRateLimit(cfg.RateLimits.Token, defaultTokenRateLimit, defaultRateLimitWindow)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("rate_limits.token: %w", err)
	}

	readyzLimit, err := normalizeRateLimit(cfg.RateLimits.Readyz, defaultReadyzRateLimit, defaultRateLimitWindow)
	if err != nil {
		return resolvedConfig{}, fmt.Errorf("rate_limits.readyz: %w", err)
	}

	cfg.BasePath = basePath

	if cfg.Issuer == "" {
		return resolvedConfig{}, errors.New("issuer is required")
	}

	if err := validateClients(cfg.Clients); err != nil {
		return resolvedConfig{}, err
	}

	if err := validateSigningConfig(cfg); err != nil {
		return resolvedConfig{}, err
	}

	if err := validateKeySourceConfig(effectiveKeyConfigs(cfg)); err != nil {
		return resolvedConfig{}, err
	}

	cfg.RateLimits.Token.limitSet = false
	cfg.RateLimits.Token.windowSet = false
	cfg.RateLimits.Readyz.limitSet = false
	cfg.RateLimits.Readyz.windowSet = false

	return resolvedConfig{
		raw:            cfg,
		logLevel:       logLevel,
		accessTokenTTL: accessTokenTTL,
		basePath:       basePath,
		tokenLimit:     tokenLimit,
		readyzLimit:    readyzLimit,
		auditEnabled:   boolDefault(cfg.AuditLogs.Enabled, true),
	}, nil
}

func normalizeRuntimeConfig(cfg Config) Config {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	cfg.LogLevel = strings.TrimSpace(cfg.LogLevel)
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	cfg.BasePath = strings.TrimSpace(cfg.BasePath)
	cfg.AccessTokenTTL = strings.TrimSpace(cfg.AccessTokenTTL)
	cfg.ActiveKID = strings.TrimSpace(cfg.ActiveKID)
	cfg.Key = normalizeKeyConfig(cfg.Key)
	cfg.Keys = append([]KeyConfig(nil), cfg.Keys...)

	for i := range cfg.Keys {
		cfg.Keys[i] = normalizeKeyConfig(cfg.Keys[i])
	}

	if cfg.Clients != nil {
		clients := make([]server.Client, len(cfg.Clients))

		for i, client := range cfg.Clients {
			clients[i] = client.Normalize()
		}

		cfg.Clients = clients
	}

	cfg.RateLimits.Token.Window = strings.TrimSpace(cfg.RateLimits.Token.Window)
	cfg.RateLimits.Readyz.Window = strings.TrimSpace(cfg.RateLimits.Readyz.Window)

	return cfg
}

func normalizeKeyConfig(cfg KeyConfig) KeyConfig {
	cfg.KID = strings.TrimSpace(cfg.KID)
	cfg.PrivateKeyPath = strings.TrimSpace(cfg.PrivateKeyPath)
	cfg.PrivateKeyPEMEnv = strings.TrimSpace(cfg.PrivateKeyPEMEnv)

	return cfg
}

func validateClients(clients []server.Client) error {
	if len(clients) == 0 {
		return errors.New("at least one client is required")
	}

	seen := make(map[string]struct{}, len(clients))

	for i, client := range clients {
		if err := client.Validate(); err != nil {
			return fmt.Errorf("clients[%d]: %w", i, err)
		}

		if _, exists := seen[client.ID]; exists {
			return fmt.Errorf("clients[%d]: duplicate client id %q", i, client.ID)
		}

		seen[client.ID] = struct{}{}
	}

	return nil
}

func ParseLogLevel(logLevel string) (slog.Level, error) {
	switch strings.TrimSpace(strings.ToLower(logLevel)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log_level %q", logLevel)
	}
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

			if _, exists := seen[kid]; exists {
				return fmt.Errorf("duplicate signing kid %q", kid)
			}

			seen[kid] = struct{}{}
		}

		if activeKID != "" {
			if _, exists := seen[activeKID]; !exists {
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

func validateKeySourceConfig(keys []KeyConfig) error {
	for i, key := range keys {
		path := strings.TrimSpace(key.PrivateKeyPath)
		envName := strings.TrimSpace(key.PrivateKeyPEMEnv)

		if path != "" && envName != "" {
			return fmt.Errorf("keys[%d]: private_key_path and private_key_pem_env are mutually exclusive", i)
		}
	}

	return nil
}

func validateKeyMaterials(keys []KeyConfig) error {
	for i, key := range keys {
		path := key.PrivateKeyPath
		envName := key.PrivateKeyPEMEnv

		if envName != "" {
			raw := os.Getenv(envName)

			if strings.TrimSpace(raw) == "" {
				return fmt.Errorf("keys[%d]: private_key_pem_env %q is empty or not set", i, envName)
			}

			if _, err := jwk.LoadEd25519SignerPEM([]byte(raw), key.KID); err != nil {
				return fmt.Errorf("keys[%d]: validate private_key_pem_env %q: %w", i, envName, err)
			}
		}

		if path != "" {
			resolvedPath := expandPath(path)
			raw, err := os.ReadFile(resolvedPath)

			switch {
			case err == nil:
				if _, err := jwk.LoadEd25519SignerPEM(raw, key.KID); err != nil {
					return fmt.Errorf("keys[%d]: validate private_key_path %q: %w", i, resolvedPath, err)
				}

			case !errors.Is(err, os.ErrNotExist):
				return fmt.Errorf("keys[%d]: read private_key_path %q: %w", i, resolvedPath, err)
			}
		}
	}

	return nil
}

func effectiveKeyConfigs(cfg Config) []KeyConfig {
	if cfg.keysSet || len(cfg.Keys) > 0 {
		return append([]KeyConfig(nil), cfg.Keys...)
	}

	return []KeyConfig{cfg.Key}
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

	duration, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%q: %w", value, err)
	}

	return duration, nil
}

func normalizeBasePath(value string) (string, error) {
	basePath := strings.TrimSpace(value)

	if basePath == "" || basePath == "/" {
		return "", nil
	}

	if !strings.HasPrefix(basePath, "/") {
		basePath = "/" + basePath
	}

	basePath = strings.TrimRight(basePath, "/")

	if strings.Contains(basePath, "//") {
		return "", errors.New("base_path must not contain empty path segments")
	}

	if strings.ContainsAny(basePath, ":*?#") || strings.IndexFunc(basePath, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) >= 0 {
		return "", errors.New(
			"base_path must be a static URL path without parameters, wildcards, query, or fragment",
		)
	}

	return basePath, nil
}

func normalizeRateLimit(
	cfg EndpointRateLimitConfig,
	defaultLimit int,
	defaultWindow time.Duration,
) (effectiveRateLimit, error) {
	limit := defaultLimit

	if cfg.limitSet || cfg.Limit != 0 {
		if cfg.Limit <= 0 {
			return effectiveRateLimit{}, errors.New("limit must be greater than zero")
		}

		limit = cfg.Limit
	}

	window := defaultWindow

	if cfg.windowSet || cfg.Window != "" {
		if cfg.Window == "" {
			return effectiveRateLimit{}, errors.New("window must not be empty")
		}

		parsed, err := time.ParseDuration(cfg.Window)
		if err != nil {
			return effectiveRateLimit{}, err
		}

		if parsed <= 0 {
			return effectiveRateLimit{}, errors.New("window must be greater than zero")
		}

		window = parsed
	}

	return effectiveRateLimit{
		enabled: boolDefault(cfg.Enabled, true),
		limit:   limit,
		window:  window,
	}, nil
}

func boolDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}

	return *value
}
