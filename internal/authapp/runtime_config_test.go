package authapp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

func TestNewValidatesRuntimeConfigBeforeCreatingKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name: "log level",
			mutate: func(cfg *Config) {
				cfg.LogLevel = "verbose"
			},
			want: "unsupported log_level",
		},
		{
			name: "base path",
			mutate: func(cfg *Config) {
				cfg.BasePath = "/auth//private"
			},
			want: "base_path",
		},
		{
			name: "parameter base path",
			mutate: func(cfg *Config) {
				cfg.BasePath = "/auth/:tenant"
			},
			want: "base_path must be a static URL path",
		},
		{
			name: "wildcard base path",
			mutate: func(cfg *Config) {
				cfg.BasePath = "/auth/*rest"
			},
			want: "base_path must be a static URL path",
		},
		{
			name: "query base path",
			mutate: func(cfg *Config) {
				cfg.BasePath = "/auth?debug=true"
			},
			want: "base_path must be a static URL path",
		},
		{
			name: "whitespace base path",
			mutate: func(cfg *Config) {
				cfg.BasePath = "/auth private"
			},
			want: "base_path must be a static URL path",
		},
		{
			name: "rate limit",
			mutate: func(cfg *Config) {
				cfg.RateLimits.Token.Window = "not-a-duration"
			},
			want: "rate_limits.token",
		},
		{
			name: "access token ttl",
			mutate: func(cfg *Config) {
				cfg.AccessTokenTTL = "tomorrow"
			},
			want: "access token ttl",
		},
		{
			name: "zero access token ttl",
			mutate: func(cfg *Config) {
				cfg.AccessTokenTTL = "0s"
			},
			want: "access token ttl must be greater than zero",
		},
		{
			name: "negative access token ttl",
			mutate: func(cfg *Config) {
				cfg.AccessTokenTTL = "-1s"
			},
			want: "access token ttl must be greater than zero",
		},
		{
			name: "sub-second access token ttl",
			mutate: func(cfg *Config) {
				cfg.AccessTokenTTL = "999ms"
			},
			want: "access token ttl must be at least 1s",
		},
		{
			name: "negative rate limit",
			mutate: func(cfg *Config) {
				cfg.RateLimits.Token.Limit = -1
			},
			want: "rate_limits.token: limit must be greater than zero",
		},
		{
			name: "zero rate limit window",
			mutate: func(cfg *Config) {
				cfg.RateLimits.Readyz.Window = "0s"
			},
			want: "rate_limits.readyz: window must be greater than zero",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			keyPath := filepath.Join(dir, "signing.pem")
			cfg := testRuntimeConfig(t)
			cfg.Key.PrivateKeyPath = keyPath
			tt.mutate(&cfg)

			_, err := New(cfg)

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}

			if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
				t.Fatalf("key file was created before validation: %v", statErr)
			}
		})
	}
}

func TestCompileConfigNormalizesClients(t *testing.T) {
	t.Parallel()

	cfg := testRuntimeConfig(t)
	cfg.Clients[0].ID = "  orders-service  "
	cfg.Clients[0].AllowedAudiences = []string{" billing-api ", "billing-api"}
	cfg.Clients[0].AllowedScopes = []string{" billing.invoice.create ", "billing.invoice.create"}

	resolved, err := compileConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	client := resolved.raw.Clients[0]

	if client.ID != "orders-service" {
		t.Fatalf("client id = %q, want normalized id", client.ID)
	}

	if len(client.AllowedAudiences) != 1 || client.AllowedAudiences[0] != "billing-api" {
		t.Fatalf("audiences = %#v, want one normalized audience", client.AllowedAudiences)
	}

	if len(client.AllowedScopes) != 1 || client.AllowedScopes[0] != "billing.invoice.create" {
		t.Fatalf("scopes = %#v, want one normalized scope", client.AllowedScopes)
	}
}

func TestNewRejectsDuplicateNormalizedClientIDsBeforeLoadingSigner(t *testing.T) {
	t.Parallel()

	cfg := testRuntimeConfig(t)
	keyPath := cfg.Key.PrivateKeyPath
	duplicate := cfg.Clients[0]
	cfg.Clients[0].ID = " orders-service "
	duplicate.ID = "orders-service\t"
	cfg.Clients = append(cfg.Clients, duplicate)
	loadCalls := 0

	_, err := newWithSignerLoader(cfg, func(KeyConfig) (server.Signer, error) {
		loadCalls++

		return nil, nil
	})

	if err == nil || !strings.Contains(err.Error(), `duplicate client id "orders-service"`) {
		t.Fatalf("error = %v, want duplicate normalized client id", err)
	}

	if loadCalls != 0 {
		t.Fatalf("signer loader calls = %d, want 0", loadCalls)
	}

	if _, statErr := os.Stat(keyPath); !os.IsNotExist(statErr) {
		t.Fatalf("key file was created before client validation: %v", statErr)
	}
}

func TestNewWithSignerLoaderAcceptsOpaqueCustomKeyMaterial(t *testing.T) {
	t.Setenv("ORIONIS_CUSTOM_SIGNER_HANDLE", "opaque-hsm-handle")

	cfg := testRuntimeConfig(t)
	cfg.Key.PrivateKeyPath = ""
	cfg.Key.PrivateKeyPEMEnv = "ORIONIS_CUSTOM_SIGNER_HANDLE"
	signer, err := jwk.GenerateEd25519Signer("custom-loader-key")
	if err != nil {
		t.Fatal(err)
	}

	loader := &fixedSignerLoader{signer: signer}
	runtime, err := NewWithSignerLoader(cfg, loader)
	if err != nil {
		t.Fatalf("custom loader material was interpreted as Ed25519 PEM: %v", err)
	}

	if runtime == nil || loader.calls != 1 {
		t.Fatalf("runtime = %v, loader calls = %d; want one custom load", runtime, loader.calls)
	}
}

func TestLoadConfigRejectsExplicitInvalidRateLimits(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setting string
		want    string
	}{
		{name: "zero limit", setting: `"limit": 0`, want: "limit must be greater than zero"},
		{name: "negative limit", setting: `"limit": -1`, want: "limit must be greater than zero"},
		{name: "empty window", setting: `"window": ""`, want: "window must not be empty"},
		{name: "zero window", setting: `"window": "0s"`, want: "window must be greater than zero"},
		{name: "negative window", setting: `"window": "-1s"`, want: "window must be greater than zero"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfgPath := writeConfig(t, `{
				"issuer": "https://auth.orionis.test",
				"key": {},
				"rate_limits": {"token": {`+tt.setting+`}},
				"clients": [{
					"id": "orders-service",
					"secrets": ["secret"],
					"allowed_audiences": ["billing-api"],
					"allowed_scopes": ["billing.read"]
				}]
			}`)

			_, err := LoadConfig(cfgPath)

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCompileConfigPreservesOmittedDefaults(t *testing.T) {
	t.Parallel()

	resolved, err := compileConfig(testRuntimeConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	if resolved.accessTokenTTL != defaultAccessTokenTTL {
		t.Fatalf("access token ttl = %s, want %s", resolved.accessTokenTTL, defaultAccessTokenTTL)
	}

	if resolved.tokenLimit.limit != defaultTokenRateLimit || resolved.tokenLimit.window != defaultRateLimitWindow {
		t.Fatalf("token rate limit = %+v, want default limit and window", resolved.tokenLimit)
	}

	if resolved.readyzLimit.limit != defaultReadyzRateLimit || resolved.readyzLimit.window != defaultRateLimitWindow {
		t.Fatalf("readyz rate limit = %+v, want default limit and window", resolved.readyzLimit)
	}
}

func TestFixedWindowRateLimiterEvictsExpiredWindows(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	limiter := newFixedWindowRateLimiter(func() time.Time { return now })

	for _, key := range []string{"token|192.0.2.1", "token|192.0.2.2"} {
		if ok, _ := limiter.allow(key, 1, time.Second); !ok {
			t.Fatalf("first request for %s was rejected", key)
		}
	}

	now = now.Add(2 * time.Second)

	if ok, _ := limiter.allow("token|192.0.2.3", 1, time.Second); !ok {
		t.Fatal("request after sweep was rejected")
	}

	if _, exists := limiter.windows["token|192.0.2.1"]; exists {
		t.Fatal("expired window was not evicted")
	}

	if got := len(limiter.windows); got != 1 {
		t.Fatalf("window count = %d, want 1", got)
	}
}

func TestNewValidatesAllKeySourcesBeforeCreatingMissingFiles(t *testing.T) {
	dir := t.TempDir()
	generatedPath := filepath.Join(dir, "generated.pem")
	t.Setenv("ORIONIS_INVALID_SIGNING_KEY", "not pem")

	cfg := testRuntimeConfig(t)
	cfg.Key = KeyConfig{}
	cfg.Keys = []KeyConfig{
		{KID: "generated", PrivateKeyPath: generatedPath},
		{KID: "invalid-env", PrivateKeyPEMEnv: "ORIONIS_INVALID_SIGNING_KEY"},
	}

	_, err := New(cfg)

	if err == nil || !strings.Contains(err.Error(), "validate private_key_pem_env") {
		t.Fatalf("error = %v, want invalid environment PEM", err)
	}

	if _, statErr := os.Stat(generatedPath); !os.IsNotExist(statErr) {
		t.Fatalf("key file was created before all sources were validated: %v", statErr)
	}
}

func TestLoadConfigRemainsPermissiveForUnknownFields(t *testing.T) {
	t.Parallel()

	cfgPath := writeConfig(t, `{
		"issuer": "https://auth.orionis.test",
		"future_setting": {"enabled": true},
		"key": {},
		"clients": [{
			"id": "orders-service",
			"secrets": ["secret"],
			"allowed_audiences": ["billing-api"],
			"allowed_scopes": ["billing.read"],
			"default_scopes": ["billing.read"]
		}]
	}`)

	if _, err := LoadConfig(cfgPath); err != nil {
		t.Fatalf("unknown fields should remain compatible: %v", err)
	}
}

type fixedSignerLoader struct {
	signer server.Signer
	calls  int
}

func (l *fixedSignerLoader) LoadSigner(KeyConfig) (server.Signer, error) {
	l.calls++

	return l.signer, nil
}
