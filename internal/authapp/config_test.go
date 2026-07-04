package authapp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis"
	"github.com/stremovskyy/orionis/server"
)

func TestLoadConfigParsesValidJSON(t *testing.T) {
	path := writeConfig(t, `{
		"listen": ":9090",
		"log_level": "debug",
		"issuer": "https://auth.orionis.test",
		"access_token_ttl": "10m",
		"key": {
			"kid": "test-key",
			"private_key_path": "./var/test.pem"
		},
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":9090" {
		t.Fatalf("unexpected listen: %q", cfg.Listen)
	}

	if cfg.LogLevel != "debug" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}

	if cfg.Issuer != "https://auth.orionis.test" {
		t.Fatalf("unexpected issuer: %q", cfg.Issuer)
	}

	if len(cfg.Clients) != 1 || cfg.Clients[0].ID != "orders-service" {
		t.Fatalf("unexpected clients: %+v", cfg.Clients)
	}
}

func TestLoadConfigParsesKeyRotationJSON(t *testing.T) {
	path := writeConfig(t, `{
		"listen": ":9090",
		"issuer": "https://auth.orionis.test",
		"active_kid": "rotation-key-2",
		"keys": [
			{"kid": "rotation-key-1", "private_key_path": "./var/key-1.pem"},
			{"kid": "rotation-key-2", "private_key_path": "./var/key-2.pem"}
		],
		"rate_limits": {
			"token": {"enabled": true, "limit": 60, "window": "1m"},
			"readyz": {"enabled": true, "limit": 300, "window": "1m"}
		},
		"audit_logs": {"enabled": true},
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ActiveKID != "rotation-key-2" {
		t.Fatalf("unexpected active kid: %q", cfg.ActiveKID)
	}

	if len(cfg.Keys) != 2 {
		t.Fatalf("expected two keys, got %+v", cfg.Keys)
	}

	if cfg.Keys[0].KID != "rotation-key-1" || cfg.Keys[1].KID != "rotation-key-2" {
		t.Fatalf("unexpected keys: %+v", cfg.Keys)
	}

	if cfg.RateLimits.Token.Limit != 60 || cfg.RateLimits.Readyz.Limit != 300 {
		t.Fatalf("unexpected rate limits: %+v", cfg.RateLimits)
	}
}

func TestLoadConfigRejectsKeyAndKeysConflict(t *testing.T) {
	path := writeConfig(t, `{
		"issuer": "https://auth.orionis.test",
		"key": {"kid": "legacy-key", "private_key_path": "./var/legacy.pem"},
		"keys": [{"kid": "rotation-key", "private_key_path": "./var/rotation.pem"}],
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected key/keys conflict to be rejected")
	}

	if !strings.Contains(err.Error(), "key") || !strings.Contains(err.Error(), "keys") {
		t.Fatalf("expected key/keys error, got %v", err)
	}
}

func TestLoadConfigRejectsEmptyKeys(t *testing.T) {
	path := writeConfig(t, `{
		"issuer": "https://auth.orionis.test",
		"keys": [],
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("expected empty keys to be rejected")
	}
}

func TestLoadConfigRejectsDuplicateKeyIDs(t *testing.T) {
	path := writeConfig(t, `{
		"issuer": "https://auth.orionis.test",
		"keys": [
			{"kid": "duplicate-key", "private_key_path": "./var/key-1.pem"},
			{"kid": "duplicate-key", "private_key_path": "./var/key-2.pem"}
		],
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected duplicate kids to be rejected")
	}

	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate kid error, got %v", err)
	}
}

func TestLoadConfigRejectsMissingActiveKID(t *testing.T) {
	path := writeConfig(t, `{
		"issuer": "https://auth.orionis.test",
		"active_kid": "missing-key",
		"keys": [
			{"kid": "rotation-key", "private_key_path": "./var/key.pem"}
		],
		"clients": [
			{
				"id": "orders-service",
				"secrets": ["secret"],
				"allowed_audiences": ["billing-api"],
				"allowed_scopes": ["billing.invoice.create"]
			}
		]
	}`)

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatalf("expected missing active kid to be rejected")
	}

	if !strings.Contains(err.Error(), "active_kid") {
		t.Fatalf("expected active_kid error, got %v", err)
	}
}

func TestLoadConfigRejectsMissingClients(t *testing.T) {
	path := writeConfig(t, `{"issuer":"https://auth.orionis.test"}`)

	if _, err := LoadConfig(path); err == nil {
		t.Fatalf("expected config without clients to be rejected")
	}
}

func TestEd25519SignerLoaderKeepsFileModeCompatibility(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "orionis-ed25519.pem")

	signer, err := Ed25519SignerLoader{}.LoadSigner(KeyConfig{KID: "file-kid", PrivateKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}

	if signer.KeyID() != "file-kid" {
		t.Fatalf("unexpected kid: %q", signer.KeyID())
	}

	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected file mode to create key at %s: %v", keyPath, err)
	}
}

func TestEd25519SignerLoaderReadsPEMFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ORIONIS_SIGNING_KEY_PEM", string(testSigningKeyPEM(t)))

	signer, err := Ed25519SignerLoader{}.LoadSigner(KeyConfig{
		KID:              "env-kid",
		PrivateKeyPEMEnv: "ORIONIS_SIGNING_KEY_PEM",
	})
	if err != nil {
		t.Fatal(err)
	}

	if signer.KeyID() != "env-kid" {
		t.Fatalf("unexpected kid: %q", signer.KeyID())
	}

	if _, err := os.Stat(filepath.Join(dir, "orionis-ed25519.pem")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected env mode not to create a key file, stat err=%v", err)
	}
}

func TestEd25519SignerLoaderRejectsMissingPEMEnvironmentVariable(t *testing.T) {
	_, err := Ed25519SignerLoader{}.LoadSigner(KeyConfig{PrivateKeyPEMEnv: "ORIONIS_MISSING_SIGNING_KEY_PEM"})
	if err == nil {
		t.Fatalf("expected missing environment variable to be rejected")
	}

	if !strings.Contains(err.Error(), "ORIONIS_MISSING_SIGNING_KEY_PEM") {
		t.Fatalf("expected environment variable name in error, got %v", err)
	}
}

func TestEd25519SignerLoaderRejectsPathAndPEMEnvironmentConflict(t *testing.T) {
	_, err := Ed25519SignerLoader{}.LoadSigner(KeyConfig{
		PrivateKeyPath:   "/app/var/key.pem",
		PrivateKeyPEMEnv: "ORIONIS_SIGNING_KEY_PEM",
	})
	if err == nil {
		t.Fatalf("expected path and env conflict to be rejected")
	}

	if !strings.Contains(err.Error(), "private_key_path") || !strings.Contains(err.Error(), "private_key_pem_env") {
		t.Fatalf("expected path/env error, got %v", err)
	}
}

func TestEd25519SignerLoaderRejectsInvalidEnvironmentPEM(t *testing.T) {
	t.Setenv("ORIONIS_SIGNING_KEY_PEM", "not pem")

	_, err := Ed25519SignerLoader{}.LoadSigner(KeyConfig{PrivateKeyPEMEnv: "ORIONIS_SIGNING_KEY_PEM"})
	if err == nil {
		t.Fatalf("expected invalid pem to be rejected")
	}

	if !strings.Contains(err.Error(), "decode pem") {
		t.Fatalf("expected decode pem error, got %v", err)
	}
}

func TestNewUsesActiveKID(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Issuer:    "https://auth.orionis.test",
		ActiveKID: "rotation-key-2",
		Keys: []KeyConfig{
			{KID: "rotation-key-1", PrivateKeyPath: filepath.Join(dir, "key-1.pem")},
			{KID: "rotation-key-2", PrivateKeyPath: filepath.Join(dir, "key-2.pem")},
		},
		Clients: serverClientForTest(),
	}

	runtime, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token := issueTestToken(t, runtime.auth)

	if kid := tokenHeaderKID(t, token); kid != "rotation-key-2" {
		t.Fatalf("expected active kid rotation-key-2, got %q", kid)
	}
}

func TestNewKeepsLegacyKeyCompatibility(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Issuer:  "https://auth.orionis.test",
		Key:     KeyConfig{KID: "legacy-key", PrivateKeyPath: filepath.Join(dir, "legacy.pem")},
		Clients: serverClientForTest(),
	}

	runtime, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	token := issueTestToken(t, runtime.auth)

	if kid := tokenHeaderKID(t, token); kid != "legacy-key" {
		t.Fatalf("expected legacy key, got %q", kid)
	}
}

func TestMountAddsReadyzWithRateLimitAndAudit(t *testing.T) {
	previousMode := gin.Mode()
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() {
		gin.SetMode(previousMode)
		slog.SetDefault(previousLogger)
	})

	enabled := true
	cfg := testRuntimeConfig(t)
	cfg.RateLimits.Readyz = EndpointRateLimitConfig{Enabled: &enabled, Limit: 1, Window: "1m"}
	cfg.AuditLogs = AuditLogConfig{Enabled: &enabled}

	runtime, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()

	if err := runtime.Mount(r); err != nil {
		t.Fatal(err)
	}

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	r.ServeHTTP(first, req)

	if first.Code != http.StatusOK {
		t.Fatalf("expected readyz 200, got %d: %s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	req.RemoteAddr = "203.0.113.10:1235"
	r.ServeHTTP(second, req)

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("expected readyz 429, got %d: %s", second.Code, second.Body.String())
	}

	if second.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on rate limit")
	}

	gotLogs := logs.String()

	if !strings.Contains(gotLogs, "path=/readyz") || !strings.Contains(gotLogs, "outcome=rate_limited") {
		t.Fatalf("expected readyz audit logs, got %q", gotLogs)
	}
}

func TestTokenAuditLogRedactsSecrets(t *testing.T) {
	previousMode := gin.Mode()
	previousLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() {
		gin.SetMode(previousMode)
		slog.SetDefault(previousLogger)
	})

	disabled := false
	enabled := true
	cfg := testRuntimeConfig(t)
	cfg.RateLimits.Token = EndpointRateLimitConfig{Enabled: &disabled}
	cfg.AuditLogs = AuditLogConfig{Enabled: &enabled}

	runtime, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	r := gin.New()

	if err := runtime.Mount(r); err != nil {
		t.Fatal(err)
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", "billing-api")
	form.Set("scope", "billing.invoice.create")
	form.Set("client_id", "orders-service")
	form.Set("client_secret", "do-not-log-this")

	res := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.20:1234"
	r.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected token 200, got %d: %s", res.Code, res.Body.String())
	}

	gotLogs := logs.String()

	if !strings.Contains(gotLogs, "path=/oauth/token") || !strings.Contains(gotLogs, "client_id=orders-service") {
		t.Fatalf("expected token audit log with safe client id, got %q", gotLogs)
	}

	for _, forbidden := range []string{"do-not-log-this", "client_secret", "Authorization", "private_key"} {
		if strings.Contains(gotLogs, forbidden) {
			t.Fatalf("audit log leaked %q: %s", forbidden, gotLogs)
		}
	}
}

func writeConfig(t *testing.T, raw string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "orionis.json")

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func serverClientForTest() []server.Client {
	return []server.Client{
		server.NewClient("orders-service").
			Secret("do-not-log-this").
			Audience("billing-api").
			Scopes("billing.invoice.create").
			Defaults("billing.invoice.create"),
	}
}

func testRuntimeConfig(t *testing.T) Config {
	t.Helper()

	dir := t.TempDir()

	return Config{
		Issuer: "https://auth.orionis.test",
		Key:    KeyConfig{KID: "runtime-key", PrivateKeyPath: filepath.Join(dir, "runtime.pem")},
		Clients: []server.Client{
			server.NewClient("orders-service").
				Secret("do-not-log-this").
				Audience("billing-api").
				Scopes("billing.invoice.create").
				Defaults("billing.invoice.create"),
		},
	}
}

func issueTestToken(t *testing.T, auth interface {
	TokenHTTP(http.ResponseWriter, *http.Request)
},
) string {
	t.Helper()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("audience", "billing-api")
	form.Set("scope", "billing.invoice.create")
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("orders-service", "do-not-log-this")
	res := httptest.NewRecorder()
	auth.TokenHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected token 200, got %d: %s", res.Code, res.Body.String())
	}

	var tr orionis.TokenResponse

	if err := json.Unmarshal(res.Body.Bytes(), &tr); err != nil {
		t.Fatal(err)
	}

	return tr.AccessToken
}

func tokenHeaderKID(t *testing.T, token string) string {
	t.Helper()

	parts := strings.Split(token, ".")

	if len(parts) < 2 {
		t.Fatalf("token is not a jwt: %q", token)
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	var header struct {
		KID string `json:"kid"`
	}

	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}

	return header.KID
}

func testSigningKeyPEM(t *testing.T) []byte {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
