package authapp

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLoadConfigYAMLMatchesJSON(t *testing.T) {
	t.Parallel()

	const yamlConfig = `# The local YAML and JSON formats share the same field names.
listen: ":9090"
log_level: debug
issuer: https://auth.orionis.test
base_path: /auth
access_token_ttl: 10m
active_kid: rotation-key-2
keys:
  - kid: rotation-key-1
    private_key_path: ./var/key-1.pem
  - kid: rotation-key-2
    private_key_pem_env: ORIONIS_TEST_SIGNING_KEY_PEM
rate_limits:
  token: {enabled: false, limit: 20, window: 30s}
  readyz: {enabled: false, limit: 80, window: 2m}
audit_logs: {enabled: false}
clients:
  - id: orders-service
    secrets: [2026-10-22, 2026-10-22T12:34:56+03:00]
    allowed_audiences: [billing-api]
    allowed_scopes: [billing.invoice.*]
    default_scopes: [billing.invoice.read]
    disabled: false
  - id: 2026-10-22
    secret_sha256_hex: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
    allowed_audiences: [dispatch-api]
    allowed_scopes: [dispatch.order.read]
    disabled: true
unknown_setting: accepted
`
	const jsonConfig = `{
  "listen": ":9090", "log_level": "debug", "issuer": "https://auth.orionis.test",
  "base_path": "/auth", "access_token_ttl": "10m", "active_kid": "rotation-key-2",
  "keys": [
    {"kid": "rotation-key-1", "private_key_path": "./var/key-1.pem"},
    {"kid": "rotation-key-2", "private_key_pem_env": "ORIONIS_TEST_SIGNING_KEY_PEM"}
  ],
  "rate_limits": {
    "token": {"enabled": false, "limit": 20, "window": "30s"},
    "readyz": {"enabled": false, "limit": 80, "window": "2m"}
  },
  "audit_logs": {"enabled": false},
  "clients": [
    {"id": "orders-service", "secrets": ["2026-10-22", "2026-10-22T12:34:56+03:00"],
     "allowed_audiences": ["billing-api"], "allowed_scopes": ["billing.invoice.*"],
     "default_scopes": ["billing.invoice.read"], "disabled": false},
    {"id": "2026-10-22", "secret_sha256_hex": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
     "allowed_audiences": ["dispatch-api"], "allowed_scopes": ["dispatch.order.read"], "disabled": true}
  ],
  "unknown_setting": "accepted"
}`

	want, err := LoadConfig(writeConfig(t, jsonConfig))
	if err != nil {
		t.Fatal(err)
	}

	for _, extension := range []string{".yaml", ".yml", ".YAML", ".YmL"} {
		t.Run(extension, func(t *testing.T) {
			t.Parallel()

			got, err := LoadConfig(writeYAMLConfig(t, extension, yamlConfig))
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, want) {
				t.Fatalf("YAML configuration differs from JSON:\ngot:  %+v\nwant: %+v", got, want)
			}

			if got.Clients[0].Secrets[0] != "2026-10-22" || got.Clients[0].Secrets[1] != "2026-10-22T12:34:56+03:00" ||
				got.Clients[1].ID != "2026-10-22" {
				t.Fatalf("date-like credentials and IDs must retain their literal text: %+v", got.Clients)
			}

			resolved, err := compileConfig(got)
			if err != nil {
				t.Fatal(err)
			}

			if resolved.tokenLimit.enabled || resolved.readyzLimit.enabled || resolved.auditEnabled {
				t.Fatal("explicit false values must disable rate limits and audit logs")
			}
		})
	}
}

func TestLoadConfigYAMLLegacyKeyPreservesDefaults(t *testing.T) {
	t.Parallel()

	got, err := LoadConfig(writeYAMLConfig(t, ".yaml", `
issuer: https://auth.orionis.test
key: {kid: legacy-key, private_key_path: ./var/legacy.pem}
`+yamlTestClients))
	if err != nil {
		t.Fatal(err)
	}

	want, err := LoadConfig(writeConfig(t, `{
  "issuer": "https://auth.orionis.test",
  "key": {"kid": "legacy-key", "private_key_path": "./var/legacy.pem"},
  "clients": [{"id": "orders-service", "secrets": ["secret"],
    "allowed_audiences": ["billing-api"], "allowed_scopes": ["billing.invoice.read"]}]
}`))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("YAML legacy configuration differs from JSON:\ngot:  %+v\nwant: %+v", got, want)
	}

	resolved, err := compileConfig(got)
	if err != nil {
		t.Fatal(err)
	}

	if got.ListenAddr() != ":8080" || resolved.accessTokenTTL != defaultAccessTokenTTL ||
		!resolved.tokenLimit.enabled || resolved.tokenLimit.limit != defaultTokenRateLimit ||
		resolved.tokenLimit.window != defaultRateLimitWindow || !resolved.readyzLimit.enabled ||
		resolved.readyzLimit.limit != defaultReadyzRateLimit ||
		resolved.readyzLimit.window != defaultRateLimitWindow || !resolved.auditEnabled {
		t.Fatalf("omitted YAML settings must retain compatibility defaults: %+v", resolved)
	}
}

func TestLoadConfigYAMLRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
	}{
		{"key and keys", "key: {kid: legacy}\nkeys: [{kid: rotated}]\n", "mutually exclusive"},
		{"key and empty keys", "key: {kid: legacy}\nkeys: []\n", "mutually exclusive"},
		{"empty keys", "keys: []\n", "at least one signing key"},
		{"duplicate key IDs", "keys: [{kid: same}, {kid: same}]\n", "duplicate signing kid"},
		{"missing key ID", "keys: [{}]\n", "kid is required"},
		{"missing active key", "active_kid: missing\nkeys: [{kid: present}]\n", "active_kid"},
		{
			"conflicting key sources",
			"key: {private_key_path: ./key.pem, private_key_pem_env: KEY_PEM}\n",
			"mutually exclusive",
		},
		{"zero token limit", "rate_limits: {token: {limit: 0}}\n", "limit must be greater than zero"},
		{"zero readyz limit", "rate_limits: {readyz: {limit: 0}}\n", "limit must be greater than zero"},
		{"empty token window", "rate_limits: {token: {window: ''}}\n", "window must not be empty"},
		{"empty readyz window", "rate_limits: {readyz: {window: ''}}\n", "window must not be empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadConfig(
				writeYAMLConfig(t, ".yaml", "issuer: https://auth.orionis.test\n"+tt.body+yamlTestClients),
			)

			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func TestLoadConfigYAMLRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	const valid = "issuer: https://auth.orionis.test\n" + yamlTestClients
	tests := []struct {
		name string
		raw  string
	}{
		{"malformed", "issuer: [unterminated\n"},
		{"duplicate fields", valid + "issuer: https://other.test\n"},
		{"duplicate nested fields", valid + "rate_limits: {token: {limit: 10, limit: 20}}\n"},
		{"multiple documents", valid + "---\n" + valid},
		{"empty second document", valid + "---\n"},
		{"empty first document", "---\n---\n" + valid},
		{"sequence root", "[one, two]\n"},
		{"scalar root", "text\n"},
		{"string limit", valid + "rate_limits: {token: {limit: '60'}}\n"},
		{"fractional limit", valid + "rate_limits: {token: {limit: 1.5}}\n"},
		{"string enabled", valid + "audit_logs: {enabled: 'false'}\n"},
		{"string boolean shorthand", valid + "audit_logs: {enabled: yes}\n"},
		{"invalid key type", valid + "key: []\n"},
		{"invalid keys type", valid + "keys: {}\n"},
		{"non-string field key", valid + "? [one, two]\n: invalid\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := LoadConfig(writeYAMLConfig(t, ".yml", tt.raw))

			if err == nil || !strings.Contains(err.Error(), "decode config") {
				t.Fatalf("expected a config decoding error, got %v", err)
			}
		})
	}
}

func TestLoadConfigYAMLExampleMatchesJSON(t *testing.T) {
	t.Parallel()

	want, err := LoadConfig(filepath.Join("..", "..", "config", "orionis.example.json"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := LoadConfig(filepath.Join("..", "..", "config", "orionis.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("YAML example differs from JSON example:\ngot:  %+v\nwant: %+v", got, want)
	}
}

func TestLoadConfigDetectsFormatFromContent(t *testing.T) {
	t.Parallel()

	const jsonConfig = `{
  "issuer": "https://auth.orionis.test",
  "key": {"kid": "legacy-key", "private_key_path": "./var/legacy.pem"},
  "clients": [{"id": "orders-service", "secrets": ["secret"],
    "allowed_audiences": ["billing-api"], "allowed_scopes": ["billing.invoice.read"]}]
}`
	const yamlConfig = "issuer: https://auth.orionis.test\nkey: {kid: legacy-key, private_key_path: ./var/legacy.pem}\n" + yamlTestClients
	want, err := LoadConfig(writeConfig(t, jsonConfig))
	if err != nil {
		t.Fatal(err)
	}

	formats := []struct {
		name string
		raw  string
	}{
		{"JSON", jsonConfig},
		{"YAML", yamlConfig},
		{"JSON leading whitespace", " \n\t" + jsonConfig},
		{"YAML leading whitespace", "\n\n" + yamlConfig},
		{"JSON BOM", "\ufeff \n" + jsonConfig},
		{"YAML BOM", "\ufeff" + yamlConfig},
		{"YAML comment and document start", "# Orionis configuration\n---\n" + yamlConfig},
		{
			"YAML flow mapping",
			`{issuer: https://auth.orionis.test, key: {kid: legacy-key, private_key_path: ./var/legacy.pem}, clients: [{id: orders-service, secrets: [secret], allowed_audiences: [billing-api], allowed_scopes: [billing.invoice.read]}]}`,
		},
	}

	for _, format := range formats {
		t.Run(format.name, func(t *testing.T) {
			t.Parallel()

			for _, extension := range []string{".json", ".yaml", ".yml", ".conf", ""} {
				name := extension

				if name == "" {
					name = "extensionless"
				}

				t.Run(name, func(t *testing.T) {
					t.Parallel()

					got, err := LoadConfig(writeYAMLConfig(t, extension, format.raw))
					if err != nil {
						t.Fatal(err)
					}

					if !reflect.DeepEqual(got, want) {
						t.Fatalf("detected configuration differs from JSON:\ngot:  %+v\nwant: %+v", got, want)
					}
				})
			}
		})
	}
}

func TestLoadConfigDetectionRejectsTrailingDocumentsAndJSONTypeErrors(t *testing.T) {
	t.Parallel()

	const jsonConfig = `{"issuer":"https://auth.orionis.test","clients":[{"id":"orders-service","secrets":["secret"],"allowed_audiences":["billing-api"],"allowed_scopes":["billing.invoice.read"]}]}`
	const yamlConfig = "issuer: https://auth.orionis.test\n" + yamlTestClients
	tests := []struct {
		name string
		raw  string
	}{
		{"JSON second object", jsonConfig + "\n{}"},
		{"JSON trailing null", jsonConfig + "\nnull"},
		{"JSON trailing array", jsonConfig + "\n[]"},
		{"YAML second document", yamlConfig + "---\n" + yamlConfig},
		{"YAML trailing empty document", yamlConfig + "---\n"},
		{"JSON float limit", strings.Replace(jsonConfig, "{", `{"rate_limits":{"token":{"limit":1.0}},`, 1)},
		{"JSON string limit", strings.Replace(jsonConfig, "{", `{"rate_limits":{"token":{"limit":"60"}},`, 1)},
		{"JSON string enabled", strings.Replace(jsonConfig, "{", `{"audit_logs":{"enabled":"false"},`, 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, extension := range []string{".json", ".yaml", ""} {
				_, err := LoadConfig(writeYAMLConfig(t, extension, tt.raw))

				if err == nil || !strings.Contains(err.Error(), "decode config") {
					t.Fatalf("extension %q: expected a config decoding error, got %v", extension, err)
				}
			}
		})
	}
}

const yamlTestClients = `clients:
  - id: orders-service
    secrets: [secret]
    allowed_audiences: [billing-api]
    allowed_scopes: [billing.invoice.read]
`

func writeYAMLConfig(t *testing.T, extension, raw string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "orionis"+extension)

	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}
