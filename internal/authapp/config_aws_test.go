package authapp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stremovskyy/confucius"
)

const awsTestConfig = `{
	"issuer": "https://auth.example.test/auth",
	"base_path": "/auth",
	"key": {"kid": "production-key", "private_key_pem_env": "ORIONIS_SIGNING_KEY_PEM"},
	"clients": [{"id": "orders-service", "secrets": ["test-secret"],
		"allowed_audiences": ["billing-api"], "allowed_scopes": ["billing.read"]}]
}`

func setAWSConfigTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_REGION", "eu-central-1")
	t.Setenv("AWS_APPCONFIG_APPLICATION", "test-app")
	t.Setenv("AWS_APPCONFIG_ENVIRONMENT", "test-env")
	t.Setenv("AWS_APPCONFIG_PROFILE", "test-profile")
}

func TestLoadConfigContextUsesConfuciusAppConfig(t *testing.T) {
	setAWSConfigTestEnv(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "test-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	var sessions, reads atomic.Int32
	var payload atomic.Value
	payload.Store(awsTestConfig)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/configurationsessions":
			sessions.Add(1)
			var request map[string]any

			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode session request: %v", err)
			}

			for key, want := range map[string]string{
				"ApplicationIdentifier": "test-app", "EnvironmentIdentifier": "test-env",
				"ConfigurationProfileIdentifier": "test-profile",
			} {
				if request[key] != want {
					t.Errorf("%s = %v, want %s", key, request[key], want)
				}
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"InitialConfigurationToken":"test-token"}`))

		case "/configuration":
			reads.Add(1)

			if r.URL.Query().Get("configuration_token") != "test-token" {
				t.Error("configuration session token was not forwarded")
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Next-Poll-Configuration-Token", "next-token")
			_, _ = w.Write([]byte(payload.Load().(string)))

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Setenv("AWS_ENDPOINT_URL_APPCONFIGDATA", srv.URL)

	got, err := LoadConfigContext(context.Background(), "aws")
	if err != nil {
		t.Fatal(err)
	}

	want, err := LoadConfig(writeConfig(t, awsTestConfig))
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatal("AppConfig and local JSON produced different runtime configurations")
	}

	if got.Key.PrivateKeyPEMEnv != "ORIONIS_SIGNING_KEY_PEM" {
		t.Fatal("AppConfig must preserve the injected signing-key environment reference")
	}

	if sessions.Load() != 1 || reads.Load() != 1 {
		t.Fatalf("want one startup fetch; sessions=%d reads=%d", sessions.Load(), reads.Load())
	}

	for _, trailing := range []string{"{}", "null", "[]"} {
		t.Run("trailing "+trailing, func(t *testing.T) {
			document := awsTestConfig + "\n" + trailing
			payload.Store(document)

			if _, err := LoadConfig(writeConfig(t, document)); err == nil {
				t.Fatal("local JSON accepted a trailing document")
			}

			if _, err := LoadConfigContext(context.Background(), "aws"); err == nil {
				t.Fatal("AppConfig JSON accepted a trailing document")
			}
		})
	}
}

func TestAWSConfigRequiresExplicitIdentifiers(t *testing.T) {
	for _, name := range []string{"AWS_APPCONFIG_APPLICATION", "AWS_APPCONFIG_ENVIRONMENT", "AWS_APPCONFIG_PROFILE"} {
		t.Run(name, func(t *testing.T) {
			setAWSConfigTestEnv(t)
			t.Setenv(name, " ")
			_, err := LoadConfigContext(context.Background(), "aws")

			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("expected missing %s, got %v", name, err)
			}
		})
	}
}

func TestAWSConfigRegionFallback(t *testing.T) {
	setAWSConfigTestEnv(t)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "us-east-1")
	options, err := awsConfigOptionsFromEnv()

	if err != nil || options.region != "us-east-1" {
		t.Fatalf("default region resolution failed: %v", err)
	}

	t.Setenv("AWS_DEFAULT_REGION", "")
	options, err = awsConfigOptionsFromEnv()

	if err != nil || options.region != "eu-central-1" {
		t.Fatalf("production region fallback failed: %v", err)
	}
}

func TestAWSConfigPreservesValidationAndRedactsFailures(t *testing.T) {
	setAWSConfigTestEnv(t)

	for name, payload := range map[string]string{
		"malformed":           `{"issuer": "sensitive-hosted-value",`,
		"key conflict":        strings.Replace(awsTestConfig, `"base_path": "/auth",`, `"keys": [],`, 1),
		"explicit zero limit": strings.Replace(awsTestConfig, `"base_path": "/auth",`, `"rate_limits": {"token": {"limit": 0}},`, 1),
		"invalid digest":      strings.Replace(awsTestConfig, `"secrets": ["test-secret"]`, `"secret_sha256_hex": ["sensitive-hosted-value"]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadAWSConfig(context.Background(), func(awsConfigOptions) configLoader {
				return confucius.FromBytes("config.json", []byte(payload))
			})

			if err == nil || !strings.Contains(err.Error(), "AppConfig") {
				t.Fatalf("expected AppConfig failure, got %v", err)
			}

			if strings.Contains(err.Error(), "sensitive-hosted-value") || !reflect.DeepEqual(cfg, Config{}) {
				t.Fatal("failed AppConfig load leaked hosted data")
			}
		})
	}
}

type configLoaderFunc func(context.Context, any) error

func (f configLoaderFunc) Load(ctx context.Context, target any) error { return f(ctx, target) }

func TestAWSConfigBoundsStartupAndPropagatesCancellation(t *testing.T) {
	setAWSConfigTestEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := loadAWSConfig(ctx, func(awsConfigOptions) configLoader {
		return configLoaderFunc(func(ctx context.Context, _ any) error {
			deadline, ok := ctx.Deadline()

			if !ok || time.Until(deadline) > appConfigStartupTimeout {
				t.Error("AppConfig startup must have a bounded deadline")
			}

			if !errors.Is(ctx.Err(), context.Canceled) {
				t.Error("caller cancellation was lost")
			}

			return errors.New("provider-sensitive-value")
		})
	})

	if err == nil || strings.Contains(err.Error(), "provider-sensitive-value") {
		t.Fatalf("provider error was not safely handled: %v", err)
	}
}
