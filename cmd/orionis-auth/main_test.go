package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestNewHTTPServerHasProductionTimeouts(t *testing.T) {
	server := newHTTPServer(":0", http.NewServeMux())

	if server.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout must be set")
	}

	if server.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout must be set")
	}

	if server.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout must be set")
	}

	if server.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout must be set")
	}
}

func TestRunHelpExitsSuccessfully(t *testing.T) {
	t.Parallel()

	if err := run(context.Background(), []string{"-h"}); err != nil {
		t.Fatalf("run(-h) = %v, want nil", err)
	}
}

func TestRunRedactsHostedSigningInitializationErrors(t *testing.T) {
	const marker = "UNSET_HOSTED_KEY_REFERENCE"
	const document = `{
		"issuer":"https://auth.example.test",
		"key":{"kid":"test-key","private_key_pem_env":"` + marker + `"},
		"clients":[{"id":"test-client","secrets":["test-secret"],
		"allowed_audiences":["test-api"],"allowed_scopes":["test.read"]}]
	}`
	t.Setenv(marker, "")
	t.Setenv("AWS_REGION", "eu-central-1")
	t.Setenv("AWS_APPCONFIG_APPLICATION", "test-app")
	t.Setenv("AWS_APPCONFIG_ENVIRONMENT", "test-env")
	t.Setenv("AWS_APPCONFIG_PROFILE", "test-profile")
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
	t.Setenv("AWS_SESSION_TOKEN", "")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/configurationsessions" {
			_, _ = w.Write([]byte(`{"InitialConfigurationToken":"test-token"}`))

			return
		}

		_, _ = w.Write([]byte(document))
	}))
	defer srv.Close()

	t.Setenv("AWS_ENDPOINT_URL_APPCONFIGDATA", srv.URL)

	err := run(context.Background(), []string{"-config", "aws"})

	if err == nil || !strings.Contains(err.Error(), "AppConfig") || strings.Contains(err.Error(), marker) {
		t.Fatalf("hosted signing initialization error was not redacted: %v", err)
	}

	path := filepath.Join(t.TempDir(), "config.json")

	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}

	err = run(context.Background(), []string{"-config", path})

	if err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("local signing initialization must retain detailed diagnostics: %v", err)
	}
}

func TestServeHTTPServerStopsOnContextCancel(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := newHTTPServer(listener.Addr().String(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	done := make(chan error, 1)
	go func() {
		done <- serveHTTPServer(ctx, server, time.Second, func() error {
			return server.Serve(listener)
		})
	}()

	client := &http.Client{Timeout: time.Second}

	if _, err := client.Get("http://" + listener.Addr().String()); err != nil {
		t.Fatal(err)
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected graceful shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not stop after context cancellation")
	}
}

func TestConfigureRuntimeModeEnablesGinDebugForDebugLevel(t *testing.T) {
	previous := gin.Mode()
	previousLogger := slog.Default()
	t.Cleanup(func() {
		gin.SetMode(previous)
		slog.SetDefault(previousLogger)
	})

	if _, err := configureRuntimeMode("debug"); err != nil {
		t.Fatal(err)
	}

	if gin.Mode() != gin.DebugMode {
		t.Fatalf("expected debug mode, got %q", gin.Mode())
	}

	if !slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatalf("expected debug logs to be enabled")
	}
}

func TestConfigureRuntimeModeUsesGinReleaseForInfoLevel(t *testing.T) {
	previous := gin.Mode()
	previousLogger := slog.Default()
	t.Cleanup(func() {
		gin.SetMode(previous)
		slog.SetDefault(previousLogger)
	})

	if _, err := configureRuntimeMode("info"); err != nil {
		t.Fatal(err)
	}

	if gin.Mode() != gin.ReleaseMode {
		t.Fatalf("expected release mode, got %q", gin.Mode())
	}

	if slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug) {
		t.Fatalf("expected debug logs to be disabled for info level")
	}
}

func TestConfigureRuntimeModeRejectsInvalidLogLevel(t *testing.T) {
	if _, err := configureRuntimeMode("verbose"); err == nil {
		t.Fatalf("expected invalid log level to be rejected")
	}
}

func TestNewGinEngineSuppressesRequestLogsForInfoLevel(t *testing.T) {
	previousMode := gin.Mode()
	previousWriter := gin.DefaultWriter
	t.Cleanup(func() {
		gin.SetMode(previousMode)
		gin.DefaultWriter = previousWriter
	})

	gin.SetMode(gin.ReleaseMode)
	var logs bytes.Buffer
	gin.DefaultWriter = &logs

	r := newGinEngine(slog.LevelInfo)
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if strings.Contains(logs.String(), "[GIN]") {
		t.Fatalf("expected info level to suppress gin request logs, got %q", logs.String())
	}
}

func TestNewGinEngineEmitsRequestLogsForDebugLevel(t *testing.T) {
	previousMode := gin.Mode()
	previousWriter := gin.DefaultWriter
	t.Cleanup(func() {
		gin.SetMode(previousMode)
		gin.DefaultWriter = previousWriter
	})

	gin.SetMode(gin.DebugMode)
	var logs bytes.Buffer
	gin.DefaultWriter = &logs

	r := newGinEngine(slog.LevelDebug)
	r.GET("/healthz", func(c *gin.Context) { c.Status(http.StatusNoContent) })
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if !strings.Contains(logs.String(), "[GIN]") {
		t.Fatalf("expected debug level to emit gin request logs, got %q", logs.String())
	}
}
