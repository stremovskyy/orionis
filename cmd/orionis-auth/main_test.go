package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
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
