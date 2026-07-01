package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestLoadConfigParsesValidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orionis.json")
	raw := []byte(`{
		"listen": ":9090",
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

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Listen != ":9090" {
		t.Fatalf("unexpected listen: %q", cfg.Listen)
	}

	if cfg.Issuer != "https://auth.orionis.test" {
		t.Fatalf("unexpected issuer: %q", cfg.Issuer)
	}

	if len(cfg.Clients) != 1 || cfg.Clients[0].ID != "orders-service" {
		t.Fatalf("unexpected clients: %+v", cfg.Clients)
	}
}

func TestLoadConfigRejectsMissingClients(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "orionis.json")
	raw := []byte(`{"issuer":"https://auth.orionis.test"}`)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(path); err == nil {
		t.Fatalf("expected config without clients to be rejected")
	}
}
