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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/ginorion"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

const (
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 15 * time.Second
	defaultWriteTimeout      = 15 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultShutdownTimeout   = 10 * time.Second
)

type config struct {
	Listen         string          `json:"listen"`
	LogLevel       string          `json:"log_level"`
	Issuer         string          `json:"issuer"`
	AccessTokenTTL string          `json:"access_token_ttl"`
	Key            keyConfig       `json:"key"`
	Clients        []server.Client `json:"clients"`
}

type keyConfig struct {
	KID            string `json:"kid"`
	PrivateKeyPath string `json:"private_key_path"`
}

func main() {
	cfgPath := flag.String(
		"config",
		getenv("ORIONIS_CONFIG", "config/orionis.example.json"),
		"Path to Orionis JSON config",
	)
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8080"
	}

	ttl, err := parseDurationDefault(cfg.AccessTokenTTL, 15*time.Minute)
	if err != nil {
		slog.Error("parse access token ttl", "error", err)
		os.Exit(1)
	}

	signer, err := jwk.Ed25519().
		Path(expandPath(cfg.Key.PrivateKeyPath)).
		KID(cfg.Key.KID).
		Build()
	if err != nil {
		slog.Error("load signing key", "error", err)
		os.Exit(1)
	}

	auth, err := server.New().
		Issuer(cfg.Issuer).
		AccessTokenTTL(ttl).
		Signer(signer).
		Clients(cfg.Clients...).
		Build()
	if err != nil {
		slog.Error("create auth server", "error", err)
		os.Exit(1)
	}

	level, err := configureRuntimeMode(cfg.LogLevel)
	if err != nil {
		slog.Error("configure runtime mode", "error", err)
		os.Exit(1)
	}

	r := newGinEngine(level)
	ginorion.Auth(auth).Mount(r)

	slog.Info("orionis auth server started", "listen", cfg.Listen, "issuer", cfg.Issuer, "kid", signer.KeyID())

	httpServer := newHTTPServer(cfg.Listen, r)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serveHTTPServer(ctx, httpServer, defaultShutdownTimeout, httpServer.ListenAndServe); err != nil {
		slog.Error("gin server stopped", "error", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (config, error) {
	var cfg config

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

	if strings.TrimSpace(cfg.Issuer) == "" {
		return cfg, errors.New("issuer is required")
	}

	if len(cfg.Clients) == 0 {
		return cfg, errors.New("at least one client is required")
	}

	return cfg, nil
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

func configureRuntimeMode(logLevel string) (slog.Level, error) {
	level, err := parseLogLevel(logLevel)
	if err != nil {
		return slog.LevelInfo, err
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if level <= slog.LevelDebug {
		gin.SetMode(gin.DebugMode)

		return level, nil
	}

	gin.SetMode(gin.ReleaseMode)

	return level, nil
}

func newGinEngine(level slog.Level) *gin.Engine {
	if level <= slog.LevelDebug {
		return gin.Default()
	}

	r := gin.New()
	r.Use(gin.Recovery())

	return r
}

func parseLogLevel(logLevel string) (slog.Level, error) {
	logLevel = strings.TrimSpace(strings.ToLower(logLevel))
	if logLevel == "" {
		return slog.LevelInfo, nil
	}

	switch logLevel {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unsupported log_level %q", logLevel)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
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

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: defaultReadHeaderTimeout,
		ReadTimeout:       defaultReadTimeout,
		WriteTimeout:      defaultWriteTimeout,
		IdleTimeout:       defaultIdleTimeout,
	}
}

func serveHTTPServer(ctx context.Context, server *http.Server, shutdownTimeout time.Duration, serve func() error) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- serve()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}

		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil

	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}
}
