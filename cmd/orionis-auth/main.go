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
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/internal/authapp"
)

func main() {
	cfgPath := flag.String(
		"config",
		getenv("ORIONIS_CONFIG", "config/orionis.example.json"),
		"Path to Orionis JSON config",
	)
	flag.Parse()

	cfg, err := authapp.LoadConfig(*cfgPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
	}

	runtime, err := authapp.New(cfg)
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

	if err := runtime.Mount(r); err != nil {
		slog.Error("mount auth routes", "error", err)
		os.Exit(1)
	}

	slog.Info(
		"orionis auth server started",
		"listen", cfg.ListenAddr(),
		"issuer", cfg.Issuer,
		"active_kid", runtime.ActiveKID(),
		"signer_count", runtime.SignerCount(),
	)

	httpServer := newHTTPServer(cfg.ListenAddr(), r)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := serveHTTPServer(ctx, httpServer, defaultShutdownTimeout, httpServer.ListenAndServe); err != nil {
		slog.Error("gin server stopped", "error", err)
		os.Exit(1)
	}
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
