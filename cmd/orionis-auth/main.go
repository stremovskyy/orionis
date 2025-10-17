package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/ginorion"
	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

type config struct {
	Listen         string          `json:"listen"`
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

	r := gin.Default()
	ginorion.Auth(auth).Mount(r)

	slog.Info("orionis auth server started", "listen", cfg.Listen, "issuer", cfg.Issuer, "kid", signer.KeyID())

	if err := r.Run(cfg.Listen); err != nil {
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
