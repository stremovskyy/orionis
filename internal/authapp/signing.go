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

package authapp

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stremovskyy/orionis/jwk"
	"github.com/stremovskyy/orionis/server"
)

type SignerLoader interface {
	LoadSigner(KeyConfig) (server.Signer, error)
}

type Ed25519SignerLoader struct{}

func (Ed25519SignerLoader) LoadSigner(cfg KeyConfig) (server.Signer, error) {
	privateKeyPath := strings.TrimSpace(cfg.PrivateKeyPath)
	privateKeyPEMEnv := strings.TrimSpace(cfg.PrivateKeyPEMEnv)

	if privateKeyPath != "" && privateKeyPEMEnv != "" {
		return nil, errors.New("key.private_key_path and key.private_key_pem_env are mutually exclusive")
	}

	if privateKeyPEMEnv == "" {
		return jwk.Ed25519().
			Path(expandPath(privateKeyPath)).
			KID(cfg.KID).
			Build()
	}

	raw := os.Getenv(privateKeyPEMEnv)

	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("key.private_key_pem_env %q is empty or not set", privateKeyPEMEnv)
	}

	return jwk.LoadEd25519SignerPEM([]byte(raw), cfg.KID)
}

func buildServer(cfg Config, loader SignerLoader) (*server.Server, []server.Signer, error) {
	ttl, err := parseDurationDefault(cfg.AccessTokenTTL, 15*time.Minute)
	if err != nil {
		return nil, nil, fmt.Errorf("parse access token ttl: %w", err)
	}

	signers, err := loadSigningKeys(cfg, loader)
	if err != nil {
		return nil, nil, fmt.Errorf("load signing keys: %w", err)
	}

	auth, err := server.New().
		Issuer(cfg.Issuer).
		AccessTokenTTL(ttl).
		Signers(signers...).
		ActiveKID(cfg.ActiveKID).
		Clients(cfg.Clients...).
		Build()
	if err != nil {
		return nil, nil, err
	}

	return auth, signers, nil
}

func loadSigningKeys(cfg Config, loader SignerLoader) ([]server.Signer, error) {
	if loader == nil {
		loader = Ed25519SignerLoader{}
	}

	keyConfigs := cfg.Keys

	if !cfg.keysSet && len(cfg.Keys) == 0 {
		keyConfigs = []KeyConfig{cfg.Key}
	}

	signers := make([]server.Signer, 0, len(keyConfigs))
	seen := make(map[string]struct{}, len(keyConfigs))

	for _, key := range keyConfigs {
		signer, err := loader.LoadSigner(key)
		if err != nil {
			return nil, err
		}

		kid := signer.KeyID()

		if _, ok := seen[kid]; ok {
			return nil, fmt.Errorf("duplicate signing kid %q", kid)
		}

		seen[kid] = struct{}{}
		signers = append(signers, signer)
	}

	if cfg.ActiveKID != "" {
		if _, ok := seen[cfg.ActiveKID]; !ok {
			return nil, fmt.Errorf("active_kid %q does not match a loaded signing key", cfg.ActiveKID)
		}
	}

	return signers, nil
}

func effectiveActiveKID(activeKID string, signers []server.Signer) string {
	if strings.TrimSpace(activeKID) != "" {
		return strings.TrimSpace(activeKID)
	}

	if len(signers) == 0 || signers[0] == nil {
		return ""
	}

	return signers[0].KeyID()
}
