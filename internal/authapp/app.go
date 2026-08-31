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

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/server"
)

type Runtime struct {
	cfg     resolvedConfig
	auth    *server.Server
	signers []server.Signer
}

func New(cfg Config) (*Runtime, error) {
	resolved, err := resolveConfig(cfg)
	if err != nil {
		return nil, err
	}

	return newRuntime(resolved, Ed25519SignerLoader{}.LoadSigner)
}

// SignerLoader is retained for internal source compatibility.
// Deprecated: inject a signer-loading function through newWithSignerLoader.
type SignerLoader interface {
	LoadSigner(KeyConfig) (server.Signer, error)
}

func NewWithSignerLoader(cfg Config, loader SignerLoader) (*Runtime, error) {
	if loader == nil {
		return nil, errors.New("signer loader is required")
	}

	return newWithSignerLoader(cfg, loader.LoadSigner)
}

func newWithSignerLoader(cfg Config, loadSigner signerLoader) (*Runtime, error) {
	resolved, err := compileConfig(cfg)
	if err != nil {
		return nil, err
	}

	return newRuntime(resolved, loadSigner)
}

func newRuntime(resolved resolvedConfig, loadSigner signerLoader) (*Runtime, error) {
	auth, signers, err := buildServer(resolved, loadSigner)
	if err != nil {
		return nil, err
	}

	return &Runtime{cfg: resolved, auth: auth, signers: signers}, nil
}

func (r *Runtime) Mount(routes *gin.Engine) error {
	if r == nil || routes == nil {
		return errors.New("auth runtime and routes are required")
	}

	mountAuthRoutes(routes, r.auth, r.cfg)

	return nil
}

func (r *Runtime) ActiveKID() string {
	return effectiveActiveKID(r.cfg.raw.ActiveKID, r.signers)
}

func (r *Runtime) SignerCount() int {
	return len(r.signers)
}
