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
	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/server"
)

type Runtime struct {
	cfg     Config
	auth    *server.Server
	signers []server.Signer
}

func New(cfg Config) (*Runtime, error) {
	return NewWithSignerLoader(cfg, Ed25519SignerLoader{})
}

func NewWithSignerLoader(cfg Config, loader SignerLoader) (*Runtime, error) {
	auth, signers, err := buildServer(cfg, loader)
	if err != nil {
		return nil, err
	}

	return &Runtime{cfg: cfg, auth: auth, signers: signers}, nil
}

func (r *Runtime) Mount(routes *gin.Engine) error {
	return mountAuthRoutes(routes, r.auth, r.cfg)
}

func (r *Runtime) ActiveKID() string {
	return effectiveActiveKID(r.cfg.ActiveKID, r.signers)
}

func (r *Runtime) SignerCount() int {
	return len(r.signers)
}
