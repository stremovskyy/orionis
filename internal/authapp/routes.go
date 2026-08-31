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

	"github.com/stremovskyy/orionis/internal/authroute"
	"github.com/stremovskyy/orionis/server"
)

func mountAuthRoutes(r *gin.Engine, auth *server.Server, cfg resolvedConfig) {
	security := newRuntimeSecurity(cfg)
	routes := r.Group(cfg.basePath)

	routes.POST(authroute.Token, security.handlers("token", cfg.tokenLimit, gin.WrapF(auth.TokenHTTP))...)
	routes.GET(authroute.JWKS, gin.WrapF(auth.JWKSHTTP))
	routes.GET(authroute.Discovery, gin.WrapF(auth.DiscoveryHTTP))
	routes.GET(authroute.Health, gin.WrapF(auth.HealthHTTP))
	routes.GET(authroute.Ready, security.handlers("readyz", cfg.readyzLimit, gin.WrapF(auth.HealthHTTP))...)
}
