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
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/ginorion"
)

func main() {
	if err := run(); err != nil {
		slog.Error("billing demo stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	issuer := getenv("ORIONIS_ISSUER", "http://localhost:8080")
	jwksURL := getenv("ORIONIS_JWKS_URL", issuer+"/.well-known/jwks.json")
	audience := getenv("ORIONIS_AUDIENCE", "billing-api")

	guard, err := ginorion.New().
		Issuer(issuer).
		Audience(audience).
		JWKS(jwksURL).
		Build()
	if err != nil {
		return fmt.Errorf("create auth guard: %w", err)
	}

	r := gin.Default()
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "billing-api"}) })

	r.POST(
		"/invoices",
		guard.Require("billing.invoice.create"),
		func(c *gin.Context) {
			claims := ginorion.MustClaims(c)
			var req struct {
				OrderID string `json:"order_id"`
				Amount  int64  `json:"amount"`
			}

			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "bad_request", "message": err.Error()})

				return
			}

			c.JSON(
				http.StatusCreated, gin.H{
					"invoice_id": "inv_demo_001",
					"order_id":   req.OrderID,
					"amount":     req.Amount,
					"called_by":  claims.ClientID,
					"scope":      claims.Scope,
				},
			)
		},
	)

	listen := getenv("BILLING_LISTEN", ":8081")
	slog.Info("billing demo started", "listen", listen, "issuer", issuer, "audience", audience)

	return r.Run(listen)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
