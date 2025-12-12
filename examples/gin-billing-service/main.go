package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/stremovskyy/orionis/ginorion"
)

func main() {
	issuer := getenv("ORIONIS_ISSUER", "http://localhost:8080")
	jwksURL := getenv("ORIONIS_JWKS_URL", issuer+"/.well-known/jwks.json")
	audience := getenv("ORIONIS_AUDIENCE", "billing-api")

	guard, err := ginorion.New().
		Issuer(issuer).
		Audience(audience).
		JWKS(jwksURL).
		Build()
	if err != nil {
		slog.Error("create auth guard", "error", err)
		os.Exit(1)
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

	if err := r.Run(listen); err != nil {
		slog.Error("billing demo stopped", "error", err)
		os.Exit(1)
	}
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
