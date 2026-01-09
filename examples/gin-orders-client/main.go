package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/stremovskyy/orionis/client"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tokenURL := getenv("ORIONIS_TOKEN_URL", "http://localhost:8080/oauth/token")
	billingURL := getenv("BILLING_URL", "http://localhost:8081/invoices")

	hc, err := client.New().
		TokenURL(tokenURL).
		As(getenv("ORIONIS_CLIENT_ID", "orders-service"), getenv("ORIONIS_CLIENT_SECRET", "orders-local-secret-change-me")).
		For("billing-api", "billing.invoice.create").
		BuildHTTPClient(http.DefaultClient)
	if err != nil {
		slog.Error("create authenticated http client", "error", err)
		os.Exit(1)
	}

	body := bytes.NewBufferString(`{"order_id":"ord_demo_001","amount":1500}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, billingURL, body)
	if err != nil {
		slog.Error("create request", "error", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := hc.Do(req)
	if err != nil {
		slog.Error("call billing", "error", err)
		os.Exit(1)
	}

	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	fmt.Printf("status=%d\n%s\n", res.StatusCode, raw)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}
