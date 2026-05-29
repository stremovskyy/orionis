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
