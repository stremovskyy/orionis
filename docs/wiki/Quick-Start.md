# Quick Start

## Run from source

Terminal 1: authorization server.

```bash
go run ./cmd/orionis-auth -config ./config/orionis.example.json
```

Terminal 2: protected billing service.

```bash
go run ./examples/gin-billing-service
```

Terminal 3: orders client.

```bash
go run ./examples/gin-orders-client
```

Expected output:

```text
status=201
{"amount":1500,"called_by":"orders-service","invoice_id":"inv_demo_001","order_id":"ord_demo_001","scope":"billing.invoice.create"}
```

## Run with Docker Compose

```bash
docker compose up --build --wait -d orionis-auth billing-api
docker compose run --rm orders-client
docker compose down --remove-orphans
```

Do not use `docker compose down -v` unless you intentionally want to delete the generated local signing key stored in the `orionis-var` volume.

## Check health and readiness

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

## Request a token manually

```bash
curl -s \
  -u 'orders-service:orders-local-secret-change-me' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'audience=billing-api' \
  -d 'scope=billing.invoice.create' \
  http://localhost:8080/oauth/token | jq
```

## Validate JWKS

```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq
```
