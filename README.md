# Orionis

[![CI](https://github.com/stremovskyy/orionis/actions/workflows/ci.yml/badge.svg)](https://github.com/stremovskyy/orionis/actions/workflows/ci.yml)
[![Docker Publish](https://github.com/stremovskyy/orionis/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/stremovskyy/orionis/actions/workflows/docker-publish.yml)
[![GitHub Release](https://img.shields.io/github/v/release/stremovskyy/orionis?sort=semver)](https://github.com/stremovskyy/orionis/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/stremovskyy/orionis.svg)](https://pkg.go.dev/github.com/stremovskyy/orionis)
[![Go Report Card](https://goreportcard.com/badge/github.com/stremovskyy/orionis)](https://goreportcard.com/report/github.com/stremovskyy/orionis)
[![Docker Image Version](https://img.shields.io/docker/v/stremovskyy/orionis?sort=semver)](https://hub.docker.com/r/stremovskyy/orionis)
[![Docker Pulls](https://img.shields.io/docker/pulls/stremovskyy/orionis)](https://hub.docker.com/r/stremovskyy/orionis)
[![Docker Image Size](https://img.shields.io/docker/image-size/stremovskyy/orionis/latest)](https://hub.docker.com/r/stremovskyy/orionis)
[![GHCR](https://img.shields.io/badge/ghcr.io-stremovskyy%2Forionis-24292f?logo=github)](https://github.com/stremovskyy/orionis/pkgs/container/orionis)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-0f766e)](https://stremovskyy.github.io/orionis/)
[![Wiki](https://img.shields.io/badge/wiki-Orionis-57636f)](https://github.com/stremovskyy/orionis/wiki)
[![License](https://img.shields.io/github/license/stremovskyy/orionis)](LICENSE)

**Orionis** is a compact Go toolkit and GIN authorization server for service-to-service OAuth 2.0 `client_credentials`, signed JWT access tokens, JWKS validation, token caching, and drop-in GIN middleware.

The API is **chain-first**:

```go
guard, err := ginorion.New().
    Issuer("http://orionis-auth.internal").
    Audience("billing-api").
    JWKS("http://orionis-auth.internal/.well-known/jwks.json").
    Build()
```

The name comes from the Orion constellation: every service is a star, the authorization server is the gravity point, and JWKS is the star map. Slightly dramatic, but better than `jwt-utils-final-final`.

## Repository path

```bash
mkdir -p ~/go/src/github.com/stremovskyy
cd ~/go/src/github.com/stremovskyy
# put this repo here:
# ~/go/src/github.com/stremovskyy/orionis
```

Module:

```go
module github.com/stremovskyy/orionis
```

## What is inside

```text
orionis/
  cmd/orionis-auth/              GIN authorization server
  client/                        OAuth2 client_credentials token provider + HTTP transport
  ginorion/                      GIN middleware + auth route registration
  jwk/                           JWKS types, Ed25519 signer, static/remote key providers
  server/                        OAuth2 token endpoint, JWKS endpoint, client registry
  examples/gin-billing-service/  Protected GIN resource server example
  examples/gin-orders-client/    Client service example that calls billing
  examples/java-orders-client/   Java calling-service example without Maven dependencies
  examples/php-orders-client/    PHP calling-service example without Composer dependencies
  config/orionis.example.json    Local development config
  docs/architecture.md           Architecture notes
  docs/wiki/                     GitHub Wiki source pages
  site/                          Static GitHub Pages site
```

## Design goals

- Chain-first API that is easy to read in existing services.
- KISS defaults: Ed25519, 15-minute token TTL, JWKS cache, Bearer JWT.
- Core packages are framework-agnostic; GIN integration is optional.
- Local JWT validation in resource services through JWKS.
- High-throughput client token cache with in-flight request de-duplication.
- Small interfaces for extension: client registry, signer, key provider, request authenticator, GIN error handler.

## Run locally

Terminal 1: authorization server.

```bash
cd ~/go/src/github.com/stremovskyy/orionis
go run ./cmd/orionis-auth -config ./config/orionis.example.json
```

Terminal 2: protected billing service.

```bash
cd ~/go/src/github.com/stremovskyy/orionis
go run ./examples/gin-billing-service
```

Terminal 3: orders service client.

```bash
cd ~/go/src/github.com/stremovskyy/orionis
go run ./examples/gin-orders-client
```

Expected client output:

```text
status=201
{"amount":1500,"called_by":"orders-service","invoice_id":"inv_demo_001","order_id":"ord_demo_001","scope":"billing.invoice.create"}
```

The Java and PHP examples use the same local auth and billing services. They first request an OAuth2
`client_credentials` access token from Orionis, then call billing with `Authorization: Bearer <token>`.

Run the Java client:

```bash
cd ~/go/src/github.com/stremovskyy/orionis
make run-java-client
```

Run the PHP client when PHP is installed locally:

```bash
cd ~/go/src/github.com/stremovskyy/orionis
make run-php-client
```

If PHP is not installed locally, run the example through Docker:

```bash
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -v "$PWD:/work" \
  -w /work \
  -e ORIONIS_TOKEN_URL=http://host.docker.internal:8080/oauth/token \
  -e BILLING_URL=http://host.docker.internal:8081/invoices \
  php:8.4-cli php examples/php-orders-client/orders_client.php
```

Both examples accept these environment variables:

```text
ORIONIS_TOKEN_URL      default: http://localhost:8080/oauth/token
BILLING_URL            default: http://localhost:8081/invoices
ORIONIS_CLIENT_ID      default: orders-service
ORIONIS_CLIENT_SECRET  default: orders-local-secret-change-me
ORIONIS_AUDIENCE       default: billing-api
ORIONIS_SCOPE          default: billing.invoice.create
```

## Run with Docker

Pull the published auth server image from Docker Hub:

```bash
docker pull stremovskyy/orionis:latest
```

Or pull the GitHub Packages mirror from GitHub Container Registry:

```bash
docker pull ghcr.io/stremovskyy/orionis:latest
```

Run Orionis from the published image:

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  stremovskyy/orionis:latest
```

Or use the release Compose file:

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

ORIONIS_IMAGE_TAG=latest docker compose -f docker-compose.release.yml up -d
curl -fsS http://localhost:8080/healthz
```

Pin a released image in deployed environments:

```bash
ORIONIS_IMAGE_TAG=0.1.2 docker compose -f docker-compose.release.yml up -d
```

The published image expects its config at `/app/config/orionis.json` by default.
Mount the config read-only, mount `/app/var` as persistent storage for the Ed25519 signing key,
replace demo secrets before sharing an environment, and prefer `secret_sha256_hex` over plaintext
secrets in deployed configs.

The GitHub Container Registry image uses the same tags as Docker Hub:

```bash
docker pull ghcr.io/stremovskyy/orionis:0.1.2

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  ghcr.io/stremovskyy/orionis:0.1.2
```

Build the auth server image:

```bash
docker build --build-arg TARGET=./cmd/orionis-auth -t orionis-auth:local .
```

Run the local auth and billing demo stack:

```bash
docker compose up --build --wait -d orionis-auth billing-api
```

Run the orders demo client against the Compose network:

```bash
docker compose run --rm orders-client
```

Expected client output:

```text
status=201
{"amount":1500,"called_by":"orders-service","invoice_id":"inv_demo_001","order_id":"ord_demo_001","scope":"billing.invoice.create"}
```

Stop the stack without deleting the generated signing key:

```bash
docker compose down --remove-orphans
```

The Compose stack mounts `config/` read-only and stores the local Ed25519 private key in the `orionis-var` named volume at `/app/var/orionis-ed25519.pem`. The existing signer loader creates that key on first start when it does not exist. Use `docker compose down -v` only when you intentionally want to delete the local demo key.

The Dockerfile builds `./cmd/orionis-auth` by default. To package another main package, override `TARGET`:

```bash
docker build --build-arg TARGET=./examples/gin-billing-service -t orionis-billing-demo:local .
```

## Manual token request

```bash
curl -s \
  -u 'orders-service:orders-local-secret-change-me' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'audience=billing-api' \
  -d 'scope=billing.invoice.create' \
  http://localhost:8080/oauth/token | jq
```

Response:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIsImtpZCI6Im9yaW9uaXMtbG9jYWwtZWQyNTUxOS0x...",
  "token_type": "Bearer",
  "expires_in": 900,
  "scope": "billing.invoice.create"
}
```

JWKS:

```bash
curl -s http://localhost:8080/.well-known/jwks.json | jq
```

---

# Chain API cookbook

## 1. Calling service: add JWT automatically to outgoing HTTP requests

```go
package orders

import (
    "net/http"

    "github.com/stremovskyy/orionis/client"
)

func BillingHTTPClient() (*http.Client, error) {
    return client.New().
        TokenURL("http://orionis-auth.internal/oauth/token").
        As("orders-service", "load-from-secrets-manager").
        For("billing-api", "billing.invoice.create").
        BuildHTTPClient(http.DefaultClient)
}
```

Usage:

```go
hc, _ := BillingHTTPClient()
req, _ := http.NewRequest("POST", "http://billing.internal/invoices", body)
req.Header.Set("Content-Type", "application/json")

res, err := hc.Do(req) // Authorization: Bearer <token> is added automatically
```

The provider caches tokens by `audience + scopes`, refreshes before expiration, and shares one token acquisition between concurrent goroutines.

## 2. Calling service: reuse one provider for several targets

```go
provider, err := client.New().
    TokenURL("http://orionis-auth.internal/oauth/token").
    As("orders-service", "load-from-secrets-manager").
    Build()
if err != nil {
    return err
}

billingHTTP := provider.
    For("billing-api", "billing.invoice.create").
    HTTPClient(http.DefaultClient)

dispatchHTTP := provider.
    For("dispatch-api", "dispatch.order.read").
    HTTPClient(http.DefaultClient)
```

## 3. GIN resource service: protect routes through JWKS

```go
package billing

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/stremovskyy/orionis/ginorion"
)

func Router() (*gin.Engine, error) {
    guard, err := ginorion.New().
        Issuer("http://orionis-auth.internal").
        Audience("billing-api").
        JWKS("http://orionis-auth.internal/.well-known/jwks.json").
        Build()
    if err != nil {
        return nil, err
    }

    r := gin.Default()

    r.POST("/invoices",
        guard.Require("billing.invoice.create"),
        func(c *gin.Context) {
            claims := ginorion.MustClaims(c)
            c.JSON(http.StatusCreated, gin.H{
                "created_by_service": claims.ClientID,
            })
        },
    )

    return r, nil
}
```

## 4. GIN resource service: custom verifier

```go
provider, _ := jwk.Remote("http://orionis-auth.internal/.well-known/jwks.json").Build()

verifier := orionis.NewVerifier().
    Issuer("http://orionis-auth.internal").
    Audience("billing-api").
    Keys(provider)

guard, _ := ginorion.New().
    Verifier(verifier).
    Build()
```

## 5. Authorization server inside an existing GIN app

```go
signer, _ := jwk.Ed25519().
    Path("/run/secrets/orionis-ed25519.pem").
    KID("orionis-prod-ed25519-1").
    Build()

auth, _ := server.New().
    Issuer("https://auth.internal.example.local").
    AccessTokenTTL(15 * time.Minute).
    Signer(signer).
    Client(server.NewClient("orders-service").
        Secret("load-from-secrets-manager").
        Audience("billing-api").
        Scopes("billing.invoice.create", "billing.invoice.read").
        Defaults("billing.invoice.read"),
    ).
    Build()

r := gin.Default()
ginorion.Auth(auth).Mount(r)
```

Registered endpoints:

```text
POST /oauth/token
GET  /.well-known/jwks.json
GET  /.well-known/openid-configuration
GET  /healthz
```

## 6. Static public key instead of remote JWKS

Useful for tests or very small deployments.

```go
provider, _ := jwk.Static(signer.PublicJWK()).Build()

verifier := orionis.NewVerifier().
    Issuer("http://localhost:8080").
    Audience("billing-api").
    Keys(provider)
```

---

# JWT payload example

```json
{
  "iss": "http://localhost:8080",
  "sub": "orders-service",
  "aud": ["billing-api"],
  "exp": 1782900900,
  "nbf": 1782900000,
  "iat": 1782900000,
  "jti": "0rYF8M77WyGLUuk0TwvT8A",
  "client_id": "orders-service",
  "scope": "billing.invoice.create",
  "token_use": "access"
}
```

# Configuration example

```json
{
  "listen": ":8080",
  "log_level": "info",
  "issuer": "http://localhost:8080",
  "access_token_ttl": "15m",
  "key": {
    "kid": "orionis-local-ed25519-1",
    "private_key_path": "./var/orionis-ed25519.pem"
  },
  "clients": [
    {
      "id": "orders-service",
      "secrets": ["orders-local-secret-change-me"],
      "allowed_audiences": ["billing-api"],
      "allowed_scopes": ["billing.invoice.create", "billing.invoice.read"],
      "default_scopes": ["billing.invoice.read"]
    }
  ]
}
```

## Production-style service-to-service config

Use this pattern when one internal service needs access to another internal service.
The caller is the OAuth client. The receiver is the audience. Scopes describe the allowed actions.

Do not put plaintext client secrets in the JSON config for shared or deployed environments.
Store only `secret_sha256_hex` in Orionis config and keep the plaintext secret in your secret manager or a local, untracked env file.

Create a client secret and hash it:

```bash
CLIENT_SECRET="$(openssl rand -base64 32)"
CLIENT_SECRET_SHA="$(printf '%s' "$CLIENT_SECRET" | openssl dgst -sha256 -r | awk '{print $1}')"

mkdir -p ./secrets
printf 'ORIONIS_CALLER_SERVICE_CLIENT_SECRET=%s\n' "$CLIENT_SECRET" >> ./secrets/client-secrets.env
chmod 600 ./secrets/client-secrets.env
```

Add the caller service to the auth server config:

```json
{
  "listen": ":8080",
  "log_level": "info",
  "issuer": "https://auth.example.internal",
  "access_token_ttl": "15m",
  "key": {
    "kid": "orionis-dev-ed25519-1",
    "private_key_path": "/app/var/orionis-ed25519.pem"
  },
  "clients": [
    {
      "id": "caller-service",
      "secret_sha256_hex": ["<CLIENT_SECRET_SHA>"],
      "allowed_audiences": ["target-api"],
      "allowed_scopes": [
        "target.read",
        "target.write"
      ],
      "default_scopes": ["target.read"]
    }
  ]
}
```

Request a token from the calling service:

```bash
set -eu
. ./secrets/client-secrets.env

curl -fsS \
  -u "caller-service:${ORIONIS_CALLER_SERVICE_CLIENT_SECRET}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'audience=target-api' \
  -d 'scope=target.write' \
  https://auth.example.internal/oauth/token | jq
```

Configure the receiving service to validate that token:

```bash
ORIONIS_ISSUER=https://auth.example.internal
ORIONIS_AUDIENCE=target-api
ORIONIS_JWKS_URL=https://auth.example.internal/.well-known/jwks.json
```

Protect a GIN route in the receiving service:

```go
guard, err := ginorion.New().
    Issuer(os.Getenv("ORIONIS_ISSUER")).
    Audience(os.Getenv("ORIONIS_AUDIENCE")).
    JWKS(os.Getenv("ORIONIS_JWKS_URL")).
    Build()
if err != nil {
    return err
}

r.POST("/internal/action",
    guard.Require("target.write"),
    func(c *gin.Context) {
        claims := ginorion.MustClaims(c)
        c.JSON(http.StatusOK, gin.H{"called_by": claims.ClientID})
    },
)
```

Rules of thumb:

- Register a service as a client only when it calls another service.
- Register the receiving service name as an audience, not as a client, unless it also calls other services.
- Use narrow scopes for concrete actions instead of broad names like `admin` or `full_access`.
- Keep example names, domains, hashes, and secrets as placeholders in documentation.

# Extension points

## Custom client registry

Implement `server.ClientStore`:

```go
type ClientStore interface {
    FindClient(ctx context.Context, id string) (server.Client, error)
}
```

Then wire it:

```go
auth, _ := server.New().
    Issuer("https://auth.internal").
    Signer(signer).
    Store(myPostgresClientStore).
    Build()
```

## Custom signer

Implement `server.Signer`:

```go
type Signer interface {
    KeyID() string
    Algorithm() string
    Sign(claims *orionis.Claims) (string, error)
    PublicJWK() jwk.Key
}
```

That allows RS256, PS256, ES256, AWS KMS, Vault Transit, or HSM-backed signing without changing clients or resource services.

## Custom GIN error response

```go
guard, _ := ginorion.New().
    Issuer(issuer).
    Audience("billing-api").
    JWKS(jwksURL).
    ErrorHandler(func(c *gin.Context, status int, code string, err error) {
        c.JSON(status, gin.H{"code": code})
    }).
    Build()
```

## Custom token request authentication

```go
provider, _ := client.New().
    TokenURL("https://auth.internal/oauth/token").
    Authenticator(myPrivateKeyJWTAuthenticator).
    For("billing-api", "billing.invoice.create").
    Build()
```

# Security notes

- Use short access token TTLs: 5–15 minutes is usually a good service-token range.
- Store client secrets and private keys outside Git.
- Prefer one `client_id` per service.
- Always validate `iss`, `aud`, `exp`, `nbf`, signature, `token_use`, and required scopes.
- Do not reuse a token minted for `billing-api` against another audience.
- For production, add rate limiting and audit logs around `/oauth/token`.
- For stronger service identity, add mTLS or SPIFFE/SPIRE alongside JWT scopes.

# Tests

```bash
go test ./...
```

# Suggested production topology

```text
orders-service
  client.Provider
  client.Transport
       |
       | POST /oauth/token, Basic Auth, client_credentials
       v
orionis-auth
  /oauth/token
  /.well-known/jwks.json
       |
       | JWT access token
       v
billing-service
  ginorion.Guard
  orionis.Verifier
  jwk.RemoteProvider
```

# Package summary

| Package | Purpose |
|---|---|
| `orionis` | Claims, verifier, token response, scope helpers |
| `client` | Chain builder, token provider, cache, HTTP transport |
| `server` | Chain builder, OAuth token endpoint, JWKS endpoint, client store |
| `jwk` | Chain builders for JWKS providers and Ed25519 signer |
| `ginorion` | Chain builder for GIN guards and auth route mounting |
