# Orionis

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
  config/orionis.example.json    Local development config
  docs/architecture.md           Architecture notes
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
