# Service-to-Service Guide

Orionis models service identity through OAuth 2.0 `client_credentials`.

## Vocabulary

- Caller: the internal service requesting a token.
- Audience: the internal API that will receive the token.
- Scope: the concrete action the caller is allowed to perform.
- Authorization server: Orionis, which authenticates callers and signs JWT access tokens.
- Resource service: the API that validates JWTs locally through JWKS.

## Calling service

```go
hc, err := client.New().
    TokenURL("http://orionis-auth.internal/oauth/token").
    As("orders-service", "load-from-secrets-manager").
    For("billing-api", "billing.invoice.create").
    BuildHTTPClient(http.DefaultClient)
```

The resulting HTTP client adds `Authorization: Bearer <token>` automatically and caches tokens by audience and scope.

## Resource service

```go
guard, err := ginorion.New().
    Issuer("http://orionis-auth.internal").
    Audience("billing-api").
    JWKS("http://orionis-auth.internal/.well-known/jwks.json").
    Build()
```

Use route-level scopes:

```go
r.POST("/invoices", guard.Require("billing.invoice.create"), handler)
```

## Authorization server config

Use generic caller and audience names. Store plaintext secrets outside Git.

```json
{
  "id": "caller-service",
  "secret_sha256_hex": ["<CLIENT_SECRET_SHA>"],
  "allowed_audiences": ["target-api"],
  "allowed_scopes": ["target.read", "target.write"],
  "default_scopes": ["target.read"]
}
```

## Rules of thumb

- Register a service as a client only when it calls another service.
- Register the receiving service name as an audience, not as a client, unless it also calls other services.
- Use narrow scopes for concrete actions.
- Validate `iss`, `aud`, `exp`, `nbf`, signature, `token_use`, and required scopes.
