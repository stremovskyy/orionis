# Orionis architecture

## Core flow

```text
Service A
  -> POST /oauth/token
     grant_type=client_credentials
     audience=service-b-api
     scope=service-b.action
  <- JWT access_token
  -> Service B
     Authorization: Bearer <JWT>

Service B
  -> validates JWT signature via JWKS
  -> validates iss/aud/exp/nbf/token_use/scope
```

## Chain-first integration

The project is optimized around readable integration blocks.

Calling service:

```go
hc, err := client.New().
    TokenURL("http://orionis-auth/oauth/token").
    As("orders-service", secret).
    For("billing-api", "billing.invoice.create").
    BuildHTTPClient(http.DefaultClient)
```

Resource service:

```go
guard, err := ginorion.New().
    Issuer("http://orionis-auth").
    Audience("billing-api").
    JWKS("http://orionis-auth/.well-known/jwks.json").
    Build()

r.POST("/invoices", guard.Require("billing.invoice.create"), handler)
```

Authorization server:

```go
auth, err := server.New().
    Issuer("https://auth.internal").
    Signer(signer).
    Client(server.NewClient("orders-service").
        Secret(secret).
        Audience("billing-api").
        Scope("billing.invoice.create"),
    ).
    Build()
```

## Why local validation

Resource services do not call the authorization server for every request. They fetch JWKS, cache public keys, and validate JWTs locally. This keeps latency low and prevents the authorization server from becoming a runtime bottleneck.

## Why Ed25519 by default

Ed25519 gives compact keys/signatures and fast signing/verification while avoiding large RSA keys. Orionis keeps the signer behind an interface, so RS256, PS256, ES256, KMS-backed signing, or HSM-backed signing can be added without changing resource services.

## Key rotation model

The server supports multiple signers. Publish all public keys through JWKS and choose one active signer for new tokens. Keep old public keys in JWKS until every token signed by the old key has expired.

```text
T0: JWKS = [old], active = old
T1: JWKS = [old, new], active = old
T2: JWKS = [old, new], active = new
T3: after max token TTL + clock skew, JWKS = [new], active = new
```

## Trust boundary

- Authorization server owns private signing keys.
- Resource services only have public keys.
- Calling services only have their own client credentials.
- Access tokens are audience-bound.
- Scopes are service permissions, not user permissions.

## KISS decisions

- `client_secret_basic` is implemented first; `Authenticator` allows `private_key_jwt` or mTLS-specific auth later.
- Ed25519 is the built-in signer; `Signer` interface keeps crypto extensible.
- `MemoryClientStore` is built in; production can replace it with Postgres, DynamoDB, Redis, Vault, or AWS Secrets Manager.
- GIN middleware is a thin wrapper around `orionis.Verifier`; non-GIN services can use the verifier directly.
