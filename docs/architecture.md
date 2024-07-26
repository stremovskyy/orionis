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
