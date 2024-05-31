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
