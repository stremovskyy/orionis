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
