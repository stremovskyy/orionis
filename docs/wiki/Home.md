# Orionis

Orionis is a compact Go toolkit and GIN authorization server for service-to-service OAuth 2.0 `client_credentials`, signed JWT access tokens, JWKS validation, token caching, and drop-in GIN middleware.

## Start here

- [Quick Start](Quick-Start): run the local auth server, billing API, and client examples.
- [Docker, GHCR, and AWS ECS](Docker-and-GHCR): deploy from Docker Hub, GitHub Container Registry, or ECS Fargate.
- [Service-to-Service Guide](Service-to-Service-Guide): model callers, audiences, and scopes.
- [Production Security](Production-Security): keep secrets, keys, logs, and token boundaries safe.

## Public resources

- Repository: https://github.com/stremovskyy/orionis
- GitHub Pages: https://stremovskyy.github.io/orionis/
- Docker Hub: https://hub.docker.com/r/stremovskyy/orionis
- GitHub Packages: https://github.com/stremovskyy/orionis/pkgs/container/orionis
- Go Reference: https://pkg.go.dev/github.com/stremovskyy/orionis

## Core endpoints

```text
POST /oauth/token
GET  /.well-known/jwks.json
GET  /.well-known/openid-configuration
GET  /healthz
GET  /readyz
```

## Supported package surfaces

```bash
docker pull stremovskyy/orionis:0.2.0
docker pull ghcr.io/stremovskyy/orionis:0.2.0
go get github.com/stremovskyy/orionis
```

AWS ECS/Fargate templates live in `deploy/aws/ecs/`.
