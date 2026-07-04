# Docker and GHCR

Orionis publishes the same auth-server image to Docker Hub and GitHub Container Registry.

## Docker Hub

```bash
docker pull stremovskyy/orionis:latest
```

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  stremovskyy/orionis:latest
```

## GitHub Container Registry

```bash
docker pull ghcr.io/stremovskyy/orionis:latest
```

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  ghcr.io/stremovskyy/orionis:latest
```

## Pinned release

Prefer a pinned tag for shared environments:

```bash
docker pull stremovskyy/orionis:0.1.2
docker pull ghcr.io/stremovskyy/orionis:0.1.2
```

## Health check

```bash
curl -fsS http://localhost:8080/healthz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```
