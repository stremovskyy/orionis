# Docker, GHCR, and AWS ECS

Orionis publishes the same auth-server image to Docker Hub and GitHub Container Registry.

## Docker Hub

```bash
docker pull stremovskyy/orionis:0.7.0
```

From the repository root, create a YAML config for a fresh installation. Keep
an existing `orionis.json` in place; the image will load it when no YAML config
exists.

```bash
if [ ! -f config/orionis.yaml ] && [ ! -f config/orionis.yml ] && [ ! -f config/orionis.json ]; then
  cp config/orionis.example.yaml config/orionis.yaml
fi

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  stremovskyy/orionis:0.7.0
```

## GitHub Container Registry

The GHCR image has the same default config selection:

```bash
docker pull ghcr.io/stremovskyy/orionis:0.7.0

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  ghcr.io/stremovskyy/orionis:0.7.0
```

Without an explicit source, the image selects `/app/config/orionis.yaml`, then
`orionis.yml`, then legacy `orionis.json`. A selected invalid YAML file causes
startup to fail instead of loading JSON. To select another file or AWS AppConfig,
pass `-config path/to/file` or `-config aws` explicitly.

## Pinned release

Pin a version in shared environments:

```bash
ORIONIS_IMAGE_TAG=0.7.0 docker compose -f docker-compose.release.yml up -d
```

## AWS ECS Fargate

Use `deploy/aws/ecs/` from the repository to deploy the public image on ECS Fargate.
The task definition uses `stremovskyy/orionis:0.7.0`, starts with `-config aws`,
reads the hosted YAML configuration from AppConfig, and injects signing keys
from Secrets Manager. Legacy JSON AppConfig content remains supported. It also
provides `/healthz` and `/readyz` endpoints and sends logs to CloudWatch.

The ECS/Fargate template does not mount EFS or write keys to `/app/var`;
local Docker examples keep using `/app/var` for generated demo keys.

## Health check

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```
