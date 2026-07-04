# Docker, GHCR, and AWS ECS

Orionis publishes the same auth-server image to Docker Hub and GitHub Container Registry.

## Docker Hub

```bash
docker pull stremovskyy/orionis:0.2.0
```

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  stremovskyy/orionis:0.2.0
```

## GitHub Container Registry

```bash
docker pull ghcr.io/stremovskyy/orionis:0.2.0
```

```bash
test -f config/orionis.json || cp config/orionis.example.json config/orionis.json

docker run --rm -d \
  --name orionis-auth \
  -p 8080:8080 \
  -v "$PWD/config:/app/config:ro" \
  -v orionis-var:/app/var \
  ghcr.io/stremovskyy/orionis:0.2.0
```

## Pinned release

Prefer a pinned tag for shared environments:

```bash
docker pull stremovskyy/orionis:0.2.0
docker pull ghcr.io/stremovskyy/orionis:0.2.0
```

## AWS ECS Fargate

Use `deploy/aws/ecs/` from the repository to deploy the public image on ECS Fargate.

The task definition template uses:

- `stremovskyy/orionis:0.2.0`
- `awsvpc` networking
- AWS Secrets Manager for `ORIONIS_CONFIG_JSON`
- AWS Secrets Manager secret injection for `ORIONIS_SIGNING_KEY_PEM` and `ORIONIS_SIGNING_KEY_PEM_OLD`
- `/healthz` as the ECS container health check
- `/readyz` as the readiness endpoint
- CloudWatch Logs through `awslogs`

The ECS/Fargate template injects signing keys as environment secrets and does not mount EFS or
write keys to `/app/var`; local Docker examples keep using `/app/var` only for generated demo keys.

## Health check

```bash
curl -fsS http://localhost:8080/healthz
curl -fsS http://localhost:8080/readyz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```
