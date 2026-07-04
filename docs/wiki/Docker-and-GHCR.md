# Docker, GHCR, and AWS ECS

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
docker pull stremovskyy/orionis:0.1.3
docker pull ghcr.io/stremovskyy/orionis:0.1.3
```

## AWS ECS Fargate

Use `deploy/aws/ecs/` from the repository to deploy the public image on ECS Fargate.

The task definition template uses:

- `stremovskyy/orionis:0.1.3`
- `awsvpc` networking
- AWS Secrets Manager for `ORIONIS_CONFIG_JSON`
- AWS Secrets Manager secret injection for `ORIONIS_SIGNING_KEY_PEM`
- `/healthz` as the ECS container health check
- CloudWatch Logs through `awslogs`

The ECS/Fargate template injects the signing key as an environment secret and does not mount EFS or
write the key to `/app/var`; local Docker examples keep using `/app/var` only for generated demo keys.

## Health check

```bash
curl -fsS http://localhost:8080/healthz
```

Expected response:

```json
{"service":"orionis-auth","status":"ok"}
```
