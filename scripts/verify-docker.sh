#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
IMAGE=${ORIONIS_VERIFY_IMAGE:-orionis-auth:verify}
COMPOSE_PROJECT_NAME=orionis-verify-$$
export COMPOSE_PROJECT_NAME

cleanup() {
	docker compose down --volumes --remove-orphans >/dev/null 2>&1 || true
}

trap cleanup EXIT HUP INT TERM

cd "$ROOT"
docker compose -f docker-compose.release.yml config --quiet
docker build --pull --no-cache --build-arg TARGET=./cmd/orionis-auth -t "$IMAGE" .
scripts/smoke-release-image.sh "$IMAGE"
docker compose build --pull
docker compose up --wait -d orionis-auth billing-api

discovery=$(docker compose exec -T orionis-auth \
	wget -qO- http://127.0.0.1:8080/.well-known/openid-configuration)

printf '%s' "$discovery" | grep -q '"issuer"'
printf '%s' "$discovery" | grep -q '"token_endpoint"'
printf '%s' "$discovery" | grep -q '"jwks_uri"'

demo=$(docker compose run --rm orders-client)
printf '%s\n' "$demo"
printf '%s\n' "$demo" | grep -q '^status=201$'
