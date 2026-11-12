#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: scripts/smoke-release-image.sh IMAGE}"
container_prefix="orionis-smoke-$RANDOM-$$"
tmpdir="$(mktemp -d)"
containers=()

cleanup() {
  for container in "${containers[@]}"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cat > "$tmpdir/orionis.yaml" <<'YAML'
listen: ":8080"
log_level: info
issuer: http://localhost:8080
access_token_ttl: "15m"
active_kid: smoke-key-2
keys:
  - kid: smoke-key-1
    private_key_path: /app/var/smoke-key-1.pem
  - kid: smoke-key-2
    private_key_path: /app/var/smoke-key-2.pem
rate_limits:
  token: {enabled: true, limit: 60, window: "1m"}
  readyz: {enabled: true, limit: 300, window: "1m"}
audit_logs: {enabled: true}
clients:
  - id: smoke-client
    secrets: [smoke-secret]
    allowed_audiences: [smoke-api]
    allowed_scopes: [smoke.read]
    default_scopes: [smoke.read]
YAML

cat > "$tmpdir/orionis.json" <<'JSON'
{
  "listen": ":8080",
  "log_level": "info",
  "issuer": "http://legacy.localhost:8080",
  "access_token_ttl": "15m",
  "active_kid": "smoke-key-2",
  "keys": [
    {"kid": "smoke-key-1", "private_key_path": "/app/var/smoke-key-1.pem"},
    {"kid": "smoke-key-2", "private_key_path": "/app/var/smoke-key-2.pem"}
  ],
  "rate_limits": {
    "token": {"enabled": true, "limit": 60, "window": "1m"},
    "readyz": {"enabled": true, "limit": 300, "window": "1m"}
  },
  "audit_logs": {"enabled": true},
  "clients": [
    {
      "id": "smoke-client",
      "secrets": ["smoke-secret"],
      "allowed_audiences": ["smoke-api"],
      "allowed_scopes": ["smoke.read"],
      "default_scopes": ["smoke.read"]
    }
  ]
}
JSON

run_case() {
  local scenario="$1"
  local expected_issuer="$2"
  local include_yaml="$3"
  local include_json="$4"
  local config_dir="$tmpdir/$scenario/config"
  local var_dir="$tmpdir/$scenario/var"
  local container="$container_prefix-$scenario"
  local port=""
  local base_url

  mkdir -p "$config_dir" "$var_dir"
  chmod 0777 "$var_dir"
  if [[ "$include_yaml" == yes ]]; then
    cp "$tmpdir/orionis.yaml" "$config_dir/orionis.yaml"
  fi
  if [[ "$include_json" == yes ]]; then
    cp "$tmpdir/orionis.json" "$config_dir/orionis.json"
  fi

  containers+=("$container")
  docker run -d \
    --name "$container" \
    -p 127.0.0.1::8080 \
    -v "$config_dir:/app/config:ro" \
    -v "$var_dir:/app/var" \
    "$image" >/dev/null

  for _ in $(seq 1 30); do
    port="$(docker port "$container" 8080/tcp 2>/dev/null | awk -F: 'END {print $NF}' || true)"
    if [[ -n "$port" ]] && curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
      break
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" == false ]]; then
      break
    fi
    sleep 1
  done

  if [[ -z "$port" ]] || ! curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    docker logs "$container" >&2 || true
    echo "orionis smoke: $scenario did not become healthy" >&2
    exit 1
  fi

  base_url="http://127.0.0.1:$port"
  curl -fsS "$base_url/readyz" >/dev/null
  curl -fsS "$base_url/.well-known/jwks.json" > "$tmpdir/$scenario/jwks.json"
  curl -fsS "$base_url/.well-known/openid-configuration" > "$tmpdir/$scenario/discovery.json"
  curl -fsS \
    -u "smoke-client:smoke-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "audience=smoke-api" \
    -d "scope=smoke.read" \
    "$base_url/oauth/token" > "$tmpdir/$scenario/token.json"

  python3 - "$tmpdir/$scenario/discovery.json" "$tmpdir/$scenario/jwks.json" "$tmpdir/$scenario/token.json" "$expected_issuer" <<'PY'
import base64
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    discovery = json.load(fh)
with open(sys.argv[2], encoding="utf-8") as fh:
    jwks = json.load(fh)
with open(sys.argv[3], encoding="utf-8") as fh:
    token_response = json.load(fh)

issuer = sys.argv[4]
expected = {
    "issuer": issuer,
    "token_endpoint": issuer + "/oauth/token",
    "jwks_uri": issuer + "/.well-known/jwks.json",
}
for field, value in expected.items():
    if discovery.get(field) != value:
        raise SystemExit(f"unexpected {field}: {discovery.get(field)!r}")

kids = {key.get("kid") for key in jwks.get("keys", [])}
missing = {"smoke-key-1", "smoke-key-2"} - kids
if missing:
    raise SystemExit(f"missing jwks kids: {sorted(missing)}")

token = token_response.get("access_token")
if not token:
    raise SystemExit("missing access_token")
header_segment = token.split(".", 1)[0]
padding = "=" * (-len(header_segment) % 4)
header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
if header.get("kid") != "smoke-key-2":
    raise SystemExit(f"unexpected token kid: {header.get('kid')}")
if token_response.get("token_type") != "Bearer":
    raise SystemExit(f"unexpected token_type: {token_response.get('token_type')}")
PY

  docker rm -f "$container" >/dev/null
  echo "orionis smoke passed: $scenario"
}

run_case yaml-only http://localhost:8080 yes no
run_case json-only http://legacy.localhost:8080 no yes
run_case yaml-preferred http://localhost:8080 yes yes

echo "orionis smoke passed for $image"
