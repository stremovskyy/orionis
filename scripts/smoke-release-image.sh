#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: scripts/smoke-release-image.sh IMAGE}"

container="orionis-smoke-$RANDOM-$$"
tmpdir="$(mktemp -d)"
config_dir="$tmpdir/config"
var_dir="$tmpdir/var"
mkdir -p "$config_dir" "$var_dir"

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cat > "$config_dir/orionis.json" <<'JSON'
{
  "listen": ":8080",
  "log_level": "info",
  "issuer": "http://localhost:8080",
  "access_token_ttl": "15m",
  "active_kid": "smoke-key-2",
  "keys": [
    {
      "kid": "smoke-key-1",
      "private_key_path": "/app/var/smoke-key-1.pem"
    },
    {
      "kid": "smoke-key-2",
      "private_key_path": "/app/var/smoke-key-2.pem"
    }
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

docker run -d \
  --name "$container" \
  -p 127.0.0.1::8080 \
  -v "$config_dir:/app/config:ro" \
  -v "$var_dir:/app/var" \
  "$image" >/dev/null

port=""
for _ in $(seq 1 30); do
  port="$(docker port "$container" 8080/tcp 2>/dev/null | awk -F: 'END {print $NF}' || true)"
  if [[ -n "$port" ]] && curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if [[ -z "$port" ]]; then
  docker logs "$container" >&2 || true
  echo "orionis smoke: container did not expose a host port" >&2
  exit 1
fi

base_url="http://127.0.0.1:$port"

curl -fsS "$base_url/healthz" >/dev/null
curl -fsS "$base_url/readyz" >/dev/null

jwks_file="$tmpdir/jwks.json"
token_file="$tmpdir/token.json"

curl -fsS "$base_url/.well-known/jwks.json" > "$jwks_file"
python3 - "$jwks_file" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    jwks = json.load(fh)

kids = {key.get("kid") for key in jwks.get("keys", [])}
expected = {"smoke-key-1", "smoke-key-2"}
missing = expected - kids
if missing:
    raise SystemExit(f"missing jwks kids: {sorted(missing)}")
PY

curl -fsS \
  -u "smoke-client:smoke-secret" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "audience=smoke-api" \
  -d "scope=smoke.read" \
  "$base_url/oauth/token" > "$token_file"

python3 - "$token_file" <<'PY'
import base64
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    token_response = json.load(fh)

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

echo "orionis smoke passed for $image"
