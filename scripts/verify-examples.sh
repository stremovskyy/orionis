#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GOTOOLCHAIN=go$(awk '/^go / { print $2; exit }' "$ROOT/go.mod")
export GOTOOLCHAIN
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/orionis-examples.XXXXXX")

cleanup() {
	rm -rf "$TMP_DIR"
}

trap cleanup EXIT HUP INT TERM

cd "$ROOT"
go build ./...
javac --release 11 -d "$TMP_DIR/java" examples/java-orders-client/OrdersClient.java
docker run --rm -v "$ROOT:/src:ro" -w /src php:8.4-cli \
	php -l examples/php-orders-client/orders_client.php
