#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
GOTOOLCHAIN=$(awk '/^go / { version = "go" $2 } /^toolchain / { version = $2 } END { print version }' "$ROOT/go.mod")
export GOTOOLCHAIN

cd "$ROOT"

go-format --check --progress=false ./...
go mod tidy -diff
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
staticcheck ./...
govulncheck ./...
scripts/check-coverage.sh
scripts/check-api-compat.sh
git diff --check
