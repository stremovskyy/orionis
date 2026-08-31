#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
MIN_PACKAGE_COVERAGE=${MIN_PACKAGE_COVERAGE:-60}
MIN_CORE_COVERAGE=${MIN_CORE_COVERAGE:-70}
GOTOOLCHAIN=go$(awk '/^go / { print $2; exit }' "$ROOT/go.mod")
export GOTOOLCHAIN
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/orionis-coverage.XXXXXX")

cleanup() {
	rm -rf "$TMP_DIR"
}

trap cleanup EXIT HUP INT TERM

coverage_value() {
	go tool cover -func="$1" | awk '/^total:/ {gsub(/%/, "", $3); print $3}'
}

check_minimum() {
	name=$1
	value=$2
	minimum=$3

	awk -v value="$value" -v minimum="$minimum" 'BEGIN { exit !(value + 0 >= minimum + 0) }' || {
		echo "$name coverage ${value}% is below ${minimum}%" >&2
		exit 1
	}
}

cd "$ROOT"

for package in . ./client ./ginorion ./jwk ./server; do
	name=$(printf '%s' "$package" | tr '/.' '__')
	profile="$TMP_DIR/${name}.out"
	go test -count=1 -coverprofile="$profile" "$package"
	value=$(coverage_value "$profile")
	check_minimum "$package" "$value" "$MIN_PACKAGE_COVERAGE"
done

CORE_PACKAGES=$(go list ./... | awk '!/\/examples\// && !/\/cmd\//')
# shellcheck disable=SC2086
go test -count=1 -coverprofile="$TMP_DIR/core.out" $CORE_PACKAGES
core_value=$(coverage_value "$TMP_DIR/core.out")
check_minimum "core" "$core_value" "$MIN_CORE_COVERAGE"

echo "Coverage: public packages >= ${MIN_PACKAGE_COVERAGE}%, core ${core_value}% >= ${MIN_CORE_COVERAGE}%"
