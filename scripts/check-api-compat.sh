#!/bin/sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BASE_REF=${ORIONIS_API_BASE_REF:-v0.3.2}
MODULE=github.com/stremovskyy/orionis
APIDIFF=${APIDIFF:-apidiff}
GOTOOLCHAIN=go$(awk '/^go / { print $2; exit }' "$ROOT/go.mod")
export GOTOOLCHAIN
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/orionis-apidiff.XXXXXX")
OLD_WORKTREE="$TMP_DIR/old"

cleanup() {
	if [ -d "$OLD_WORKTREE/.git" ] || [ -f "$OLD_WORKTREE/.git" ]; then
		git -C "$ROOT" worktree remove --force "$OLD_WORKTREE" >/dev/null 2>&1 || true
	fi

	rm -rf "$TMP_DIR"
}

trap cleanup EXIT HUP INT TERM

command -v "$APIDIFF" >/dev/null 2>&1 || {
	echo "apidiff is required" >&2
	exit 1
}

git -C "$ROOT" rev-parse --verify "$BASE_REF^{commit}" >/dev/null
git -C "$ROOT" worktree add --quiet --detach "$OLD_WORKTREE" "$BASE_REF"

(
	cd "$OLD_WORKTREE"
	"$APIDIFF" -m -w "$TMP_DIR/old.api" "$MODULE"
)

(
	cd "$ROOT"
	"$APIDIFF" -m -w "$TMP_DIR/new.api" "$MODULE"
)

INCOMPATIBLE=$("$APIDIFF" -m -incompatible "$TMP_DIR/old.api" "$TMP_DIR/new.api")

if [ -n "$INCOMPATIBLE" ]; then
	echo "$INCOMPATIBLE" >&2
	exit 1
fi

echo "API compatibility with $BASE_REF: ok"
