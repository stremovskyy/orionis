#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$repo_root/docs/wiki"
remote="${ORIONIS_WIKI_REMOTE:-git@github.com:stremovskyy/orionis.wiki.git}"

if [ ! -d "$source_dir" ]; then
  echo "missing wiki source directory: $source_dir" >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

if git ls-remote "$remote" >/dev/null 2>&1; then
  git clone "$remote" "$tmp_dir/wiki" >/dev/null
else
  mkdir -p "$tmp_dir/wiki"
  git -C "$tmp_dir/wiki" init -b master >/dev/null
  git -C "$tmp_dir/wiki" remote add origin "$remote"
fi

find "$tmp_dir/wiki" -maxdepth 1 -type f -name '*.md' -delete
cp "$source_dir"/*.md "$tmp_dir/wiki"/

git -C "$tmp_dir/wiki" add .
if git -C "$tmp_dir/wiki" diff --cached --quiet; then
  echo "wiki is already up to date"
  exit 0
fi

git -C "$tmp_dir/wiki" \
  -c user.name="${GIT_AUTHOR_NAME:-Orionis Release Bot}" \
  -c user.email="${GIT_AUTHOR_EMAIL:-actions@users.noreply.github.com}" \
  commit -m "Update Orionis wiki" >/dev/null

git -C "$tmp_dir/wiki" push origin HEAD:master
