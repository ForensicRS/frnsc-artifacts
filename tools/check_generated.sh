#!/usr/bin/env bash
# Fails when src/generated/ is not exactly what tools/gen_catalog.py produces from the pinned
# ForensicArtifacts commit.
#
#   tools/check_generated.sh [path-to-artifacts-checkout]   (default: ../artifacts)
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checkout="${1:-$here/../artifacts}"

pinned="$(sed -n 's/^pub const KB_COMMIT: &str = r"\([0-9a-f]*\)";$/\1/p' "$here/src/generated/mod.rs")"
head="$(git -C "$checkout" rev-parse HEAD)"
if [ "$pinned" != "$head" ]; then
    echo "checkout is at $head, src/generated/ is pinned to $pinned" >&2
    echo "check out $pinned, or regenerate with tools/gen_catalog.py to move the pin" >&2
    exit 1
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
python3 "$here/tools/gen_catalog.py" "$checkout" --out "$tmp" >/dev/null
if ! diff -r "$here/src/generated" "$tmp"; then
    echo "src/generated/ differs from the generator output (see the diff above)" >&2
    exit 1
fi
echo "src/generated/ matches ForensicArtifacts @ ${pinned:0:7}"
