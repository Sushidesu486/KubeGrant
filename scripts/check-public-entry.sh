#!/usr/bin/env bash
set -euo pipefail

if (( $# > 1 )); then
  echo 'usage: bash scripts/check-public-entry.sh [HTTPS_ORIGIN]' >&2
  exit 2
fi
origin=${1:-https://kubegrant.clusters.zjusct.io}
origin=${origin%/}
[[ "$origin" == https://* ]]
page=$(mktemp)
trap 'rm -f "$page"' EXIT
# Check the actual external front door without a cached gateway login or proxy.
status=$(curl --noproxy '*' --max-time 10 --silent --show-error \
  -o "$page" -w '%{http_code}' "$origin/")
python3 - "$status" "$page" <<'PY'
import pathlib
import sys

body = pathlib.Path(sys.argv[2]).read_text(errors="replace")
if sys.argv[1] != "200" or "KubeGrant" not in body:
    raise SystemExit("FAIL: external entry did not serve KubeGrant login; HTTP " + sys.argv[1])
print("PASS: external HTTPS serves KubeGrant login")
PY
