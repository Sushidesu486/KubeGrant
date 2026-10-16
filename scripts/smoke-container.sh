#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
  echo "usage: bash scripts/smoke-container.sh IMAGE" >&2
  exit 2
fi

image=$1
container="kubegrant-smoke-$$"
backup_file=$(mktemp)
cleanup() {
  result=$?
  if (( result != 0 )); then
    docker logs "$container" >&2 2>/dev/null || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -f "$backup_file"
}
trap cleanup EXIT

docker run -d --name "$container" \
  --read-only --user 65532:65532 --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /data:uid=65532,gid=65532,mode=0700 \
  --tmpfs /tmp:uid=65532,gid=65532,mode=0700 \
  -p 127.0.0.1::8080 "$image" >/dev/null
port=$(docker port "$container" 8080/tcp | sed -n 's/^127\.0\.0\.1://p')
[[ "$port" =~ ^[0-9]+$ ]]
base_url="http://127.0.0.1:$port"
curl --retry 15 --retry-connrefused --retry-delay 1 --max-time 3 \
  -fsS "$base_url/livez" >/dev/null
curl --max-time 3 -fsS "$base_url/" | python3 -c \
  'import sys; assert "KubeGrant" in sys.stdin.read()'
curl --max-time 3 -fsS "$base_url/api/v1/status" | python3 -c \
  'import json,sys; s=json.load(sys.stdin); assert s["features"]["login"] is False; assert s["features"]["kubeconfig_download"] is False'
# Authentication is deliberately absent in this isolated container test.
[[ $(curl --max-time 3 -sS -o /dev/null -w '%{http_code}' "$base_url/readyz") == 503 ]]
docker exec "$container" /kubegrant backup --output - > "$backup_file"
python3 - "$backup_file" <<'PY'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as db:
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
PY
docker stop --time 15 "$container" >/dev/null
[[ $(docker inspect --format '{{.State.ExitCode}}' "$container") == 0 ]]
echo "Container smoke passed: static UI, health, disabled login, consistent backup, graceful shutdown."
