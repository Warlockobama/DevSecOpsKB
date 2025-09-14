#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
export ZAP_API_KEY=${ZAP_API_KEY:-kb-demo-$(date +%s)}
export ZAP_URL=${ZAP_URL:-http://127.0.0.1:8090}

echo "Using ZAP_API_KEY=$ZAP_API_KEY" >&2

echo "Starting containers (ZAP + Juice Shop)…" >&2
docker compose -f "$ROOT_DIR/examples/compose/docker-compose.yml" up -d

echo "Waiting for Juice Shop…" >&2
for i in {1..60}; do
  if curl -fsS http://127.0.0.1:3000 >/dev/null 2>&1; then echo "Juice Shop ready"; break; fi
  sleep 2
done

echo "Waiting for ZAP…" >&2
for i in {1..60}; do
  if curl -fsS "$ZAP_URL/JSON/core/view/version/" >/dev/null 2>&1; then echo "ZAP ready"; break; fi
  sleep 2
done

echo "Running spider + active scan via API…" >&2
TARGET=http://juice-shop:3000 ZAP_URL="$ZAP_URL" ZAP_API_KEY="$ZAP_API_KEY" bash "$ROOT_DIR/zap-kb/scripts/scan-zap.sh"

echo "Building KB artifacts…" >&2
pushd "$ROOT_DIR/zap-kb" >/dev/null
mkdir -p out
RUN_ID=demo-$(date -u +%Y%m%dT%H%M%SZ)
go run ./cmd/zap-kb -format entities -out out/entities.json \
  -zap-url "$ZAP_URL" -api-key "$ZAP_API_KEY" -baseurl http://juice-shop:3000 \
  -include-traffic -traffic-scope first -traffic-max-bytes 2048 \
  -include-detection -detection-details summary \
  -scan-label "$RUN_ID" -site-label "Juice Shop" -zap-base-url "$ZAP_URL" \
  -redact cookies,auth \
  -run-out out/run.json

go run ./cmd/zap-kb -format obsidian -entities-in out/entities.json -obsidian-dir kb-new/obsidian -zap-base-url "$ZAP_URL" -scan-label "$RUN_ID"

go run ./cmd/zap-kb -format both -out out/alerts.json -entities-in out/entities.json -zip-out out/kb.zip || true
popd >/dev/null

echo "Done. Artifacts in zap-kb/out and vault in zap-kb/kb-new/obsidian" >&2
echo "Stop containers with: docker compose -f $ROOT_DIR/examples/compose/docker-compose.yml down" >&2

