#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)

NS=kb-demo
ZAP_SVC=zap
ZAP_PORT_LOCAL=${ZAP_PORT_LOCAL:-8090}
ZAP_URL=http://127.0.0.1:${ZAP_PORT_LOCAL}
ZAP_API_KEY=${ZAP_API_KEY:-kb-demo}

echo "Applying Kubernetes demo manifests…" >&2
kubectl apply -f "$ROOT_DIR/examples/k8s/kb-demo.yaml"

echo "Waiting for deployments to become available…" >&2
kubectl -n "$NS" rollout status deploy/juice-shop --timeout=300s
kubectl -n "$NS" rollout status deploy/zap --timeout=300s

echo "Port-forwarding ZAP API to localhost:${ZAP_PORT_LOCAL}…" >&2
kubectl -n "$NS" port-forward svc/${ZAP_SVC} ${ZAP_PORT_LOCAL}:8090 >/dev/null 2>&1 &
PF_PID=$!
trap 'kill ${PF_PID} 2>/dev/null || true' EXIT

echo "Waiting for ZAP API…" >&2
for i in {1..60}; do
  if curl -fsS "$ZAP_URL/JSON/core/view/version/" >/dev/null 2>&1; then break; fi
  sleep 2
done

echo "Running scan via ZAP API…" >&2
TARGET=http://juice-shop:3000 ZAP_URL="$ZAP_URL" ZAP_API_KEY="$ZAP_API_KEY" bash "$ROOT_DIR/zap-kb/scripts/scan-zap.sh"

echo "Building KB artifacts…" >&2
pushd "$ROOT_DIR/zap-kb" >/dev/null
mkdir -p out
RUN_ID=k8s-$(date -u +%Y%m%dT%H%M%SZ)
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

echo "Artifacts ready:"
echo " - zap-kb/out/run.json"
echo " - zap-kb/out/entities.json"
echo " - zap-kb/out/kb.zip"
echo "Vault: zap-kb/kb-new/obsidian"
echo "Stop demo: kubectl delete -f $ROOT_DIR/examples/k8s/kb-demo.yaml"

