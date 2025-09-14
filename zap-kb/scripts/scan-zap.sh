#!/usr/bin/env bash
set -euo pipefail

# Simple ZAP scan driver using the JSON API.
# Requires: curl, jq, a running ZAP daemon, and the target reachable from the ZAP container.

ZAP_URL=${ZAP_URL:-http://127.0.0.1:8090}
ZAP_API_KEY=${ZAP_API_KEY:-changeme}
TARGET=${TARGET:-http://juice-shop:3000}

curl_json() {
  curl -fsS "$1" | jq -r .
}

echo "ZAP: $ZAP_URL" >&2
echo "Target: $TARGET" >&2

echo "Starting spider…" >&2
SCAN_ID=$(curl -fsS "$ZAP_URL/JSON/spider/action/scan/?apikey=$ZAP_API_KEY&url=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$TARGET")&recurse=true" | jq -r .scan)

for i in $(seq 1 120); do
  pct=$(curl -fsS "$ZAP_URL/JSON/spider/view/status/?scanId=$SCAN_ID" | jq -r .status)
  echo "Spider $pct%" >&2
  [ "$pct" = "100" ] && break
  sleep 2
done

echo "Starting active scan…" >&2
ASCAN_ID=$(curl -fsS "$ZAP_URL/JSON/ascan/action/scan/?apikey=$ZAP_API_KEY&url=$(python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' "$TARGET")&recurse=true&inScopeOnly=false" | jq -r .scan)
for i in $(seq 1 600); do
  pct=$(curl -fsS "$ZAP_URL/JSON/ascan/view/status/?scanId=$ASCAN_ID" | jq -r .status)
  echo "Active scan $pct%" >&2
  [ "$pct" = "100" ] && break
  sleep 5
done

echo "Done." >&2

