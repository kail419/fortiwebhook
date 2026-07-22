#!/usr/bin/env bash
# Simulate a FortiGate webhook call for testing.
#
#   WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh [url]
#
# Default hits the app directly on :8080 (only works if you exposed that port).
# Through the Caddy proxy with a self-signed internal cert, allow insecure TLS:
#   INSECURE=1 WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh https://127.0.0.1/webhook/fortigate
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/webhook/fortigate}"
TOKEN="${WEBHOOK_TOKEN:-change-me-to-a-long-random-secret}"
CURL_OPTS=(-sS -i)
[ "${INSECURE:-0}" = "1" ] && CURL_OPTS+=(-k)

curl "${CURL_OPTS[@]}" -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: ${TOKEN}" \
  -d '{
        "user": "jdoe",
        "ip": "203.0.113.45",
        "country": "Russian Federation",
        "time": "2026-07-22 09:15:03"
      }'
echo
