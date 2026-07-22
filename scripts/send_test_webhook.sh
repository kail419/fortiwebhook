#!/usr/bin/env bash
# Simulate a FortiGate webhook call for local testing.
#
#   WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh [url]
#
# Defaults to the local service. Pass a different URL as the first argument.
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/webhook/fortigate}"
TOKEN="${WEBHOOK_TOKEN:-change-me-to-a-long-random-secret}"

curl -sS -i -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: ${TOKEN}" \
  -d '{
        "user": "jdoe",
        "ip": "203.0.113.45",
        "country": "Russian Federation",
        "time": "2026-07-22 09:15:03"
      }'
echo
