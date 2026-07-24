#!/usr/bin/env bash
# Simulate a FortiGate webhook call for testing.
#
#   WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh [url]
#
# By default this sends a VPN-login body (routed to the user). To test a
# team-routed event, set EVENT to a catalog key:
#   EVENT=admin-login   WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh [url]
#   EVENT=config-change WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh [url]
#
# Default hits the app directly on :8080 (only works if you exposed that port).
# Through the Caddy proxy with a self-signed internal cert, allow insecure TLS:
#   INSECURE=1 WEBHOOK_TOKEN=xxx ./scripts/send_test_webhook.sh https://127.0.0.1/webhook/fortigate
set -euo pipefail

URL="${1:-http://127.0.0.1:8080/webhook/fortigate}"
TOKEN="${WEBHOOK_TOKEN:-change-me-to-a-long-random-secret}"
CURL_OPTS=(-sS -i)
[ "${INSECURE:-0}" = "1" ] && CURL_OPTS+=(-k)

if [ -n "${EVENT:-}" ]; then
  # A team-routed event (admin/system/threat). Extra fields are shown as-is.
  BODY=$(cat <<JSON
{
  "event": "${EVENT}",
  "devname": "FGT-HQ",
  "admin": "root",
  "srcip": "203.0.113.45",
  "ui": "GUI(203.0.113.45)",
  "action": "edit",
  "cfgpath": "firewall.policy",
  "time": "2026-07-22 09:15:03"
}
JSON
)
else
  # A VPN login (routed to the connecting user via LDAP).
  BODY=$(cat <<JSON
{
  "user": "jdoe",
  "ip": "203.0.113.45",
  "country": "Russian Federation",
  "time": "2026-07-22 09:15:03"
}
JSON
)
fi

curl "${CURL_OPTS[@]}" -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Token: ${TOKEN}" \
  -d "$BODY"
echo
