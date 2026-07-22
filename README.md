# IPsecAlert

External webhook service for **FortiGate Automation**. FortiGate cannot turn the
`%%user%%` log variable into a mailbox on its own, so this service does it:

```
FortiGate (IPsec/VPN event)
   └─▶ Automation ▸ Action: Webhook  ──POST JSON──▶  IPsecAlert
                                                        │ 1. verify shared token
                                                        │ 2. resolve %%user%% → e-mail (LDAP/AD)
                                                        │ 3. send bilingual alert (SMTP)
                                                        ▼
                                              當事人 (the connecting user)
```

Runs as an always-on container on a Linux host. Python + Flask, `ldap3` for the
directory lookup, stdlib `smtplib` for mail, served by gunicorn.

---

## 1. Quick start

```bash
cp .env.example .env
# edit .env: WEBHOOK_TOKEN, LDAP_*, SMTP_*, MAIL_FROM  (see the file's comments)

docker compose up -d --build
docker compose logs -f
```

Check it is alive:

```bash
curl http://<host>:8080/health
# {"status":"ok","missing_config":[]}   <- missing_config must be empty
```

Send a test event (uses `$WEBHOOK_TOKEN` from your shell):

```bash
WEBHOOK_TOKEN=$(grep ^WEBHOOK_TOKEN= .env | cut -d= -f2) ./scripts/send_test_webhook.sh
```

---

## 2. FortiGate configuration

### 2a. Trigger — decide *when* to fire
`Security Fabric ▸ Automation ▸ Trigger`. Create a **FortiOS Event Log** (or
log-based) trigger that matches the events you care about — typically an IPsec
VPN tunnel/user coming up from a foreign `srccountry`. Add a filter so it only
fires on the countries/events you want. (IPsecAlert also has an
`IGNORE_COUNTRIES` safety net, but filtering at the source is best.)

### 2b. Action — the Webhook
`Security Fabric ▸ Automation ▸ Action ▸ Create New ▸ Webhook`

| Field | Value |
|-------|-------|
| Protocol | HTTP (or HTTPS if you terminate TLS in front — recommended) |
| URL / URI | `http://<ipsecalert-host>:8080/webhook/fortigate` |
| Method | `POST` |
| HTTP header | `Content-Type: application/json` |
| HTTP header | `X-Webhook-Token: <the WEBHOOK_TOKEN from your .env>` |

**HTTP Body:**

```json
{
  "user": "%%user%%",
  "ip": "%%remip%%",
  "country": "%%srccountry%%",
  "time": "%%time%%"
}
```

> The exact FortiGate log variables available depend on the triggering event.
> Common alternatives: `%%srcip%%`, `%%logid%%`, `%%devname%%`. IPsecAlert also
> accepts the raw field names (`remip`, `srccountry`, …), so you can pass the
> log fields through directly if you prefer.

### 2c. Stitch — tie them together
`Automation ▸ Automation Stitch ▸ Create New`: pick the trigger from 2a and the
Webhook action from 2b. Use the **Test** button to fire a sample — you should
see the request in `docker compose logs`.

---

## 3. Configuration reference

All settings are environment variables (see [.env.example](.env.example) for the
annotated list). The important ones:

| Variable | Purpose |
|----------|---------|
| `WEBHOOK_TOKEN` | Shared secret; FortiGate sends it in the `X-Webhook-Token` header. Required. |
| `LDAP_SERVER`, `LDAP_USE_SSL`, `LDAP_PORT` | Domain controller. Use LDAPS (636). |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | Read-only service account to bind with. |
| `LDAP_BASE_DN` | Search base, e.g. `DC=corp,DC=example,DC=com`. |
| `LDAP_USER_FILTER` | Default `(sAMAccountName={user})`. `{user}` is escaped before substitution. |
| `LDAP_EMAIL_ATTR` | Attribute holding the address (`mail`). |
| `SMTP_HOST`/`SMTP_PORT`/`SMTP_USE_STARTTLS`/`SMTP_USE_SSL` | Mail relay. |
| `SMTP_USERNAME`/`SMTP_PASSWORD` | Leave blank for an internal unauthenticated relay. |
| `MAIL_FROM`, `MAIL_FROM_NAME`, `MAIL_SUBJECT` | Sender & subject. |
| `MAIL_CC`, `MAIL_BCC`, `MAIL_REPLY_TO` | Optional extra recipients (e.g. CC the SOC). |
| `IGNORE_COUNTRIES` | Comma list of countries to never alert on. |
| `DEDUP_WINDOW_SECONDS` | Suppress duplicate user+IP alerts within N seconds (default 300). |
| `FALLBACK_EMAIL` | Notified when a user's mailbox can't be resolved, so events aren't lost. |

The e-mail itself is a bilingual (中文 / English) security notice. Edit
`app/templates/alert.txt.j2` and `app/templates/alert.html.j2` to change wording
or branding, then rebuild.

---

## 4. How a request is handled

1. **Auth** — reject with `401` unless the token matches (constant-time compare).
2. **Parse** — pull `user`/`ip`/`country`/`time` from the JSON (friendly *or*
   raw FortiGate field names).
3. **Country filter** — skip if `country` is in `IGNORE_COUNTRIES`.
4. **Dedup** — skip if the same user+IP was alerted within the window.
5. **Resolve** — look up the mailbox in AD (username is escaped → no LDAP
   injection; `DOMAIN\user` and `user@domain` are normalised to the account).
6. **Send** — deliver the alert; optionally CC/BCC; on lookup failure, notify
   `FALLBACK_EMAIL` instead.

Response codes: `200` handled (sent or intentionally skipped), `401`
unauthorized, `400` bad body, `502` LDAP/SMTP failure. Every outcome is logged
to stdout (`docker compose logs`).

---

## 5. Testing

```bash
# Unit tests (no network needed):
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m unittest -v

# End-to-end against a running container:
./scripts/send_test_webhook.sh http://127.0.0.1:8080/webhook/fortigate
```

From a Windows box (PowerShell):

```powershell
$body = @{ user="jdoe"; ip="203.0.113.45"; country="Russian Federation"; time="2026-07-22 09:15:03" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://<host>:8080/webhook/fortigate" -Method Post `
  -ContentType "application/json" `
  -Headers @{ "X-Webhook-Token" = "<your-token>" } -Body $body
```

---

## 6. Security notes

- **Put HTTPS in front.** The token authenticates FortiGate but is only private
  over TLS. Terminate TLS on a reverse proxy (nginx/Caddy) or FortiGate-facing
  load balancer, or restrict the listener to the management network.
- **Lock down the network** so only the FortiGate can reach `:8080`.
- Use a **read-only** LDAP service account; it never needs write access.
- The container runs as a **non-root** user; secrets come from `.env` (git-ignored).
- LDAP filter input is escaped; e-mail headers are sanitised; HTML values are
  auto-escaped in the template.

---

## 7. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `/health` shows names in `missing_config` | Those env vars aren't set — fix `.env`, `docker compose up -d`. |
| `401` on the webhook | Token header name/value mismatch between FortiGate and `.env`. |
| `status: email-not-found` | `LDAP_USER_FILTER`/`LDAP_EMAIL_ATTR` wrong, or the account has no `mail`. Check `FALLBACK_EMAIL` inbox. |
| `502 ldap-error` | Can't reach/bind the DC — check `LDAP_SERVER`, port, SSL, credentials, firewall. |
| `502 smtp-error` | Relay rejected the mail — check `SMTP_*`, and that `MAIL_FROM` is allowed to relay. |

View logs: `docker compose logs -f ipsecalert`
