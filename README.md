# IPsecAlert

External webhook service for **FortiGate Automation**. FortiGate cannot turn the
`%%user%%` log variable into a mailbox on its own, so this service does it:

```
FortiGate (IPsec/VPN event)
   └─▶ Automation ▸ Action: Webhook ──HTTPS POST──▶ Caddy (TLS) ─▶ IPsecAlert
                                                                     │ 1. verify shared token
                                                                     │ 2. resolve %%user%% → e-mail (LDAP/AD)
                                                                     │ 3. send bilingual alert (SMTP)
                                                                     ▼
                                                          當事人 (the connecting user)
```

Runs as two always-on containers on a Linux host:

- **caddy** — terminates TLS and reverse-proxies to the app (only `/webhook/*`
  and `/health` are exposed at the edge).
- **ipsecalert** — Python + Flask, `ldap3` for the directory lookup, stdlib
  `smtplib` for mail, served by gunicorn. Not published to the host directly.

---

## 1. Quick start

```bash
cp .env.example .env
# edit .env: WEBHOOK_TOKEN, LDAP_*, SMTP_*, MAIL_FROM  (see the file's comments)

docker compose up -d --build
docker compose ps           # both containers should be "running"/"healthy"
docker compose logs -f
```

With the default `SITE_ADDRESS=:443`, Caddy serves HTTPS immediately using a
self-signed certificate from its own local CA — no domain or internet needed.
Verify (the `-k` accepts the self-signed cert):

```bash
curl -k https://<host>/health
# {"status":"ok","missing_config":[]}   <- missing_config must be empty

# Send a test event:
INSECURE=1 WEBHOOK_TOKEN=$(grep ^WEBHOOK_TOKEN= .env | cut -d= -f2) \
  ./scripts/send_test_webhook.sh https://127.0.0.1/webhook/fortigate
```

---

## 2. HTTPS / reverse proxy (Caddy)

TLS is terminated by Caddy so the shared token is never sent in cleartext. Pick
the mode that fits your network by editing `SITE_ADDRESS` in `.env` and, for
options B/C, uncommenting a line in the [Caddyfile](Caddyfile):

| Mode | When | How |
|------|------|-----|
| **A. Public domain** | The host is internet-reachable with a real DNS name | `SITE_ADDRESS=ipsecalert.corp.example.com` — Caddy auto-obtains & renews a Let's Encrypt cert. Needs ports 80/443 reachable. |
| **B. Self-signed (default)** | Closed / internal network | `SITE_ADDRESS=:443` — Caddy's local CA issues a self-signed cert. Zero external dependencies. FortiGate must skip cert verification or trust the Caddy root. |
| **C. Corporate cert** | You have an internal-CA cert for the host | Mount the files (uncomment the `./certs` volume in `docker-compose.yml`) and the `tls /certs/...` line in the Caddyfile. |

> Prefer nginx? The app is a plain HTTP upstream on `ipsecalert:8080`; any proxy
> that terminates TLS and forwards to it works. Caddy is the default only because
> it needs the least configuration.

**FortiGate + self-signed:** FortiGate's webhook validates the server certificate
by default. On a closed network either import the Caddy local-CA root into
FortiGate, use a corporate cert (mode C), or use a public cert (mode A).

---

## 3. FortiGate configuration

### 3a. Trigger — decide *when* to fire
`Security Fabric ▸ Automation ▸ Trigger`. Create a log/event trigger that matches
what you care about — typically an IPsec VPN user coming up from a foreign
`srccountry`. Filter it at the source so it only fires on the countries/events
you want. (IPsecAlert also has an `IGNORE_COUNTRIES` safety net.)

### 3b. Action — the Webhook
`Security Fabric ▸ Automation ▸ Action ▸ Create New ▸ Webhook`

| Field | Value |
|-------|-------|
| Protocol | HTTPS |
| URL / URI | `https://<ipsecalert-host>/webhook/fortigate` |
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

> The available log variables depend on the triggering event. IPsecAlert also
> accepts the raw FortiGate field names (`remip`, `srccountry`, …), so you can
> pass log fields through directly if you prefer.

### 3c. Stitch — tie them together
`Automation ▸ Automation Stitch ▸ Create New`: pick the trigger from 3a and the
Webhook action from 3b, then use **Test** to fire a sample — you should see the
request in `docker compose logs`.

---

## 4. Configuration reference

All settings are environment variables (see [.env.example](.env.example) for the
annotated list). Highlights:

| Variable | Purpose |
|----------|---------|
| `WEBHOOK_TOKEN` | Shared secret; FortiGate sends it in the `X-Webhook-Token` header. Required. |
| `SITE_ADDRESS` | What Caddy serves on: `:443` (self-signed, default) or a domain (auto HTTPS). |
| `LDAP_SERVER`, `LDAP_USE_SSL`, `LDAP_PORT` | Domain controller. Use LDAPS (636). |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | Read-only service account to bind with. |
| `LDAP_BASE_DN` | Search base, e.g. `DC=corp,DC=example,DC=com`. |
| `LDAP_USER_FILTER` | Default `(sAMAccountName={user})`. `{user}` is escaped before substitution. |
| `LDAP_EMAIL_ATTR` | Attribute holding the address (`mail`). |
| `SMTP_HOST`/`SMTP_PORT`/`SMTP_USE_STARTTLS`/`SMTP_USE_SSL` | Mail relay. |
| `SMTP_USERNAME`/`SMTP_PASSWORD` | Leave blank for an internal unauthenticated relay. |
| `MAIL_FROM`, `MAIL_FROM_NAME`, `MAIL_SUBJECT` | Sender & subject. |
| `ORG_NAME` | Company/team name shown in the e-mail (blank to omit). |
| `SECURITY_CONTACT` | Who to contact if the login wasn't the user (shown in the alert). |
| `MAIL_CC`, `MAIL_BCC`, `MAIL_REPLY_TO` | Optional extra recipients (e.g. CC the SOC). |
| `IGNORE_COUNTRIES` | Comma list of countries to never alert on. |
| `DEDUP_WINDOW_SECONDS` | Suppress duplicate user+IP alerts within N seconds (default 300). |
| `FALLBACK_EMAIL` | Notified when a user's mailbox can't be resolved, so events aren't lost. |

The e-mail is a bilingual (中文 / English) security notice with a clear
"if this was you / if it wasn't you" split. Edit
[app/templates/alert.txt.j2](app/templates/alert.txt.j2) and
[app/templates/alert.html.j2](app/templates/alert.html.j2) to change wording,
then rebuild.

---

## 5. How a request is handled

1. **TLS** terminated by Caddy; only `/webhook/*` and `/health` reach the app.
2. **Auth** — reject with `401` unless the token matches (constant-time compare).
3. **Parse** — pull `user`/`ip`/`country`/`time` (friendly *or* raw FortiGate names).
4. **Country filter** — skip if `country` is in `IGNORE_COUNTRIES`.
5. **Dedup** — skip if the same user+IP was alerted within the window.
6. **Resolve** — look up the mailbox in AD (username is escaped → no LDAP
   injection; `DOMAIN\user` and `user@domain` are normalised to the account).
7. **Send** — deliver the alert; optionally CC/BCC; on lookup failure, notify
   `FALLBACK_EMAIL` instead.

Response codes: `200` handled (sent or intentionally skipped), `401`
unauthorized, `400` bad body, `502` LDAP/SMTP failure. Every outcome is logged to
stdout (`docker compose logs`).

---

## 6. Testing

```bash
# Unit + HTTP tests (no network needed):
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m unittest discover -s tests -t .

# End-to-end against the running stack (self-signed cert):
INSECURE=1 ./scripts/send_test_webhook.sh https://127.0.0.1/webhook/fortigate
```

From a Windows box (PowerShell); `-SkipCertificateCheck` for the self-signed cert:

```powershell
$body = @{ user="jdoe"; ip="203.0.113.45"; country="Russian Federation"; time="2026-07-22 09:15:03" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://<host>/webhook/fortigate" -Method Post `
  -ContentType "application/json" -SkipCertificateCheck `
  -Headers @{ "X-Webhook-Token" = "<your-token>" } -Body $body
```

---

## 7. Security notes

- TLS is terminated by **Caddy**; the token travels encrypted. Still restrict the
  network so only the FortiGate can reach the proxy.
- The app container is **not** published to the host — it's only reachable via
  Caddy on the internal compose network.
- Use a **read-only** LDAP service account; it never needs write access.
- The app container runs as a **non-root** user; secrets come from `.env`
  (git-ignored).
- LDAP filter input is escaped; e-mail headers are sanitised; HTML values are
  auto-escaped in the template.

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `/health` shows names in `missing_config` | Those env vars aren't set — fix `.env`, `docker compose up -d`. |
| FortiGate webhook test fails on TLS | Self-signed cert not trusted — import Caddy's root, use a corporate/public cert, or allow-insecure on the FortiGate side. |
| `401` on the webhook | Token header name/value mismatch between FortiGate and `.env`. |
| `status: email-not-found` | `LDAP_USER_FILTER`/`LDAP_EMAIL_ATTR` wrong, or the account has no `mail`. Check `FALLBACK_EMAIL` inbox. |
| `502 ldap-error` | Can't reach/bind the DC — check `LDAP_SERVER`, port, SSL, credentials, firewall. |
| `502 smtp-error` | Relay rejected the mail — check `SMTP_*`, and that `MAIL_FROM` is allowed to relay. |

View logs: `docker compose logs -f`  (add `ipsecalert` or `caddy` for one service)
