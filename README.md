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
curl -k https://<host>:18443/health
# {"status":"ok","missing_config":[]}   <- missing_config must be empty

# Send a test event:
INSECURE=1 WEBHOOK_TOKEN=$(grep ^WEBHOOK_TOKEN= .env | cut -d= -f2) \
  ./scripts/send_test_webhook.sh https://127.0.0.1:18443/webhook/fortigate
```

> HTTPS is published on host port **18443** by default (443 is left for other
> services such as avss). Change it with `HOST_HTTPS_PORT` in `.env`.

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
| URL / URI | `https://<ipsecalert-host>:18443/webhook/fortigate` (or your `HOST_HTTPS_PORT`) |
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
| `WEBHOOK_TOKEN` | Shared secret; FortiGate sends it in the `X-Webhook-Token` header. Required. (`WEBHOOK_TOKEN_FILE` for a Docker secret.) |
| `SITE_ADDRESS` | What Caddy serves on: `:443` (self-signed, default) or a domain (auto HTTPS). |
| `FORTIGATE_IPS` | Source IPs Caddy accepts; `private_ranges` (internal only) → tighten to the FortiGate IP. |
| `BIND_ADDR` | Host interface the HTTPS port binds to (set to your internal IP). |
| `HOST_HTTPS_PORT` | Host port published for HTTPS (default `18443`; keeps off 443). |
| `LDAP_SERVER`, `LDAP_USE_SSL`, `LDAP_PORT` | Domain controller. LDAPS (636) is the default. |
| `LDAP_TLS_VALIDATE`, `LDAP_CA_CERT` | Verify the DC cert (on by default); point at your internal CA bundle. |
| `LDAP_BIND_DN`, `LDAP_BIND_PASSWORD` | Read-only service account to bind with. (`LDAP_BIND_PASSWORD_FILE` for a secret.) |
| `LDAP_BASE_DN` | Search base, e.g. `DC=corp,DC=example,DC=com`. |
| `LDAP_USER_FILTER` | Default `(sAMAccountName={user})`. `{user}` is escaped before substitution. |
| `LDAP_EMAIL_ATTR` | Attribute holding the address (`mail`). |
| `SMTP_HOST`/`SMTP_PORT`/`SMTP_USE_STARTTLS`/`SMTP_USE_SSL` | Mail relay (TLS validated). |
| `SMTP_USERNAME`/`SMTP_PASSWORD` | Leave blank for an internal unauthenticated relay. (`SMTP_PASSWORD_FILE` for a secret.) |
| `SMTP_CA_CERT` | Optional CA bundle to trust the relay's TLS cert (internal CA). |
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
INSECURE=1 ./scripts/send_test_webhook.sh https://127.0.0.1:18443/webhook/fortigate
```

From a Windows box (PowerShell); `-SkipCertificateCheck` for the self-signed cert:

```powershell
$body = @{ user="jdoe"; ip="203.0.113.45"; country="Russian Federation"; time="2026-07-22 09:15:03" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://<host>:18443/webhook/fortigate" -Method Post `
  -ContentType "application/json" -SkipCertificateCheck `
  -Headers @{ "X-Webhook-Token" = "<your-token>" } -Body $body
```

---

## 7. Security — internal deployment

This service is meant to run on a closed internal network (FortiGate → service);
it should never be internet-facing. Defence in depth, outside-in:

**Network**
- Set `FORTIGATE_IPS` to the FortiGate's exact source IP — Caddy `403`s everyone
  else. The default `private_ranges` already blocks any non-internal source.
- Set `BIND_ADDR` to the internal interface IP so 443 isn't offered elsewhere.
- Port 80 stays closed (only public-domain ACME would need it).
- Add a host firewall rule as an independent second layer:

```
# nftables: only the FortiGate may reach 443
nft add rule inet filter input ip saddr 10.10.1.1 tcp dport 443 accept
nft add rule inet filter input tcp dport 443 drop
```

**TLS — keep FortiGate's certificate verification ON**
- *Corporate CA (recommended):* issue a host cert from your internal CA and use
  Caddyfile option C — FortiGate already trusts that root, so it verifies cleanly.
- *Caddy local CA:* export its root and import it into FortiGate as a trusted CA:

```
docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt
```

- LDAP uses **LDAPS with certificate validation** (`LDAP_TLS_VALIDATE=true`); set
  `LDAP_CA_CERT` to your internal CA so the DC cert is verified (blocks MITM).
  SMTP validates too — set `SMTP_CA_CERT` for an internal-CA relay.

**Secrets & container**
- Prefer Docker secrets: set `WEBHOOK_TOKEN_FILE`, `LDAP_BIND_PASSWORD_FILE`,
  `SMTP_PASSWORD_FILE` to mounted files instead of inline env values.
- Long random token: `openssl rand -hex 32`. Use a **read-only** LDAP account.
- Both containers run non-root with `no-new-privileges` and **all capabilities
  dropped** (`ipsecalert` also has a read-only root filesystem); the app is never
  published to the host — only Caddy can reach it.

**Application**
- LDAP filter input is escaped (no injection); e-mail headers sanitised; HTML
  auto-escaped. The token is compared in constant time and never logged.

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
| `502 ldap-error` right after enabling TLS | DC cert not trusted — set `LDAP_CA_CERT` to your internal CA (or the cert's SAN doesn't match `LDAP_SERVER`). |
| `caddy` returns `403` to the FortiGate | Its source IP isn't in `FORTIGATE_IPS` — add it (or widen to `private_ranges`). |
| `caddy` fails: `port is already allocated` | Another service (e.g. avss) holds that host port — change `HOST_HTTPS_PORT` in `.env` and re-run `docker compose up -d`. |
| App container won't start (read-only FS) | A library needs to write outside `/tmp`; set `read_only: false` on the `ipsecalert` service. |

View logs: `docker compose logs -f`  (add `ipsecalert` or `caddy` for one service)
