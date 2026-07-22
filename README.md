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

# Put the GoDaddy wildcard cert in certs/ (see certs/README.md):
#   certs/fullchain.pem  (leaf + GoDaddy intermediate bundle)
#   certs/privkey.pem    (private key)

docker compose up -d --build
docker compose ps           # both containers should be "running"/"healthy"
docker compose logs -f
```

Caddy serves HTTPS on `:443` (published as `HOST_HTTPS_PORT`) using the company
**GoDaddy wildcard** cert from `certs/`. Verify locally (`-k` skips the hostname
check when hitting `127.0.0.1`; real clients use the FQDN and validate fully):

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

TLS is terminated by Caddy. This deployment uses the **company GoDaddy wildcard
certificate** (`*.gss.com.tw`), which FortiGate already trusts — so certificate
verification stays on with nothing to import.

**Setup**
1. Put the cert and key in `certs/` (git-ignored) — see [certs/README.md](certs/README.md):
   - `certs/fullchain.pem` — your leaf cert **plus** the GoDaddy intermediate bundle
   - `certs/privkey.pem` — the matching private key
2. Add an **internal DNS** A record for a subdomain the wildcard covers, e.g.
   `fortiwebhook.gss.com.tw` → the service host's internal IP.
3. Point FortiGate at that FQDN:
   `https://fortiwebhook.gss.com.tw:18443/webhook/fortigate`.

Caddy serves the cert on `:443` (mapped to `HOST_HTTPS_PORT`); FortiGate validates
it against GoDaddy's public root, and the hostname against the `*.gss.com.tw` SAN.

> **Use the FQDN, not the IP,** in the FortiGate URL — a wildcard cert matches
> names, so connecting by IP fails verification. The name only needs to resolve
> on your internal DNS; no public record is required.

Other options, if ever needed (in the [Caddyfile](Caddyfile)): `tls internal` for
a self-signed local CA, or a real public domain with automatic Let's Encrypt
(remove the `tls` line and set `SITE_ADDRESS` to that domain).

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
| URL / URI | `https://<fqdn>:18443/webhook/fortigate` — the wildcard-covered FQDN (e.g. `fortiwebhook.gss.com.tw`), not the IP |
| Method | `POST` |
| HTTP header | `Content-Type: application/json` |
| HTTP header | `X-Webhook-Token: <the WEBHOOK_TOKEN from your .env>` |

**HTTP Body:**

```json
{
  "user": "%%log.xauthuser%%",
  "ip": "%%log.remip%%",
  "country": "%%log.srccountry%%",
  "time": "%%log.date%% %%log.time%%"
}
```

> Field names depend on the triggering event; use the `%%log.<field>%%` form to
> read log fields directly. For IPsec VPN the AD identity is **`xauthuser`**
> (e.g. `alice@corp`), not `user` (which may be a config/peer name). IPsecAlert
> normalises `user@domain` / `DOMAIN\user` and also accepts the friendly keys
> (`ip`, `country`, `city`, …). The recommended body intentionally omits
> `city`, because `srccity` is not available for every FortiGate VPN event.
> If FortiGate does not support a variable for that event and sends the literal
> placeholder (for example `%%log.srccity%%`), IPsecAlert treats it as missing
> data instead of displaying the placeholder in the e-mail.
>
> **Alert once per connection:** filter the trigger to `action=tunnel-up` so
> rekeys / status-changes / disconnects don't each fire a webhook.

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
| `MAIL_FROM`, `MAIL_FROM_NAME`, `MAIL_SUBJECT` | Sender & subject. `MAIL_SUBJECT` supports `{{ country }}` for the event country. |
| `ORG_NAME` | Company/team name shown in the e-mail (blank to omit). |
| `SECURITY_CONTACT` | Retained for existing `.env` compatibility; no longer shown in the alert. |
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

## 7. Optional FortiClient EMS overseas monitor

The `feature/ems-overseas-monitor` implementation adds an isolated polling
service that detects an endpoint appearing or coming online from a foreign
public IP and sends the warning to that endpoint's user through the same SMTP
relay as IPsecAlert. If EMS returns a UPN/e-mail it is used directly; otherwise
the existing LDAP settings resolve the account. `EMS_ALERT_TO` is the fallback
when the user's mailbox cannot be resolved.

Fortinet's public EMS 7.4.7 guide confirms that EMS has an API, but keeps the
supported operations in the authenticated **FortiAPI** tab on FNDN. The default
`EMS_ENDPOINTS_PATH=/api/v1/endpoints/index?offset=0` was observed from an EMS
7.4.7 web console and remains configurable because UI-facing endpoints may
change between releases. Confirm the authentication method and JSON mappings
against the EMS 7.4.7 FortiAPI page:

- endpoint list: `data.endpoints`
- public source IP: `public_ip_addr`
- online state: `is_ems_online`
- registration state: `is_ems_registered`
- user mailbox: `fct_users.0.user_email`
- pagination: `data.total` with the `offset` query parameter

<https://docs.fortinet.com/document/forticlient/7.4.7/ems-administration-guide/30768/forticlient-ems-api>

### Setup

1. Copy a current MaxMind GeoLite2 Country database to
   `geoip/GeoLite2-Country.mmdb`. GeoIP lookups stay local.
2. Fill the `EMS_*` section in `.env`, especially `EMS_API_URL`,
   `EMS_ENDPOINTS_PATH`, `EMS_API_TOKEN`, and `EMS_ALERT_TO`.
3. Validate the API shape before starting the monitor:

```bash
docker compose --profile ems run --rm ems-monitor \
  python -m app.ems_monitor --validate-api
```

The command prints only the record count and available JSON field paths. If the
defaults do not match, update `EMS_ENDPOINTS_KEY` and the `EMS_*_FIELDS` lists.
It does not print endpoint values, tokens, users, or IP addresses.

4. Start the monitor:

```bash
docker compose --profile ems up -d --build
docker compose logs -f ems-monitor
```

The first successful poll creates a SQLite baseline in the `ems_state` volume
and sends no mail. Later polls alert only when a foreign endpoint is newly seen,
changes from unregistered to registered, changes from offline to online, or
changes to a new foreign public IP. Domestic registrations do not generate user
notifications. If SMTP delivery fails, that endpoint's state is not advanced,
so the next poll retries.

This detects the FortiClient-to-EMS management connection, not a VPN session.
GeoIP is approximate and may reflect a NAT, proxy, or corporate egress address.

---

## 8. Security — internal deployment

This service is meant to run on a closed internal network (FortiGate → service);
it should never be internet-facing. Defence in depth, outside-in:

**Network**
- Set `FORTIGATE_IPS` to the FortiGate's exact source IP — Caddy `403`s everyone
  else. The default `private_ranges` already blocks any non-internal source.
- Set `BIND_ADDR` to the internal interface IP so the HTTPS port isn't offered elsewhere.
- Port 80 stays closed (only public-domain ACME would need it).
- Add a host firewall rule as an independent second layer:

```
# nftables: only the FortiGate may reach the published HTTPS port
nft add rule inet filter input ip saddr 10.10.1.1 tcp dport 18443 accept
nft add rule inet filter input tcp dport 18443 drop
```

**TLS — FortiGate verification stays ON, nothing to import**
- Caddy presents the **company GoDaddy wildcard cert** (`certs/fullchain.pem` +
  `certs/privkey.pem`). FortiGate already trusts GoDaddy's root, so it verifies
  both the certificate and the hostname with no extra config — connect via the
  wildcard FQDN (see §2), never the IP.
- Keep the key safe: `certs/` is git-ignored (only its README is tracked), the
  volume is mounted read-only, and `privkey.pem` should be `chmod 600`.
- LDAP uses **LDAPS with certificate validation** (`LDAP_TLS_VALIDATE=true`). If
  your DCs present internal AD-CA certs, set `LDAP_CA_CERT` to that CA; if they
  use the same GoDaddy wildcard, the public trust store already covers them.
  SMTP validates too — `SMTP_CA_CERT` is only needed for an internal-CA relay.

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

## 9. Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `/health` shows names in `missing_config` | Those env vars aren't set — fix `.env`, `docker compose up -d`. |
| FortiGate webhook test fails on TLS | Connect by the wildcard **FQDN** (not IP); ensure `fullchain.pem` includes the GoDaddy **intermediate** bundle and the FQDN resolves internally to this host. |
| `curl … tlsv1 alert internal error` when testing by IP | No SNI is sent for an IP, so Caddy has no cert to present. Test with the FQDN: `curl --resolve <fqdn>:18443:127.0.0.1 https://<fqdn>:18443/health`. `TLS_DEFAULT_SNI` also lets SNI-less/IP clients through. |
| `caddy` fails loading the certificate | `certs/fullchain.pem` / `certs/privkey.pem` missing or unreadable — see [certs/README.md](certs/README.md). |
| `401` on the webhook | Token header name/value mismatch between FortiGate and `.env`. |
| `status: email-not-found` | `LDAP_USER_FILTER`/`LDAP_EMAIL_ATTR` wrong, or the account has no `mail`. Check `FALLBACK_EMAIL` inbox. |
| `502 ldap-error` | Can't reach/bind the DC — check `LDAP_SERVER`, port, SSL, credentials, firewall. |
| `502 smtp-error` | Relay rejected the mail — check `SMTP_*`, and that `MAIL_FROM` is allowed to relay. |
| `502 ldap-error` right after enabling TLS | DC cert not trusted — set `LDAP_CA_CERT` to your internal CA (or the cert's SAN doesn't match `LDAP_SERVER`). |
| `caddy` returns `403` to the FortiGate | Its source IP isn't in `FORTIGATE_IPS` — add it (or widen to `private_ranges`). |
| `caddy` fails: `port is already allocated` | Another service (e.g. avss) holds that host port — change `HOST_HTTPS_PORT` in `.env` and re-run `docker compose up -d`. |
| App container won't start (read-only FS) | A library needs to write outside `/tmp`; set `read_only: false` on the `ipsecalert` service. |

View logs: `docker compose logs -f`  (add `ipsecalert` or `caddy` for one service)
