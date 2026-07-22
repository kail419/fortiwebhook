# TLS certificates

Caddy terminates TLS using the company **GoDaddy wildcard** certificate. Put two
files in this directory — it is git-ignored **except** for this README, so the
private key can never be committed:

- `fullchain.pem` — your leaf/domain certificate **followed by** the GoDaddy
  intermediate bundle (leaf first).
- `privkey.pem` — the private key that matches the certificate.

## Assembling from a GoDaddy download

GoDaddy gives you a leaf cert (e.g. `abc123.crt`) and an intermediate bundle
(e.g. `gd_bundle-g2-g1.crt`); the private key is the one generated with the CSR.

```bash
cat abc123.crt gd_bundle-g2-g1.crt > fullchain.pem
cp  your-domain.key                  privkey.pem
chmod 600 privkey.pem
```

If GoDaddy gave you a single `.pfx` / PKCS#12 file:

```bash
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out fullchain.pem   # append the intermediate if it isn't included
openssl pkcs12 -in cert.pfx -nocerts -nodes  -out privkey.pem
```

## Verify the chain is complete (important)

FortiGate needs the intermediate chain, not just the leaf certificate:

```bash
openssl verify -untrusted fullchain.pem fullchain.pem   # expect: OK
openssl x509 -in fullchain.pem -noout -subject -enddate # check name + expiry
```

The certificate is a wildcard (`*.gss.com.tw`), so pick a **single-label**
subdomain FQDN (e.g. `fortiwebhook.gss.com.tw`) for the FortiGate webhook URL and
add an internal DNS A record pointing it at this host.

After replacing the files, reload Caddy:

```bash
docker compose restart caddy
```
