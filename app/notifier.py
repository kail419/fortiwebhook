"""Orchestration: parse -> country filter -> dedup -> resolve e-mail -> render -> send."""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from jinja2 import Environment, FileSystemLoader

from .config import Config
from .ldap_lookup import LdapLookupError, resolve_email
from .mailer import MailSendError, send_mail

log = logging.getLogger("ipsecalert.notifier")

_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _autoescape(template_name) -> bool:
    """Escape only HTML/XML templates; leave the plaintext template untouched."""
    if not template_name:
        return False
    return template_name.endswith((".html.j2", ".html", ".htm.j2", ".htm", ".xml"))


_jinja = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=_autoescape,
    trim_blocks=True,
    lstrip_blocks=True,
)

# Keys we accept from the FortiGate JSON body, in priority order. This lets the
# body use either the friendly names or FortiGate's raw log field names.
_USER_KEYS = ("user", "username", "unauthuser")
_IP_KEYS = ("ip", "remip", "srcip", "remote_ip")
_COUNTRY_KEYS = ("country", "srccountry", "src_country")
_TIME_KEYS = ("time", "eventtime", "logtime", "date")


@dataclass
class Event:
    user: str = ""
    ip: str = ""
    country: str = ""
    time: str = ""
    raw: dict = field(default_factory=dict)


def _first(payload: dict, keys: Tuple[str, ...]) -> str:
    for key in keys:
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def parse_event(payload: dict) -> Event:
    return Event(
        user=_first(payload, _USER_KEYS),
        ip=_first(payload, _IP_KEYS),
        country=_first(payload, _COUNTRY_KEYS),
        time=_first(payload, _TIME_KEYS),
        raw=payload,
    )


class _DedupCache:
    """In-memory 'have I alerted on this recently?' cache (per process).

    Good enough for a single-worker deployment. If you scale to multiple
    gunicorn workers, move this to a shared store (e.g. Redis) or keep
    WEB_CONCURRENCY=1 so the cache stays authoritative.
    """

    def __init__(self, window_seconds: int):
        self.window = window_seconds
        self._store: Dict[str, float] = {}
        self._lock = threading.Lock()

    def seen_recently(self, key: str) -> bool:
        if self.window <= 0:
            return False
        now = time.monotonic()
        with self._lock:
            for stale in [k for k, ts in self._store.items() if now - ts > self.window]:
                self._store.pop(stale, None)
            if key in self._store and now - self._store[key] <= self.window:
                return True
            self._store[key] = now
            return False

    def release(self, key: str) -> None:
        """Forget a key so a *failed* attempt doesn't suppress an immediate retry."""
        with self._lock:
            self._store.pop(key, None)


class Notifier:
    def __init__(self, config: Config):
        self.config = config
        self._dedup = _DedupCache(config.dedup_window_seconds)

    def handle(self, payload: dict) -> dict:
        """Process one webhook event and return a JSON-serialisable result.

        ``status`` is one of: ``sent`` | ``skipped`` | ``error``. The route
        maps sent/skipped to HTTP 200 and error to HTTP 502.
        """
        event = parse_event(payload)
        base = {"user": event.user, "ip": event.ip, "country": event.country}

        if not event.user:
            log.warning("Webhook with no user field; payload keys=%s", list(payload.keys()))
            return {**base, "status": "skipped", "reason": "no-user-in-payload"}

        if event.country and event.country.lower() in self.config.ignore_countries:
            log.info("Ignoring user=%s from allow-listed country=%s", event.user, event.country)
            return {**base, "status": "skipped", "reason": "ignored-country"}

        dedup_key = f"{event.user.lower()}|{event.ip}"
        if self._dedup.seen_recently(dedup_key):
            log.info("Deduplicated recent alert for %s", dedup_key)
            return {**base, "status": "skipped", "reason": "deduplicated"}

        try:
            email = resolve_email(self.config, event.user)
        except LdapLookupError as exc:
            log.error("LDAP lookup failed for user=%s: %s", event.user, exc)
            self._dedup.release(dedup_key)  # transient failure — allow retry
            self._maybe_fallback(event, reason="ldap-error")
            return {**base, "status": "error", "reason": "ldap-error"}

        if not email:
            log.warning("No mailbox for user=%s (country=%s ip=%s)",
                        event.user, event.country, event.ip)
            notified = self._maybe_fallback(event, reason="user-email-not-found")
            return {**base, "status": "skipped", "reason": "email-not-found",
                    "fallback_notified": notified}

        subject, text_body, html_body = self._render(event, recipient=email)
        try:
            send_mail(
                self.config, to_addr=email, subject=subject,
                text_body=text_body, html_body=html_body,
                cc=self.config.mail_cc, bcc=self.config.mail_bcc,
            )
        except MailSendError as exc:
            log.error("Failed to send alert to %s: %s", email, exc)
            self._dedup.release(dedup_key)  # transient failure — allow retry
            return {**base, "status": "error", "reason": "smtp-error", "recipient": email}

        log.info("Notified user=%s at %s (country=%s ip=%s)",
                 event.user, email, event.country, event.ip)
        return {**base, "status": "sent", "recipient": email}

    def _maybe_fallback(self, event: Event, reason: str) -> bool:
        """Notify the SOC/fallback mailbox when the user can't be reached."""
        cfg = self.config
        if not (cfg.fallback_email and cfg.notify_fallback_on_missing):
            return False
        subject = f"[IPsecAlert] 無法通知當事人 ({reason}) — user={event.user}"
        text = (
            "IPsecAlert 無法直接通知連線當事人，請資安人員手動跟進。\n"
            "IPsecAlert could not notify the connecting user; please follow up manually.\n\n"
            f"原因 Reason : {reason}\n"
            f"帳號 User   : {event.user}\n"
            f"來源 IP     : {event.ip}\n"
            f"國家 Country: {event.country}\n"
            f"時間 Time   : {event.time}\n"
        )
        try:
            send_mail(cfg, to_addr=cfg.fallback_email, subject=subject, text_body=text)
            return True
        except MailSendError as exc:
            log.error("Fallback notification failed: %s", exc)
            return False

    def _render(self, event: Event, recipient: str) -> Tuple[str, str, str]:
        ctx = {
            "user": event.user,
            "ip": event.ip or "N/A",
            "country": event.country or "Unknown",
            "time": event.time or "N/A",
            "recipient": recipient,
            "from_name": self.config.mail_from_name,
            "org_name": self.config.org_name,
            "security_contact": self.config.security_contact,
        }
        text_body = _jinja.get_template("alert.txt.j2").render(**ctx)
        html_body = _jinja.get_template("alert.html.j2").render(**ctx)
        return self.config.mail_subject, text_body, html_body
