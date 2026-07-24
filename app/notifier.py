"""Orchestration: parse -> country filter -> dedup -> resolve e-mail -> render -> send."""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Tuple

from jinja2 import Environment, FileSystemLoader, TemplateError

from .config import Config
from .events import (
    BOTH,
    USER,
    EventType,
    classify,
    clean_value,
    first_value,
    humanize_field,
    resolve_audience,
)
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

# Severity presentation for team alerts.
_SEVERITY_ACCENT = {"critical": "#b91c1c", "warning": "#b45309", "info": "#1d4ed8"}
_SEVERITY_LABEL = {
    "critical": "嚴重 / Critical",
    "warning": "警告 / Warning",
    "info": "資訊 / Info",
}

# Keys we accept from the FortiGate JSON body, in priority order, so the body
# can use friendly names or FortiGate's raw log field names. Unexpanded log
# variables (e.g. "%%log.srccity%%") are treated as missing by first_value().
_USER_KEYS = ("user", "username", "unauthuser", "xauthuser")
_IP_KEYS = ("ip", "remip", "srcip", "remote_ip", "tunnelip")
_COUNTRY_KEYS = ("country", "srccountry", "src_country")
_CITY_KEYS = ("city", "srccity", "src_city")
_TIME_KEYS = ("time", "eventtime", "logtime", "date")


@dataclass
class Event:
    user: str = ""
    ip: str = ""
    country: str = ""
    city: str = ""
    time: str = ""
    raw: dict = field(default_factory=dict)


def parse_event(payload: dict) -> Event:
    return Event(
        user=first_value(payload, _USER_KEYS),
        ip=first_value(payload, _IP_KEYS),
        country=first_value(payload, _COUNTRY_KEYS),
        city=first_value(payload, _CITY_KEYS),
        time=first_value(payload, _TIME_KEYS),
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

        The body is classified into a FortiGate event type and routed by
        audience: user-facing events (VPN logins) notify the affected user,
        while administrative / system / threat events notify the security-IT
        team. ``status`` is one of ``sent`` | ``skipped`` | ``error``; the route
        maps sent/skipped to HTTP 200 and error to HTTP 502.
        """
        event = parse_event(payload)
        event_type, _ = classify(payload, self.config.event_aliases)
        audience = resolve_audience(event_type, self.config.event_audience_overrides)
        base = {
            "user": event.user,
            "ip": event.ip,
            "country": event.country,
            "event": event_type.key,
        }

        if not event_type.notify:
            log.info("Event %s is muted; no notification sent", event_type.key)
            return {**base, "status": "skipped", "reason": "event-muted"}

        if event_type.key in self.config.disabled_events:
            log.info("Event %s disabled by config", event_type.key)
            return {**base, "status": "skipped", "reason": "event-disabled"}

        if audience == USER:
            return self._handle_user_event(event, event_type, base)

        result = self._handle_team_event(event, event_type, base)
        if audience == BOTH and event.user:
            # 'both' also copies the affected user; the team result is canonical.
            self._handle_user_event(event, event_type, dict(base))
        return result

    def _handle_user_event(self, event: Event, event_type: EventType, base: dict) -> dict:
        """Notify the affected user — the classic VPN-login path."""
        if not event.user:
            log.warning("Webhook with no user field; payload keys=%s", list(event.raw.keys()))
            return {**base, "status": "skipped", "reason": "no-user-in-payload"}

        if event.country and event.country.lower() in self.config.ignore_countries:
            log.info("Ignoring user=%s from allow-listed country=%s", event.user, event.country)
            return {**base, "status": "skipped", "reason": "ignored-country"}

        dedup_key = f"{event_type.key}|{event.user.lower()}|{event.ip}"
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

        try:
            subject, text_body, html_body = self._render(event, recipient=email)
        except TemplateError as exc:
            log.error("Failed to render alert for user=%s: %s", event.user, exc)
            self._dedup.release(dedup_key)  # repaired templates can retry immediately
            return {**base, "status": "error", "reason": "template-error",
                    "recipient": email}

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

    def _handle_team_event(self, event: Event, event_type: EventType, base: dict) -> dict:
        """Notify the security-IT team about an admin / system / threat event."""
        recipients = self.config.team_recipients()
        if not recipients:
            log.warning("Team event %s but no SECURITY_TEAM_EMAIL/FALLBACK_EMAIL set",
                        event_type.key)
            return {**base, "status": "skipped", "reason": "no-team-recipient"}

        dedup_key = self._team_dedup_key(event, event_type)
        if self._dedup.seen_recently(dedup_key):
            log.info("Deduplicated recent team alert for %s", dedup_key)
            return {**base, "status": "skipped", "reason": "deduplicated"}

        try:
            subject, text_body, html_body = self._render_team(event, event_type)
        except TemplateError as exc:
            log.error("Failed to render team alert for event=%s: %s", event_type.key, exc)
            self._dedup.release(dedup_key)
            return {**base, "status": "error", "reason": "template-error"}

        primary, extra_cc = recipients[0], recipients[1:]
        try:
            send_mail(
                self.config, to_addr=primary, subject=subject,
                text_body=text_body, html_body=html_body,
                cc=[*extra_cc, *self.config.mail_cc], bcc=self.config.mail_bcc,
            )
        except MailSendError as exc:
            log.error("Failed to send team alert to %s: %s", primary, exc)
            self._dedup.release(dedup_key)  # transient failure — allow retry
            return {**base, "status": "error", "reason": "smtp-error", "recipient": primary}

        log.info("Team-notified event=%s to=%s (srcip=%s)", event_type.key, primary, event.ip)
        return {**base, "status": "sent", "recipient": primary}

    @staticmethod
    def _team_dedup_key(event: Event, event_type: EventType) -> str:
        raw = event.raw
        identity = (event.user or clean_value(raw.get("admin"))).lower()
        detail = clean_value(raw.get("attack") or raw.get("cfgpath") or raw.get("virus"))
        srcip = event.ip or clean_value(raw.get("srcip"))
        return "|".join((event_type.key, identity, srcip, detail))

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
        location = ", ".join(p for p in (event.city, event.country) if p) or "Unknown"
        ctx = {
            "user": event.user,
            "ip": event.ip or "N/A",
            "country": event.country or "Unknown",
            "city": event.city or "",
            "location": location,
            "time": event.time or "N/A",
            "recipient": recipient,
            "from_name": self.config.mail_from_name,
            "org_name": self.config.org_name,
        }
        text_body = _jinja.get_template("alert.txt.j2").render(**ctx)
        html_body = _jinja.get_template("alert.html.j2").render(**ctx)
        subject = _jinja.from_string(self.config.mail_subject).render(**ctx)
        return subject, text_body, html_body

    def _render_team(self, event: Event, event_type: EventType) -> Tuple[str, str, str]:
        """Render the generic team alert (subject + text + HTML)."""
        raw = event.raw
        srcip = event.ip or clean_value(raw.get("srcip"))
        location = ", ".join(p for p in (event.city, event.country) if p)

        # Curated, prominent rows: common fields first, then the fields the
        # catalog flags as important for this event type. Deduplicated by label.
        candidate_rows = [
            ("設備 / Device", first_value(raw, ("devname", "device", "devid"))),
            ("時間 / Time", event.time),
            ("管理者 / Admin", clean_value(raw.get("admin"))),
            ("使用者 / User", event.user),
            ("來源 IP / Source IP", srcip),
            ("目的 IP / Dest IP", clean_value(raw.get("dstip"))),
            ("位置 / Location", location),
            ("動作 / Action", clean_value(raw.get("action"))),
        ]
        candidate_rows += [
            (humanize_field(name), clean_value(raw.get(name)))
            for name in event_type.detail_fields
        ]
        candidate_rows.append(("訊息 / Message", first_value(raw, ("msg", "logdesc"))))

        rows, seen = [], set()
        for label, value in candidate_rows:
            if value and label not in seen:
                rows.append((label, value))
                seen.add(label)

        # Every provided field, so nothing is lost for unrecognised events.
        all_fields = [
            (humanize_field(key), clean_value(value))
            for key, value in raw.items()
            if key != "token" and clean_value(value)
        ]

        ctx = {
            "title_zh": event_type.title_zh,
            "title_en": event_type.title_en,
            "severity": event_type.severity,
            "severity_label": _SEVERITY_LABEL.get(event_type.severity, event_type.severity),
            "accent": _SEVERITY_ACCENT.get(event_type.severity, _SEVERITY_ACCENT["warning"]),
            "event_key": event_type.key,
            "rows": rows,
            "all_fields": all_fields,
            "org_name": self.config.org_name,
        }
        text_body = _jinja.get_template("event_alert.txt.j2").render(**ctx)
        html_body = _jinja.get_template("event_alert.html.j2").render(**ctx)
        subject = _jinja.get_template("event_alert.subject.j2").render(**ctx)
        return subject, text_body, html_body
