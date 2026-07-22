"""Application configuration, loaded entirely from environment variables.

Every setting has a safe default so the process can always start; required
settings that are missing are reported by :meth:`Config.missing_required` and
logged at startup, and the webhook returns an error until they are supplied.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


def _get_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on", "y")


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val.strip() == "":
        return default
    try:
        return int(val)
    except ValueError:
        return default


def _get_list(name: str, default: Optional[List[str]] = None) -> List[str]:
    val = os.getenv(name)
    if not val:
        return list(default or [])
    return [item.strip() for item in val.split(",") if item.strip()]


@dataclass
class Config:
    # --- Webhook authentication ---
    webhook_token: str = ""
    webhook_token_header: str = "X-Webhook-Token"

    # --- HTTP server (also read by gunicorn.conf.py) ---
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    max_content_length: int = 64 * 1024  # 64 KiB request-body cap

    # --- LDAP / Active Directory ---
    ldap_server: str = ""            # e.g. "dc01.corp.example.com" or "ldaps://dc01..."
    ldap_port: int = 0               # 0 => let ldap3 choose 389 / 636
    ldap_use_ssl: bool = False       # True => LDAPS (recommended, port 636)
    ldap_bind_dn: str = ""           # service account: "svc-fgt@corp.example.com" or full DN
    ldap_bind_password: str = ""
    ldap_base_dn: str = ""           # e.g. "DC=corp,DC=example,DC=com"
    ldap_user_filter: str = "(sAMAccountName={user})"
    ldap_email_attr: str = "mail"
    ldap_strip_upn_suffix: bool = True
    ldap_timeout: int = 10

    # --- SMTP ---
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_use_ssl: bool = False       # implicit TLS (usually port 465)
    smtp_use_starttls: bool = True   # explicit TLS/STARTTLS (usually port 587)
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_timeout: int = 15
    mail_from: str = ""
    mail_from_name: str = "IT Security Alert"
    mail_cc: List[str] = field(default_factory=list)
    mail_bcc: List[str] = field(default_factory=list)
    mail_reply_to: str = ""
    mail_subject: str = "[資安通知] 偵測到您的帳號自海外連線 VPN / Security Alert"

    # --- Behaviour ---
    ignore_countries: List[str] = field(default_factory=list)   # lower-cased
    dedup_window_seconds: int = 300
    fallback_email: str = ""         # notified when the user's mailbox can't be resolved
    notify_fallback_on_missing: bool = True

    # --- Logging ---
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            webhook_token=os.getenv("WEBHOOK_TOKEN", ""),
            webhook_token_header=os.getenv("WEBHOOK_TOKEN_HEADER", "X-Webhook-Token"),
            listen_host=os.getenv("LISTEN_HOST", "0.0.0.0"),
            listen_port=_get_int("LISTEN_PORT", 8080),
            max_content_length=_get_int("MAX_CONTENT_LENGTH", 64 * 1024),
            ldap_server=os.getenv("LDAP_SERVER", ""),
            ldap_port=_get_int("LDAP_PORT", 0),
            ldap_use_ssl=_get_bool("LDAP_USE_SSL", False),
            ldap_bind_dn=os.getenv("LDAP_BIND_DN", ""),
            ldap_bind_password=os.getenv("LDAP_BIND_PASSWORD", ""),
            ldap_base_dn=os.getenv("LDAP_BASE_DN", ""),
            ldap_user_filter=os.getenv("LDAP_USER_FILTER", "(sAMAccountName={user})"),
            ldap_email_attr=os.getenv("LDAP_EMAIL_ATTR", "mail"),
            ldap_strip_upn_suffix=_get_bool("LDAP_STRIP_UPN_SUFFIX", True),
            ldap_timeout=_get_int("LDAP_TIMEOUT", 10),
            smtp_host=os.getenv("SMTP_HOST", ""),
            smtp_port=_get_int("SMTP_PORT", 587),
            smtp_use_ssl=_get_bool("SMTP_USE_SSL", False),
            smtp_use_starttls=_get_bool("SMTP_USE_STARTTLS", True),
            smtp_username=os.getenv("SMTP_USERNAME", ""),
            smtp_password=os.getenv("SMTP_PASSWORD", ""),
            smtp_timeout=_get_int("SMTP_TIMEOUT", 15),
            mail_from=os.getenv("MAIL_FROM", ""),
            mail_from_name=os.getenv("MAIL_FROM_NAME", "IT Security Alert"),
            mail_cc=_get_list("MAIL_CC"),
            mail_bcc=_get_list("MAIL_BCC"),
            mail_reply_to=os.getenv("MAIL_REPLY_TO", ""),
            mail_subject=os.getenv(
                "MAIL_SUBJECT",
                "[資安通知] 偵測到您的帳號自海外連線 VPN / Security Alert",
            ),
            ignore_countries=[c.lower() for c in _get_list("IGNORE_COUNTRIES")],
            dedup_window_seconds=_get_int("DEDUP_WINDOW_SECONDS", 300),
            fallback_email=os.getenv("FALLBACK_EMAIL", ""),
            notify_fallback_on_missing=_get_bool("NOTIFY_FALLBACK_ON_MISSING", True),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        )

    def missing_required(self) -> List[str]:
        """Names of required settings that are not configured."""
        checks = {
            "WEBHOOK_TOKEN": self.webhook_token,
            "LDAP_SERVER": self.ldap_server,
            "LDAP_BIND_DN": self.ldap_bind_dn,
            "LDAP_BIND_PASSWORD": self.ldap_bind_password,
            "LDAP_BASE_DN": self.ldap_base_dn,
            "SMTP_HOST": self.smtp_host,
            "MAIL_FROM": self.mail_from,
        }
        return [name for name, value in checks.items() if not value]
