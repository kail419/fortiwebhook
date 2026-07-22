"""Configuration for the optional FortiClient EMS polling service."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from .config import _get_bool, _get_int, _get_list, _get_secret


@dataclass
class EmsConfig:
    # Fortinet publishes the version-specific path in the authenticated FNDN
    # FortiAPI documentation, so it intentionally has no guessed default.
    api_url: str = ""
    endpoints_path: str = ""
    api_token: str = ""
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    endpoints_key: str = "data"
    next_key: str = "next"
    timeout: int = 20
    poll_seconds: int = 60
    max_pages: int = 100
    tls_validate: bool = True
    ca_cert: str = ""
    allow_http: bool = False

    alert_to: str = ""
    alert_on_initial_sync: bool = False
    home_countries: List[str] = field(default_factory=lambda: ["TW", "Taiwan"])
    state_file: str = "/data/ems-state.db"
    geoip_db: str = "/geoip/GeoLite2-Country.mmdb"

    id_fields: List[str] = field(
        default_factory=lambda: ["uuid", "endpoint_id", "id", "uid"]
    )
    hostname_fields: List[str] = field(
        default_factory=lambda: ["hostname", "host_name", "device_name", "name"]
    )
    user_fields: List[str] = field(
        default_factory=lambda: ["username", "user_name", "user", "logged_in_user"]
    )
    ip_fields: List[str] = field(
        default_factory=lambda: ["public_ip", "remote_ip", "ip_address", "ip"]
    )
    country_fields: List[str] = field(
        default_factory=lambda: ["country_code", "country", "geo.country_code"]
    )
    status_fields: List[str] = field(
        default_factory=lambda: ["connection_status", "status", "online"]
    )
    registered_fields: List[str] = field(
        default_factory=lambda: ["registered_at", "registration_time", "created_at"]
    )
    last_seen_fields: List[str] = field(
        default_factory=lambda: ["last_seen", "last_seen_at", "last_seen_time"]
    )
    online_values: List[str] = field(
        default_factory=lambda: ["online", "connected", "true", "1"]
    )

    @classmethod
    def from_env(cls) -> "EmsConfig":
        return cls(
            api_url=os.getenv("EMS_API_URL", "").rstrip("/"),
            endpoints_path=os.getenv("EMS_ENDPOINTS_PATH", ""),
            api_token=_get_secret("EMS_API_TOKEN"),
            token_header=os.getenv("EMS_API_TOKEN_HEADER", "Authorization"),
            token_prefix=os.getenv("EMS_API_TOKEN_PREFIX", "Bearer"),
            endpoints_key=os.getenv("EMS_ENDPOINTS_KEY", "data"),
            next_key=os.getenv("EMS_NEXT_KEY", "next"),
            timeout=_get_int("EMS_API_TIMEOUT", 20),
            poll_seconds=_get_int("EMS_POLL_SECONDS", 60),
            max_pages=_get_int("EMS_MAX_PAGES", 100),
            tls_validate=_get_bool("EMS_TLS_VALIDATE", True),
            ca_cert=os.getenv("EMS_CA_CERT", ""),
            allow_http=_get_bool("EMS_ALLOW_HTTP", False),
            alert_to=os.getenv("EMS_ALERT_TO", ""),
            alert_on_initial_sync=_get_bool("EMS_ALERT_ON_INITIAL_SYNC", False),
            home_countries=_get_list("EMS_HOME_COUNTRIES", ["TW", "Taiwan"]),
            state_file=os.getenv("EMS_STATE_FILE", "/data/ems-state.db"),
            geoip_db=os.getenv("EMS_GEOIP_DB", "/geoip/GeoLite2-Country.mmdb"),
            id_fields=_get_list("EMS_ID_FIELDS", ["uuid", "endpoint_id", "id", "uid"]),
            hostname_fields=_get_list(
                "EMS_HOSTNAME_FIELDS", ["hostname", "host_name", "device_name", "name"]
            ),
            user_fields=_get_list(
                "EMS_USER_FIELDS", ["username", "user_name", "user", "logged_in_user"]
            ),
            ip_fields=_get_list(
                "EMS_IP_FIELDS", ["public_ip", "remote_ip", "ip_address", "ip"]
            ),
            country_fields=_get_list(
                "EMS_COUNTRY_FIELDS", ["country_code", "country", "geo.country_code"]
            ),
            status_fields=_get_list(
                "EMS_STATUS_FIELDS", ["connection_status", "status", "online"]
            ),
            registered_fields=_get_list(
                "EMS_REGISTERED_FIELDS",
                ["registered_at", "registration_time", "created_at"],
            ),
            last_seen_fields=_get_list(
                "EMS_LAST_SEEN_FIELDS", ["last_seen", "last_seen_at", "last_seen_time"]
            ),
            online_values=[
                value.lower()
                for value in _get_list(
                    "EMS_ONLINE_VALUES", ["online", "connected", "true", "1"]
                )
            ],
        )

    def api_validation_errors(self) -> List[str]:
        checks = {
            "EMS_API_URL": self.api_url,
            "EMS_ENDPOINTS_PATH": self.endpoints_path,
            "EMS_API_TOKEN (or EMS_API_TOKEN_FILE)": self.api_token,
        }
        errors = [f"{name} is required" for name, value in checks.items() if not value]
        if self.api_url and not self.api_url.startswith("https://"):
            if not (self.allow_http and self.api_url.startswith("http://")):
                errors.append("EMS_API_URL must use HTTPS (or set EMS_ALLOW_HTTP=true)")
        if self.poll_seconds < 10:
            errors.append("EMS_POLL_SECONDS must be at least 10")
        if self.timeout < 1:
            errors.append("EMS_API_TIMEOUT must be positive")
        if self.max_pages < 1:
            errors.append("EMS_MAX_PAGES must be positive")
        if not self.id_fields:
            errors.append("EMS_ID_FIELDS must contain at least one field")
        return errors

    def validation_errors(self, smtp_host: str = "", mail_from: str = "") -> List[str]:
        errors = self.api_validation_errors()
        checks = {
            "EMS_ALERT_TO": self.alert_to,
            "EMS_GEOIP_DB": self.geoip_db,
            "SMTP_HOST": smtp_host,
            "MAIL_FROM": mail_from,
        }
        errors.extend(
            f"{name} is required" for name, value in checks.items() if not value
        )
        return errors
