"""Configuration for the optional FortiClient EMS polling service."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List

from .config import _get_bool, _get_int, _get_list, _get_secret


@dataclass
class EmsConfig:
    # Observed from the EMS 7.4.7 web console. Keep configurable because this
    # UI-facing endpoint may change between EMS patch releases.
    api_url: str = ""
    endpoints_path: str = "/api/v1/endpoints/index?offset=0"
    api_token: str = ""
    token_header: str = "Authorization"
    token_prefix: str = "Bearer"
    endpoints_key: str = "data.endpoints"
    next_key: str = ""
    total_key: str = "data.total"
    offset_param: str = "offset"
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
        default_factory=lambda: [
            "uid",
            "device_id",
            "forticlient_id",
            "uuid",
            "endpoint_id",
            "id",
        ]
    )
    hostname_fields: List[str] = field(
        default_factory=lambda: ["host", "name", "hostname", "device_name"]
    )
    user_fields: List[str] = field(
        default_factory=lambda: [
            "fct_users.0.user_email",
            "fct_users.0.auth_user_name",
            "fct_users.0.machine_user_name",
            "username",
        ]
    )
    ip_fields: List[str] = field(
        default_factory=lambda: ["public_ip_addr", "ip_addr", "public_ip", "ip"]
    )
    country_fields: List[str] = field(
        default_factory=lambda: ["country_code", "country", "geo.country_code"]
    )
    country_name_fields: List[str] = field(
        default_factory=lambda: ["country_name", "geo.country_name", "country"]
    )
    status_fields: List[str] = field(
        default_factory=lambda: [
            "is_ems_online",
            "connection_status",
            "status",
            "online",
        ]
    )
    registration_status_fields: List[str] = field(
        default_factory=lambda: ["is_ems_registered", "registration_status"]
    )
    registered_fields: List[str] = field(
        default_factory=lambda: ["registered_at", "registration_time", "created_at"]
    )
    last_seen_fields: List[str] = field(
        default_factory=lambda: [
            "last_seen",
            "fct_users.0.last_seen",
            "last_seen_at",
        ]
    )
    online_values: List[str] = field(
        default_factory=lambda: ["online", "connected", "true", "1"]
    )
    registered_values: List[str] = field(
        default_factory=lambda: ["registered", "true", "1"]
    )

    @classmethod
    def from_env(cls) -> "EmsConfig":
        return cls(
            api_url=os.getenv("EMS_API_URL", "").rstrip("/"),
            endpoints_path=os.getenv(
                "EMS_ENDPOINTS_PATH", "/api/v1/endpoints/index?offset=0"
            ),
            api_token=_get_secret("EMS_API_TOKEN"),
            token_header=os.getenv("EMS_API_TOKEN_HEADER", "Authorization"),
            token_prefix=os.getenv("EMS_API_TOKEN_PREFIX", "Bearer"),
            endpoints_key=os.getenv("EMS_ENDPOINTS_KEY", "data.endpoints"),
            next_key=os.getenv("EMS_NEXT_KEY", ""),
            total_key=os.getenv("EMS_TOTAL_KEY", "data.total"),
            offset_param=os.getenv("EMS_OFFSET_PARAM", "offset"),
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
            id_fields=_get_list(
                "EMS_ID_FIELDS",
                [
                    "uid",
                    "device_id",
                    "forticlient_id",
                    "uuid",
                    "endpoint_id",
                    "id",
                ],
            ),
            hostname_fields=_get_list(
                "EMS_HOSTNAME_FIELDS", ["host", "name", "hostname", "device_name"]
            ),
            user_fields=_get_list(
                "EMS_USER_FIELDS",
                [
                    "fct_users.0.user_email",
                    "fct_users.0.auth_user_name",
                    "fct_users.0.machine_user_name",
                    "username",
                ],
            ),
            ip_fields=_get_list(
                "EMS_IP_FIELDS", ["public_ip_addr", "ip_addr", "public_ip", "ip"]
            ),
            country_fields=_get_list(
                "EMS_COUNTRY_FIELDS", ["country_code", "country", "geo.country_code"]
            ),
            country_name_fields=_get_list(
                "EMS_COUNTRY_NAME_FIELDS",
                ["country_name", "geo.country_name", "country"],
            ),
            status_fields=_get_list(
                "EMS_STATUS_FIELDS",
                ["is_ems_online", "connection_status", "status", "online"],
            ),
            registration_status_fields=_get_list(
                "EMS_REGISTRATION_STATUS_FIELDS",
                ["is_ems_registered", "registration_status"],
            ),
            registered_fields=_get_list(
                "EMS_REGISTERED_FIELDS",
                ["registered_at", "registration_time", "created_at"],
            ),
            last_seen_fields=_get_list(
                "EMS_LAST_SEEN_FIELDS",
                ["last_seen", "fct_users.0.last_seen", "last_seen_at"],
            ),
            online_values=[
                value.lower()
                for value in _get_list(
                    "EMS_ONLINE_VALUES", ["online", "connected", "true", "1"]
                )
            ],
            registered_values=[
                value.lower()
                for value in _get_list(
                    "EMS_REGISTERED_VALUES", ["registered", "true", "1"]
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
