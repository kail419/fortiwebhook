"""Poll FortiClient EMS, detect registrations/overseas connections, and e-mail."""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import signal
import sqlite3
import ssl
import sys
import threading
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib import error, parse, request

from geoip2 import database as geoip_database
from geoip2.errors import AddressNotFoundError
from jinja2 import Environment, FileSystemLoader

from .config import Config
from .ems_config import EmsConfig
from .ldap_lookup import LdapLookupError, resolve_email
from .mailer import MailSendError, send_mail

log = logging.getLogger("ipsecalert.ems")
_TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "templates")


def _autoescape(template_name: Optional[str]) -> bool:
    return bool(template_name and template_name.endswith((".html.j2", ".html")))


class EmsMonitorError(RuntimeError):
    """Controlled EMS polling/configuration failure."""


@dataclass
class Endpoint:
    endpoint_id: str
    hostname: str = ""
    user: str = ""
    ip: str = ""
    country_code: str = ""
    country_name: str = ""
    status: str = ""
    registered_at: str = ""
    last_seen: str = ""


@dataclass
class Alert:
    kind: str
    label: str
    endpoint: Endpoint
    previous: Optional[Endpoint] = None


def _lookup(value: Any, path: str) -> Any:
    """Read a dotted path from dictionaries; an empty path returns the root."""
    if not path:
        return value
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, dict):
        for key in ("email", "username", "name", "value"):
            if value.get(key) not in (None, ""):
                return str(value[key]).strip()
        return ""
    return str(value).strip()


def _first(record: dict, fields: Iterable[str]) -> str:
    for field in fields:
        value = _text(_lookup(record, field))
        if value:
            return value
    return ""


def parse_endpoint(record: dict, config: EmsConfig) -> Optional[Endpoint]:
    endpoint_id = _first(record, config.id_fields)
    if not endpoint_id:
        return None
    return Endpoint(
        endpoint_id=endpoint_id,
        hostname=_first(record, config.hostname_fields),
        user=_first(record, config.user_fields),
        ip=_first(record, config.ip_fields),
        country_code=_first(record, config.country_fields),
        status=_first(record, config.status_fields).lower(),
        registered_at=_first(record, config.registered_fields),
        last_seen=_first(record, config.last_seen_fields),
    )


def _flatten_keys(record: dict, prefix: str = "") -> List[str]:
    keys: List[str] = []
    for key, value in record.items():
        path = f"{prefix}.{key}" if prefix else key
        keys.append(path)
        if isinstance(value, dict):
            keys.extend(_flatten_keys(value, path))
    return keys


class EmsApiClient:
    def __init__(self, config: EmsConfig):
        self.config = config
        try:
            if config.tls_validate:
                self.context = ssl.create_default_context(
                    cafile=(config.ca_cert or None)
                )
            else:
                self.context = ssl._create_unverified_context()  # noqa: SLF001
        except (OSError, ValueError) as exc:
            raise EmsMonitorError(f"Unable to load EMS CA certificate: {exc}") from exc

        token = f"{config.token_prefix} {config.api_token}".strip()
        self.headers = {
            "Accept": "application/json",
            "User-Agent": "IPsecAlert-EMS-Monitor/1.0",
            config.token_header: token,
        }
        self.base_origin = self._origin(config.api_url)

    @staticmethod
    def _origin(url: str) -> Tuple[str, str]:
        parsed = parse.urlsplit(url)
        return parsed.scheme.lower(), parsed.netloc.lower()

    def _request_json(self, url: str) -> Any:
        if self._origin(url) != self.base_origin:
            raise EmsMonitorError("EMS pagination URL points outside EMS_API_URL")
        req = request.Request(url, headers=self.headers, method="GET")
        try:
            with request.urlopen(
                req, timeout=self.config.timeout, context=self.context
            ) as response:
                body = response.read()
        except error.HTTPError as exc:
            detail = exc.read(1024).decode("utf-8", errors="replace").strip()
            raise EmsMonitorError(
                f"EMS API returned HTTP {exc.code}: {detail or exc.reason}"
            ) from exc
        except (error.URLError, OSError, TimeoutError) as exc:
            raise EmsMonitorError(f"EMS API request failed: {exc}") from exc
        try:
            return json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EmsMonitorError("EMS API response is not valid UTF-8 JSON") from exc

    def _extract_records(self, payload: Any) -> List[dict]:
        records = payload if isinstance(payload, list) else _lookup(
            payload, self.config.endpoints_key
        )
        if not isinstance(records, list):
            keys = sorted(payload.keys()) if isinstance(payload, dict) else []
            raise EmsMonitorError(
                "EMS_ENDPOINTS_KEY did not resolve to a JSON list; "
                f"top-level keys={keys}"
            )
        return [item for item in records if isinstance(item, dict)]

    def fetch_records(self) -> List[dict]:
        url = parse.urljoin(f"{self.config.api_url}/", self.config.endpoints_path)
        records: List[dict] = []
        seen_urls = set()
        for _page in range(self.config.max_pages):
            if url in seen_urls:
                raise EmsMonitorError("EMS API returned a pagination loop")
            seen_urls.add(url)
            payload = self._request_json(url)
            records.extend(self._extract_records(payload))
            next_value = (
                _text(_lookup(payload, self.config.next_key))
                if isinstance(payload, dict) and self.config.next_key
                else ""
            )
            if not next_value:
                return records
            url = parse.urljoin(url, next_value)
        raise EmsMonitorError(
            f"EMS API exceeded EMS_MAX_PAGES={self.config.max_pages}"
        )


class GeoResolver:
    def __init__(self, database_path: str):
        try:
            self.reader = geoip_database.Reader(database_path)
        except (OSError, ValueError) as exc:
            raise EmsMonitorError(f"Unable to open GeoIP database: {exc}") from exc

    def close(self) -> None:
        self.reader.close()

    def lookup(self, ip: str) -> Tuple[str, str]:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return "", ""
        if not address.is_global:
            return "", ""
        try:
            country = self.reader.country(str(address)).country
        except (AddressNotFoundError, ValueError):
            return "", ""
        return country.iso_code or "", country.name or ""


class StateStore:
    def __init__(self, path: str):
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        with self.connection:
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.connection.execute(
                """
                CREATE TABLE IF NOT EXISTS endpoint_state (
                    endpoint_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    user_name TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    country_code TEXT NOT NULL,
                    country_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def close(self) -> None:
        self.connection.close()

    def initialized(self) -> bool:
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key='initialized'"
        ).fetchone()
        return bool(row and row["value"] == "1")

    def mark_initialized(self) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO metadata(key, value) VALUES('initialized', '1') "
                "ON CONFLICT(key) DO UPDATE SET value='1'"
            )

    def get(self, endpoint_id: str) -> Optional[Endpoint]:
        row = self.connection.execute(
            "SELECT * FROM endpoint_state WHERE endpoint_id=?", (endpoint_id,)
        ).fetchone()
        if not row:
            return None
        return Endpoint(
            endpoint_id=row["endpoint_id"],
            hostname=row["hostname"],
            user=row["user_name"],
            ip=row["ip"],
            country_code=row["country_code"],
            country_name=row["country_name"],
            status=row["status"],
            registered_at=row["registered_at"],
            last_seen=row["last_seen"],
        )

    def put(self, endpoint: Endpoint) -> None:
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO endpoint_state(
                    endpoint_id, hostname, user_name, ip, country_code,
                    country_name, status, registered_at, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    hostname=excluded.hostname,
                    user_name=excluded.user_name,
                    ip=excluded.ip,
                    country_code=excluded.country_code,
                    country_name=excluded.country_name,
                    status=excluded.status,
                    registered_at=excluded.registered_at,
                    last_seen=excluded.last_seen,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (
                    endpoint.endpoint_id,
                    endpoint.hostname,
                    endpoint.user,
                    endpoint.ip,
                    endpoint.country_code,
                    endpoint.country_name,
                    endpoint.status,
                    endpoint.registered_at,
                    endpoint.last_seen,
                ),
            )


class AlertMailer:
    def __init__(self, smtp_config: Config):
        self.smtp_config = smtp_config
        self.templates = Environment(
            loader=FileSystemLoader(_TEMPLATE_DIR),
            autoescape=_autoescape,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def send(self, alert: Alert, to_addr: str) -> None:
        context = {
            "event_kind": alert.kind,
            "event_label": alert.label,
            "endpoint": alert.endpoint,
            "previous": alert.previous,
            "org_name": self.smtp_config.org_name,
        }
        subject = self.templates.get_template("ems_alert.subject.j2").render(**context)
        text_body = self.templates.get_template("ems_alert.txt.j2").render(**context)
        html_body = self.templates.get_template("ems_alert.html.j2").render(**context)
        send_mail(
            self.smtp_config,
            to_addr=to_addr,
            subject=subject,
            text_body=text_body,
            html_body=html_body,
            cc=self.smtp_config.mail_cc,
            bcc=self.smtp_config.mail_bcc,
        )


class EmsMonitor:
    def __init__(
        self,
        config: EmsConfig,
        api: EmsApiClient,
        geo: GeoResolver,
        state: StateStore,
        mailer: AlertMailer,
        smtp_config: Config,
    ):
        self.config = config
        self.api = api
        self.geo = geo
        self.state = state
        self.mailer = mailer
        self.smtp_config = smtp_config
        self.home_countries = {value.strip().lower() for value in config.home_countries}

    def _is_online(self, endpoint: Endpoint) -> bool:
        return endpoint.status.lower() in self.config.online_values

    def _is_foreign(self, endpoint: Endpoint) -> bool:
        values = {endpoint.country_code.lower(), endpoint.country_name.lower()} - {""}
        return bool(values) and values.isdisjoint(self.home_countries)

    def _enrich(self, endpoint: Endpoint) -> Endpoint:
        if endpoint.country_code or endpoint.country_name or not endpoint.ip:
            return endpoint
        country_code, country_name = self.geo.lookup(endpoint.ip)
        return replace(
            endpoint, country_code=country_code, country_name=country_name
        )

    def _detect(self, current: Endpoint, previous: Optional[Endpoint]) -> Optional[Alert]:
        if previous is None:
            if self._is_foreign(current):
                return Alert("overseas-registration", "海外新裝置連線", current, previous)
            return None
        if not (self._is_online(current) and self._is_foreign(current)):
            return None
        if not self._is_online(previous):
            return Alert("overseas-online", "海外裝置上線", current, previous)
        if current.ip and current.ip != previous.ip:
            return Alert("overseas-ip-change", "海外連線 IP 變更", current, previous)
        return None

    def _recipient(self, endpoint: Endpoint) -> str:
        # EMS commonly returns a UPN/e-mail. Use it directly so a transient LDAP
        # issue does not prevent a security notification to the user.
        candidate = endpoint.user.strip()
        forbidden = "\r\n,;<>"
        if (
            candidate.count("@") == 1
            and not any(ch.isspace() for ch in candidate)
            and not any(ch in candidate for ch in forbidden)
        ):
            return candidate
        if endpoint.user:
            try:
                email = resolve_email(self.smtp_config, endpoint.user)
            except LdapLookupError as exc:
                log.error(
                    "EMS recipient LDAP lookup failed user=%s: %s", endpoint.user, exc
                )
            else:
                if email:
                    return email
        return self.config.alert_to

    def run_once(self) -> Dict[str, int]:
        records = self.api.fetch_records()
        endpoints = [parse_endpoint(record, self.config) for record in records]
        endpoints = [endpoint for endpoint in endpoints if endpoint is not None]
        if records and not endpoints:
            raise EmsMonitorError(
                "No endpoint IDs were found; adjust EMS_ID_FIELDS for this API response"
            )

        initial_sync = not self.state.initialized()
        alerts_sent = 0
        skipped_records = len(records) - len(endpoints)
        for endpoint in endpoints:
            endpoint = self._enrich(endpoint)
            previous = self.state.get(endpoint.endpoint_id)
            alert = self._detect(endpoint, previous)
            if initial_sync and not self.config.alert_on_initial_sync:
                alert = None
            if alert:
                recipient = self._recipient(endpoint)
                try:
                    self.mailer.send(alert, recipient)
                except MailSendError as exc:
                    # Do not advance this endpoint's state; the next poll retries.
                    log.error(
                        "EMS alert send failed endpoint=%s: %s",
                        endpoint.endpoint_id,
                        exc,
                    )
                    continue
                alerts_sent += 1
                log.info(
                    "EMS alert sent kind=%s endpoint=%s country=%s ip=%s",
                    alert.kind,
                    endpoint.endpoint_id,
                    endpoint.country_code or endpoint.country_name,
                    endpoint.ip,
                )
            self.state.put(endpoint)

        self.state.mark_initialized()
        result = {
            "records": len(records),
            "endpoints": len(endpoints),
            "skipped": skipped_records,
            "alerts": alerts_sent,
        }
        log.info("EMS poll complete: %s", result)
        return result


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def _build_components() -> Tuple[EmsConfig, EmsApiClient, GeoResolver, StateStore, EmsMonitor]:
    ems_config = EmsConfig.from_env()
    smtp_config = Config.from_env()
    problems = ems_config.validation_errors(smtp_config.smtp_host, smtp_config.mail_from)
    if problems:
        raise EmsMonitorError("; ".join(problems))
    api = EmsApiClient(ems_config)
    geo = GeoResolver(ems_config.geoip_db)
    state = StateStore(ems_config.state_file)
    mailer = AlertMailer(smtp_config)
    monitor = EmsMonitor(ems_config, api, geo, state, mailer, smtp_config)
    return ems_config, api, geo, state, monitor


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--once", action="store_true", help="poll once and exit")
    parser.add_argument(
        "--validate-api",
        action="store_true",
        help="fetch once and print only record count/available field names",
    )
    args = parser.parse_args(argv)
    smtp_config = Config.from_env()
    _setup_logging(smtp_config.log_level)

    if args.validate_api:
        config = EmsConfig.from_env()
        problems = config.api_validation_errors()
        if problems:
            log.error("EMS API configuration failed: %s", "; ".join(problems))
            return 2
        try:
            records = EmsApiClient(config).fetch_records()
        except EmsMonitorError as exc:
            log.error("EMS API validation failed: %s", exc)
            return 2
        print(f"records={len(records)}")
        if records:
            print("fields=" + ",".join(sorted(_flatten_keys(records[0]))))
        return 0

    try:
        config, api, geo, state, monitor = _build_components()
    except EmsMonitorError as exc:
        log.error("EMS monitor configuration failed: %s", exc)
        return 2

    try:
        if args.once:
            monitor.run_once()
            return 0

        stop = threading.Event()

        def _stop(_signum, _frame):
            stop.set()

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        log.info("EMS monitor started; polling every %d seconds", config.poll_seconds)
        while not stop.is_set():
            try:
                monitor.run_once()
            except (EmsMonitorError, OSError, sqlite3.Error) as exc:
                log.error("EMS poll failed: %s", exc)
            stop.wait(config.poll_seconds)
        return 0
    finally:
        state.close()
        geo.close()


if __name__ == "__main__":
    sys.exit(main())
