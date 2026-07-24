"""Unit tests for EMS parsing, state transitions, and user notifications."""
import sqlite3
import tempfile
import unittest
from unittest import mock
from urllib import parse

from app.config import Config
from app.ems_config import EmsConfig
from app.ems_monitor import (
    Alert,
    AlertMailer,
    EmsApiClient,
    EmsMonitor,
    EmsMonitorError,
    Endpoint,
    StateStore,
    parse_endpoint,
)
from app.mailer import MailSendError


class FakeApi:
    def __init__(self, records=None):
        self.records = records or []

    def fetch_records(self):
        return self.records


class FakeGeo:
    def __init__(self, result=("", "")):
        self.result = result

    def lookup(self, _ip):
        return self.result


class FakeMailer:
    def __init__(self):
        self.sent = []
        self.error = None

    def send(self, alert, recipient):
        if self.error:
            raise self.error
        self.sent.append((alert, recipient))


def _ems_config(**overrides):
    cfg = EmsConfig(
        api_url="https://ems.example.com",
        endpoints_path="/api/endpoints",
        api_token="token",
        alert_to="soc@example.com",
        state_file=":memory:",
        geoip_db="/geo.mmdb",
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def _smtp_config():
    return Config(
        smtp_host="smtp.example.com",
        mail_from="alerts@example.com",
        ldap_server="dc.example.com",
        ldap_bind_dn="reader@example.com",
        ldap_bind_password="secret",
        ldap_base_dn="DC=example,DC=com",
    )


def _record(**overrides):
    value = {
        "uuid": "endpoint-1",
        "hostname": "LAPTOP-1",
        "username": "user@example.com",
        "public_ip": "8.8.8.8",
        "country_code": "US",
        "status": "online",
        "last_seen": "2026-07-22T12:00:00Z",
    }
    value.update(overrides)
    return value


class EndpointParsingTests(unittest.TestCase):
    def test_configurable_dotted_fields(self):
        cfg = _ems_config(
            id_fields=["identity.uuid"],
            user_fields=["identity.email"],
            ip_fields=["network.public_ip"],
        )
        endpoint = parse_endpoint(
            {
                "identity": {"uuid": "u1", "email": "a@example.com"},
                "network": {"public_ip": "1.1.1.1"},
            },
            cfg,
        )
        self.assertEqual(endpoint.endpoint_id, "u1")
        self.assertEqual(endpoint.user, "a@example.com")
        self.assertEqual(endpoint.ip, "1.1.1.1")

    def test_reads_user_from_fct_users_array(self):
        endpoint = parse_endpoint(
            {
                "uid": "u1",
                "host": "LAPTOP-1",
                "public_ip_addr": "8.8.8.8",
                "is_ems_online": True,
                "is_ems_registered": True,
                "fct_users": [
                    {
                        "user_email": "user@example.com",
                        "last_seen": "2026-07-22T12:00:00Z",
                    }
                ],
            },
            _ems_config(),
        )
        self.assertEqual(endpoint.user, "user@example.com")
        self.assertEqual(endpoint.last_seen, "2026-07-22T12:00:00Z")
        self.assertEqual(endpoint.status, "online")
        self.assertEqual(endpoint.registration_status, "registered")

    def test_record_without_id_is_skipped(self):
        self.assertIsNone(parse_endpoint({"hostname": "unknown"}, _ems_config()))

    def test_reads_country_name_from_dedicated_field(self):
        endpoint = parse_endpoint(
            _record(country_code="US", country_name="United States"), _ems_config()
        )
        self.assertEqual(endpoint.country_code, "US")
        self.assertEqual(endpoint.country_name, "United States")


class ApiClientTests(unittest.TestCase):
    def test_extracts_configured_record_list(self):
        client = EmsApiClient(_ems_config(endpoints_key="result.items"))
        records = client._extract_records({"result": {"items": [_record()]}})
        self.assertEqual(records[0]["uuid"], "endpoint-1")

    def test_bad_list_key_has_actionable_error(self):
        client = EmsApiClient(_ems_config(endpoints_key="data"))
        with self.assertRaisesRegex(EmsMonitorError, "top-level keys"):
            client._extract_records({"results": []})

    def test_reports_expired_ems_session(self):
        client = EmsApiClient(_ems_config())
        payload = {
            "result": {
                "retval": -4,
                "message": "Session has expired or does not exist.",
            }
        }
        with self.assertRaisesRegex(EmsMonitorError, "Session has expired"):
            client._extract_records(payload)

    def test_refuses_to_send_token_to_other_origin(self):
        client = EmsApiClient(_ems_config())
        with self.assertRaisesRegex(EmsMonitorError, "outside EMS_API_URL"):
            client._request_json("https://attacker.example/api")

    def test_fetches_all_offset_pages_using_total(self):
        client = EmsApiClient(
            _ems_config(
                endpoints_path="/api/v1/endpoints/index?offset=0",
                endpoints_key="data.endpoints",
                total_key="data.total",
            )
        )
        pages = [
            {
                "result": {"retval": 0, "message": None},
                "data": {"endpoints": [{"uid": "1"}, {"uid": "2"}], "total": 3},
            },
            {
                "result": {"retval": 0, "message": None},
                "data": {"endpoints": [{"uid": "3"}], "total": 3},
            },
        ]
        with mock.patch.object(client, "_request_json", side_effect=pages) as get:
            records = client.fetch_records()

        self.assertEqual([item["uid"] for item in records], ["1", "2", "3"])
        second_url = get.call_args_list[1].args[0]
        self.assertEqual(
            parse.parse_qs(parse.urlsplit(second_url).query)["offset"], ["2"]
        )


class StateStoreTests(unittest.TestCase):
    def test_adds_registration_status_to_existing_database(self):
        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/state.db"
            connection = sqlite3.connect(path)
            connection.execute(
                """
                CREATE TABLE endpoint_state (
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
            connection.commit()
            connection.close()

            state = StateStore(path)
            columns = {
                row[1]
                for row in state.connection.execute(
                    "PRAGMA table_info(endpoint_state)"
                ).fetchall()
            }
            state.close()

        self.assertIn("registration_status", columns)


class MonitorTransitionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.state = StateStore(f"{self.tempdir.name}/state.db")
        self.mailer = FakeMailer()
        self.api = FakeApi()
        self.config = _ems_config()
        self.monitor = EmsMonitor(
            self.config,
            self.api,
            FakeGeo(),
            self.state,
            self.mailer,
            _smtp_config(),
        )

    def tearDown(self):
        self.state.close()
        self.tempdir.cleanup()

    def test_first_poll_seeds_without_alerting(self):
        self.api.records = [_record()]
        result = self.monitor.run_once()
        self.assertEqual(result["alerts"], 0)
        self.assertTrue(self.state.initialized())
        self.assertIsNotNone(self.state.get("endpoint-1"))

    def test_new_foreign_endpoint_after_baseline_alerts_user(self):
        self.monitor.run_once()  # empty baseline
        self.api.records = [_record()]
        result = self.monitor.run_once()
        self.assertEqual(result["alerts"], 1)
        alert, recipient = self.mailer.sent[0]
        self.assertEqual(alert.kind, "overseas-registration")
        self.assertEqual(recipient, "user@example.com")

    def test_new_domestic_endpoint_does_not_alert(self):
        self.monitor.run_once()
        self.api.records = [_record(country_code="TW")]
        result = self.monitor.run_once()
        self.assertEqual(result["alerts"], 0)

    def test_offline_to_online_overseas_alerts(self):
        self.api.records = [_record(status="offline")]
        self.monitor.run_once()
        self.api.records = [_record(status="online")]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][0].kind, "overseas-online")

    def test_unregistered_to_registered_overseas_alerts(self):
        self.api.records = [_record(is_ems_registered=False)]
        self.monitor.run_once()
        self.api.records = [_record(is_ems_registered=True)]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][0].kind, "overseas-registration")

    def test_blank_legacy_state_does_not_create_upgrade_alert(self):
        self.api.records = [_record(status="", is_ems_registered="")]
        self.monitor.run_once()
        self.api.records = [_record(is_ems_online=True, is_ems_registered=True)]
        result = self.monitor.run_once()
        self.assertEqual(result["alerts"], 0)

    def test_foreign_ip_change_alerts(self):
        self.api.records = [_record(public_ip="8.8.8.8")]
        self.monitor.run_once()
        self.api.records = [_record(public_ip="1.1.1.1")]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][0].kind, "overseas-ip-change")

    def test_geoip_enriches_when_api_has_no_country(self):
        self.monitor.geo = FakeGeo(("JP", "Japan"))
        self.monitor.run_once()
        self.api.records = [_record(country_code="")]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][0].endpoint.country_name, "Japan")

    def test_geoip_names_country_when_api_gives_only_code(self):
        self.monitor.geo = FakeGeo(("US", "United States"))
        self.monitor.run_once()
        self.api.records = [_record(country_code="US")]
        self.monitor.run_once()
        endpoint = self.mailer.sent[0][0].endpoint
        self.assertEqual(endpoint.country_code, "US")
        self.assertEqual(endpoint.country_name, "United States")

    def test_geoip_name_ignored_when_it_disagrees_with_api_code(self):
        self.monitor.geo = FakeGeo(("CN", "China"))
        self.monitor.run_once()
        self.api.records = [_record(country_code="US")]
        self.monitor.run_once()
        endpoint = self.mailer.sent[0][0].endpoint
        self.assertEqual(endpoint.country_code, "US")
        self.assertEqual(endpoint.country_name, "")

    @mock.patch("app.ems_monitor.resolve_email", return_value="user@example.com")
    def test_account_name_is_resolved_through_ldap(self, lookup):
        self.monitor.run_once()
        self.api.records = [_record(username="CORP\\user")]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][1], "user@example.com")
        lookup.assert_called_once()

    @mock.patch("app.ems_monitor.resolve_email", return_value=None)
    def test_fallback_recipient_when_ldap_has_no_mailbox(self, _lookup):
        self.monitor.run_once()
        self.api.records = [_record(username="user")]
        self.monitor.run_once()
        self.assertEqual(self.mailer.sent[0][1], "soc@example.com")

    def test_mail_failure_does_not_consume_event(self):
        self.monitor.run_once()
        self.api.records = [_record()]
        self.mailer.error = MailSendError("down")
        self.monitor.run_once()
        self.assertIsNone(self.state.get("endpoint-1"))
        self.mailer.error = None
        self.monitor.run_once()
        self.assertEqual(len(self.mailer.sent), 1)


class EmsTemplateTests(unittest.TestCase):
    def _render(self, alert):
        with mock.patch("app.ems_monitor.send_mail") as send:
            AlertMailer(_smtp_config()).send(alert, "user@example.com")
        return send.call_args.kwargs

    @mock.patch("app.ems_monitor.send_mail")
    def test_mail_emphasizes_source_ip_and_escapes_html(self, send):
        endpoint = Endpoint(
            endpoint_id="1",
            hostname="<device>",
            user="user@example.com",
            ip="8.8.8.8",
            country_code="US",
            country_name="United States",
            status="online",
        )
        AlertMailer(_smtp_config()).send(
            Alert("overseas-online", "海外裝置上線", endpoint),
            "user@example.com",
        )
        kwargs = send.call_args.kwargs
        self.assertIn("8.8.8.8", kwargs["text_body"])
        self.assertIn("8.8.8.8", kwargs["html_body"])
        self.assertNotIn("<device>", kwargs["html_body"])
        self.assertIn("&lt;device&gt;", kwargs["html_body"])

    def test_event_label_appears_in_subject_and_bodies(self):
        endpoint = Endpoint(
            endpoint_id="1",
            ip="8.8.8.8",
            country_code="US",
            country_name="United States",
            status="online",
        )
        kwargs = self._render(Alert("overseas-online", "海外裝置上線", endpoint))
        for part in ("subject", "text_body", "html_body"):
            self.assertIn("海外裝置上線", kwargs[part])
        # The bilingual e-mail also names the event in English.
        self.assertIn("Overseas device came online", kwargs["subject"])
        self.assertIn("Overseas device came online", kwargs["html_body"])

    def test_ip_change_shows_previous_ip(self):
        current = Endpoint(
            endpoint_id="1", ip="1.1.1.1", country_code="US", status="online"
        )
        previous = Endpoint(endpoint_id="1", ip="8.8.8.8", status="online")
        kwargs = self._render(
            Alert("overseas-ip-change", "海外連線 IP 變更", current, previous)
        )
        for part in ("text_body", "html_body"):
            self.assertIn("1.1.1.1", kwargs[part])
            self.assertIn("8.8.8.8", kwargs[part])

    def test_non_ip_change_event_omits_previous_ip(self):
        current = Endpoint(
            endpoint_id="1", ip="1.1.1.1", country_code="US", status="online"
        )
        previous = Endpoint(endpoint_id="1", ip="8.8.8.8", status="offline")
        kwargs = self._render(
            Alert("overseas-online", "海外裝置上線", current, previous)
        )
        self.assertNotIn("8.8.8.8", kwargs["text_body"])
        self.assertNotIn("8.8.8.8", kwargs["html_body"])

    def test_country_name_and_code_are_combined(self):
        endpoint = Endpoint(
            endpoint_id="1",
            ip="8.8.8.8",
            country_code="US",
            country_name="United States",
            status="online",
        )
        kwargs = self._render(Alert("overseas-online", "海外裝置上線", endpoint))
        self.assertIn("United States (US)", kwargs["text_body"])
        self.assertIn("United States (US)", kwargs["html_body"])


if __name__ == "__main__":
    unittest.main()
