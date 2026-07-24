"""Unit tests for the pure logic (no network). Run: python -m unittest -v"""
import time
import unittest
from unittest import mock

from jinja2 import TemplateError

from app.config import Config
from app.ldap_lookup import normalize_username
from app.mailer import MailSendError
from app.notifier import Notifier, _DedupCache, parse_event


class NormalizeUsernameTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(normalize_username("jdoe"), "jdoe")

    def test_downlevel_domain(self):
        self.assertEqual(normalize_username("CORP\\jdoe"), "jdoe")

    def test_upn_stripped_by_default(self):
        self.assertEqual(normalize_username("jdoe@corp.example.com"), "jdoe")

    def test_upn_kept_when_disabled(self):
        self.assertEqual(
            normalize_username("jdoe@corp.example.com", strip_upn_suffix=False),
            "jdoe@corp.example.com",
        )

    def test_blank(self):
        self.assertEqual(normalize_username("   "), "")


class ParseEventTests(unittest.TestCase):
    def test_fortigate_raw_field_names(self):
        event = parse_event(
            {"user": "jdoe", "remip": "203.0.113.5",
             "srccountry": "Russian Federation", "eventtime": "t"}
        )
        self.assertEqual(event.ip, "203.0.113.5")
        self.assertEqual(event.country, "Russian Federation")
        self.assertEqual(event.time, "t")

    def test_missing_fields_default_empty(self):
        event = parse_event({"user": "jdoe"})
        self.assertEqual(event.ip, "")
        self.assertEqual(event.country, "")

    def test_city_from_srccity(self):
        event = parse_event({"user": "jdoe", "srccity": "Taichung City"})
        self.assertEqual(event.city, "Taichung City")

    def test_unexpanded_fortigate_variables_are_ignored(self):
        event = parse_event(
            {
                "user": "jdoe",
                "city": "%%log.srccity%%",
                "country": "Taiwan",
            }
        )
        self.assertEqual(event.city, "")
        self.assertEqual(event.country, "Taiwan")


class DedupCacheTests(unittest.TestCase):
    def test_second_hit_within_window_is_deduped(self):
        cache = _DedupCache(window_seconds=300)
        self.assertFalse(cache.seen_recently("k"))
        self.assertTrue(cache.seen_recently("k"))

    def test_zero_window_never_dedupes(self):
        cache = _DedupCache(window_seconds=0)
        self.assertFalse(cache.seen_recently("k"))
        self.assertFalse(cache.seen_recently("k"))


def _base_config(**overrides) -> Config:
    cfg = Config(
        webhook_token="t", ldap_server="dc", ldap_bind_dn="b",
        ldap_bind_password="p", ldap_base_dn="dc=x", smtp_host="smtp",
        mail_from="from@x", dedup_window_seconds=300,
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class NotifierHandleTests(unittest.TestCase):
    def test_skips_when_no_user(self):
        result = Notifier(_base_config()).handle({"ip": "1.2.3.4"})
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "no-user-in-payload")

    def test_skips_ignored_country(self):
        cfg = _base_config(ignore_countries=["taiwan"])
        result = Notifier(cfg).handle({"user": "jdoe", "country": "Taiwan"})
        self.assertEqual(result["reason"], "ignored-country")

    def test_dedup_second_call_skipped(self):
        notifier = Notifier(_base_config())
        payload = {"user": "jdoe", "ip": "1.2.3.4", "country": "X"}
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch("app.notifier.send_mail") as send:
            first = notifier.handle(dict(payload))
            second = notifier.handle(dict(payload))
        self.assertEqual(first["status"], "sent")
        self.assertEqual(second["reason"], "deduplicated")
        self.assertEqual(send.call_count, 1)

    def test_smtp_failure_releases_dedup_for_retry(self):
        notifier = Notifier(_base_config())
        payload = {"user": "jdoe", "ip": "1.2.3.4", "country": "X"}
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"):
            with mock.patch("app.notifier.send_mail", side_effect=MailSendError("boom")):
                first = notifier.handle(dict(payload))
            with mock.patch("app.notifier.send_mail") as send:
                second = notifier.handle(dict(payload))
        self.assertEqual(first["status"], "error")       # first send failed
        self.assertEqual(second["status"], "sent")       # retry NOT deduplicated
        send.assert_called_once()

    def test_template_failure_releases_dedup_for_retry(self):
        notifier = Notifier(_base_config())
        payload = {"user": "jdoe", "ip": "1.2.3.4", "country": "X"}
        rendered = ("subject", "plain", "<p>html</p>")
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch.object(
                 notifier, "_render", side_effect=[TemplateError("broken"), rendered]
             ), \
             mock.patch("app.notifier.send_mail") as send:
            first = notifier.handle(dict(payload))
            second = notifier.handle(dict(payload))
        self.assertEqual(first["reason"], "template-error")
        self.assertEqual(second["status"], "sent")
        send.assert_called_once()

    def test_sent_path_calls_mailer(self):
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x") as lookup, \
             mock.patch("app.notifier.send_mail") as send:
            result = Notifier(_base_config()).handle(
                {"user": "jdoe", "ip": "1.2.3.4", "country": "X"}
            )
        lookup.assert_called_once()
        send.assert_called_once()
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["recipient"], "jdoe@x")

    def test_email_not_found_triggers_fallback(self):
        cfg = _base_config(fallback_email="soc@x")
        with mock.patch("app.notifier.resolve_email", return_value=None), \
             mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle({"user": "ghost", "ip": "1.1.1.1"})
        self.assertEqual(result["reason"], "email-not-found")
        self.assertTrue(result["fallback_notified"])
        send.assert_called_once()  # the fallback notice

    def test_ldap_error_returns_error_status(self):
        from app.ldap_lookup import LdapLookupError
        cfg = _base_config(fallback_email="")  # no fallback
        with mock.patch("app.notifier.resolve_email",
                        side_effect=LdapLookupError("boom")):
            result = Notifier(cfg).handle({"user": "jdoe", "ip": "1.1.1.1"})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "ldap-error")


class RenderTests(unittest.TestCase):
    def test_html_escapes_injection(self):
        notifier = Notifier(_base_config())
        from app.notifier import Event
        _, _, html = notifier._render(
            Event(user="<b>x</b>", ip="1.1.1.1", country="X", time="t"),
            recipient="a@x",
        )
        self.assertNotIn("<b>x</b>", html)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)

    def test_location_combines_city_and_country(self):
        from app.notifier import Event
        subject, text, html = Notifier(_base_config())._render(
            Event(user="u", ip="1.1.1.1", country="Taiwan", city="Taichung City", time="t"),
            recipient="u@x",
        )
        self.assertEqual(
            subject,
            "[資安通知] 偵測到您的帳號自 Taiwan 連線 VPN / Security Alert",
        )
        self.assertIn("Taichung City, Taiwan", text)
        self.assertIn("Taichung City, Taiwan", html)
        self.assertIn(
            "系統偵測到您的帳號自 Taichung City, Taiwan 建立了 VPN 連線。",
            text,
        )
        self.assertIn("建立了 VPN 連線。", html)
        self.assertNotIn("建立了一次", text)
        self.assertNotIn("建立了一次", html)
        self.assertNotIn("VPN（IPsec）", text)
        self.assertNotIn("VPN（IPsec）", html)

    def test_location_omits_unexpanded_city_variable(self):
        event = parse_event(
            {"user": "u", "city": "%%log.srccity%%", "country": "Taiwan"}
        )
        _, text, html = Notifier(_base_config())._render(event, recipient="u@x")
        self.assertIn("位置 Location: Taiwan", text)
        self.assertIn(">Taiwan</td>", html)
        self.assertNotIn("%%log.srccity%%", text)
        self.assertNotIn("%%log.srccity%%", html)

    def test_warning_has_no_security_contact(self):
        from app.notifier import Event
        cfg = _base_config(security_contact="資安專線 #1234")
        _, text, html = Notifier(cfg)._render(Event(user="u"), recipient="u@x")
        self.assertIn("⚠ 若「不是」您本人操作", text)
        self.assertIn("若「不是」您本人操作", html)
        self.assertNotIn("聯絡窗口", text)
        self.assertNotIn("聯絡窗口", html)
        self.assertNotIn("#1234", text)
        self.assertNotIn("#1234", html)
        self.assertNotIn("通報資訊安全單位", text)
        self.assertNotIn("通報資訊安全單位", html)

    def test_static_custom_subject_remains_compatible(self):
        from app.notifier import Event
        cfg = _base_config(mail_subject="Existing static subject")
        subject, _, _ = Notifier(cfg)._render(
            Event(user="u", country="Taiwan"), recipient="u@x"
        )
        self.assertEqual(subject, "Existing static subject")


class TeamEventRoutingTests(unittest.TestCase):
    def _team_config(self, **overrides) -> Config:
        overrides.setdefault("team_email", ["soc@x"])
        return _base_config(**overrides)

    def test_config_change_goes_to_team(self):
        cfg = self._team_config()
        payload = {"event": "config-change", "admin": "root",
                   "srcip": "10.0.0.9", "cfgpath": "firewall.policy", "action": "edit"}
        with mock.patch("app.notifier.resolve_email") as lookup, \
             mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle(payload)
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["event"], "config-change")
        self.assertEqual(result["recipient"], "soc@x")
        lookup.assert_not_called()          # team events never hit LDAP
        send.assert_called_once()
        self.assertEqual(send.call_args.kwargs["to_addr"], "soc@x")
        self.assertIn("設定變更", send.call_args.kwargs["subject"])

    def test_team_event_without_recipient_is_skipped(self):
        cfg = _base_config(team_email=[], fallback_email="")
        with mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle({"event": "config-change"})
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(result["reason"], "no-team-recipient")
        send.assert_not_called()

    def test_team_event_falls_back_to_fallback_email(self):
        cfg = _base_config(team_email=[], fallback_email="soc@x")
        with mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle({"event": "admin-login", "admin": "root"})
        self.assertEqual(result["status"], "sent")
        self.assertEqual(send.call_args.kwargs["to_addr"], "soc@x")

    def test_extra_team_recipients_become_cc(self):
        cfg = self._team_config(team_email=["soc@x", "ops@x"])
        with mock.patch("app.notifier.send_mail") as send:
            Notifier(cfg).handle({"event": "ha-event"})
        self.assertEqual(send.call_args.kwargs["to_addr"], "soc@x")
        self.assertIn("ops@x", send.call_args.kwargs["cc"])

    def test_audience_override_routes_vpn_to_team(self):
        cfg = self._team_config(event_audience_overrides={"vpn-login": "team"})
        payload = {"subtype": "vpn", "user": "jdoe", "ip": "1.1.1.1"}
        with mock.patch("app.notifier.resolve_email") as lookup, \
             mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle(payload)
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["recipient"], "soc@x")
        lookup.assert_not_called()
        send.assert_called_once()

    def test_disabled_event_is_skipped(self):
        cfg = self._team_config(disabled_events=["config-change"])
        with mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle({"event": "config-change"})
        self.assertEqual(result["reason"], "event-disabled")
        send.assert_not_called()

    def test_unknown_event_uses_generic_team_alert(self):
        cfg = self._team_config()
        payload = {"type": "traffic", "subtype": "forward", "srcip": "1.2.3.4"}
        with mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle(payload)
        self.assertEqual(result["status"], "sent")
        self.assertEqual(result["event"], "fortigate-event")
        self.assertIn("FortiGate 事件", send.call_args.kwargs["text_body"])

    def test_team_dedup_suppresses_repeat(self):
        cfg = self._team_config()
        payload = {"event": "ips-attack", "attack": "Bad.Sig", "srcip": "9.9.9.9"}
        with mock.patch("app.notifier.send_mail") as send:
            first = Notifier(cfg).handle(dict(payload))
            notifier = Notifier(cfg)  # fresh cache; re-run to prove first send happened
            second_same = notifier.handle(dict(payload))
            third_same = notifier.handle(dict(payload))
        self.assertEqual(first["status"], "sent")
        self.assertEqual(second_same["status"], "sent")
        self.assertEqual(third_same["reason"], "deduplicated")

    def test_team_smtp_error_is_error(self):
        cfg = self._team_config()
        with mock.patch("app.notifier.send_mail", side_effect=MailSendError("boom")):
            result = Notifier(cfg).handle({"event": "config-change"})
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["reason"], "smtp-error")

    def test_both_audience_notifies_user_and_team(self):
        cfg = self._team_config(event_audience_overrides={"admin-login": "both"})
        payload = {"event": "admin-login", "user": "jdoe", "ip": "1.1.1.1", "admin": "jdoe"}
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch("app.notifier.send_mail") as send:
            result = Notifier(cfg).handle(payload)
        self.assertEqual(result["status"], "sent")   # team result is canonical
        self.assertEqual(send.call_count, 2)          # team + user copies


class TeamRenderTests(unittest.TestCase):
    def test_team_alert_lists_all_fields_and_escapes_html(self):
        from app.events import _BY_KEY
        from app.notifier import Event
        cfg = _base_config(team_email=["soc@x"], org_name="Acme")
        event = Event(user="jdoe", ip="9.9.9.9",
                      raw={"admin": "<b>root</b>", "cfgpath": "firewall.policy"})
        subject, text, html = Notifier(cfg)._render_team(event, _BY_KEY["config-change"])
        self.assertIn("設定變更", subject)
        self.assertIn("警告 / Warning", subject)
        self.assertIn("firewall.policy", text)
        self.assertIn("firewall.policy", html)
        # HTML values are escaped; the plaintext part keeps the raw value.
        self.assertNotIn("<b>root</b>", html)
        self.assertIn("&lt;b&gt;root&lt;/b&gt;", html)
        self.assertIn("<b>root</b>", text)


if __name__ == "__main__":
    unittest.main()
