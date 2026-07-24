"""Unit tests for FortiGate event classification and routing (no network)."""
import unittest

from app.events import (
    BOTH,
    GENERIC,
    TEAM,
    USER,
    classify,
    clean_value,
    first_value,
    humanize_field,
    resolve_audience,
)


class CleanValueTests(unittest.TestCase):
    def test_strips_and_coerces(self):
        self.assertEqual(clean_value("  x  "), "x")
        self.assertEqual(clean_value(0), "0")
        self.assertEqual(clean_value(None), "")

    def test_drops_unexpanded_fortigate_variable(self):
        self.assertEqual(clean_value("%%log.srccity%%"), "")

    def test_first_value_priority(self):
        payload = {"a": "", "b": "%%log.x%%", "c": "hit"}
        self.assertEqual(first_value(payload, ("a", "b", "c")), "hit")


class ExplicitClassifyTests(unittest.TestCase):
    def test_explicit_event_key(self):
        event, hint = classify({"event": "config-change"})
        self.assertEqual(event.key, "config-change")
        self.assertTrue(hint)

    def test_explicit_key_is_normalised(self):
        event, _ = classify({"event": "Admin_Login"})
        self.assertEqual(event.key, "admin-login")

    def test_alias_maps_to_catalog_key(self):
        event, _ = classify({"event": "設定異動"}, aliases={"設定異動": "config-change"})
        self.assertEqual(event.key, "config-change")

    def test_unknown_explicit_key_falls_back_to_generic(self):
        event, hint = classify({"event": "something-new"})
        self.assertEqual(event.key, GENERIC.key)
        self.assertTrue(hint)


class HeuristicClassifyTests(unittest.TestCase):
    def test_no_hint_defaults_to_vpn_login(self):
        event, hint = classify({"user": "jdoe", "ip": "1.2.3.4"})
        self.assertEqual(event.key, "vpn-login")
        self.assertFalse(hint)

    def test_subtype_vpn_is_login(self):
        event, hint = classify({"type": "event", "subtype": "vpn", "action": "tunnel-up"})
        self.assertEqual(event.key, "vpn-login")
        self.assertTrue(hint)

    def test_vpn_tunnel_down_is_logout(self):
        event, _ = classify({"subtype": "vpn", "action": "tunnel-down"})
        self.assertEqual(event.key, "vpn-logout")

    def test_admin_login_failed(self):
        event, _ = classify(
            {"logdesc": "Admin login failed", "admin": "root", "status": "failed"}
        )
        self.assertEqual(event.key, "admin-login-failed")

    def test_admin_login_success(self):
        event, _ = classify({"logdesc": "Administrator admin logged in", "admin": "admin"})
        self.assertEqual(event.key, "admin-login")

    def test_admin_login_by_action_and_status_success(self):
        event, _ = classify(
            {"subtype": "system", "action": "login", "status": "success", "user": "root"}
        )
        self.assertEqual(event.key, "admin-login")

    def test_admin_login_by_action_and_status_failed(self):
        event, _ = classify(
            {"subtype": "system", "action": "login", "status": "failed", "user": "root"}
        )
        self.assertEqual(event.key, "admin-login-failed")

    def test_admin_login_failed_by_logdesc_only(self):
        event, _ = classify({"logdesc": "Admin login failed", "user": "root"})
        self.assertEqual(event.key, "admin-login-failed")

    def test_admin_logout_by_action(self):
        event, _ = classify({"subtype": "system", "action": "logout", "user": "root"})
        self.assertEqual(event.key, "admin-logout")

    def test_logout_events_are_muted_but_logins_are_not(self):
        admin_logout, _ = classify({"subtype": "system", "action": "logout"})
        vpn_logout, _ = classify({"subtype": "vpn", "action": "tunnel-down"})
        admin_login, _ = classify({"subtype": "system", "action": "login"})
        self.assertFalse(admin_logout.notify)
        self.assertFalse(vpn_logout.notify)
        self.assertTrue(admin_login.notify)

    def test_config_edit_is_not_mistaken_for_admin_login(self):
        event, _ = classify(
            {"subtype": "system", "action": "edit", "cfgpath": "firewall.policy",
             "msg": "Administrator admin edited a firewall policy"}
        )
        self.assertEqual(event.key, "config-change")

    def test_config_change_by_action(self):
        event, _ = classify({"action": "edit", "cfgpath": "firewall.policy"})
        self.assertEqual(event.key, "config-change")

    def test_ips_attack_by_field(self):
        event, _ = classify({"type": "utm", "subtype": "ips", "attack": "Bad.Signature"})
        self.assertEqual(event.key, "ips-attack")

    def test_virus_detected(self):
        event, _ = classify({"subtype": "virus", "virus": "EICAR"})
        self.assertEqual(event.key, "virus-detected")

    def test_ha_event(self):
        event, _ = classify({"logdesc": "HA failover occurred"})
        self.assertEqual(event.key, "ha-event")

    def test_conserve_mode(self):
        event, _ = classify({"logdesc": "device entered conserve mode"})
        self.assertEqual(event.key, "conserve-mode")

    def test_unrecognised_hint_is_generic(self):
        event, hint = classify({"type": "traffic", "subtype": "forward"})
        self.assertEqual(event.key, GENERIC.key)
        self.assertTrue(hint)


class AudienceTests(unittest.TestCase):
    def test_user_event_default_audience(self):
        event, _ = classify({"subtype": "vpn"})
        self.assertEqual(resolve_audience(event), USER)

    def test_team_event_default_audience(self):
        event, _ = classify({"event": "config-change"})
        self.assertEqual(resolve_audience(event), TEAM)

    def test_override_wins(self):
        event, _ = classify({"subtype": "vpn"})
        self.assertEqual(resolve_audience(event, {"vpn-login": TEAM}), TEAM)

    def test_invalid_override_is_ignored(self):
        event, _ = classify({"event": "config-change"})
        self.assertEqual(resolve_audience(event, {"config-change": "nonsense"}), TEAM)


class FieldLabelTests(unittest.TestCase):
    def test_known_and_unknown(self):
        self.assertIn("Source IP", humanize_field("srcip"))
        self.assertEqual(humanize_field("weird_field"), "weird_field")


if __name__ == "__main__":
    unittest.main()
