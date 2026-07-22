"""Tests for LDAP error classification (no network)."""
import unittest
from unittest import mock

from app.config import Config
from app.ldap_lookup import LdapLookupError, resolve_email


def _cfg(**overrides) -> Config:
    cfg = Config(
        ldap_server="dc.example.com",
        ldap_use_ssl=False,
        ldap_bind_dn="reader@example.com",
        ldap_bind_password="secret",
        ldap_base_dn="DC=example,DC=com",
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class LdapFailureTests(unittest.TestCase):
    def test_malformed_filter_becomes_controlled_ldap_error(self):
        cfg = _cfg(ldap_user_filter="(&(sAMAccountName={user})({missing}=x))")
        with self.assertRaisesRegex(LdapLookupError, "Invalid LDAP_USER_FILTER"):
            resolve_email(cfg, "jdoe")

    @mock.patch("app.ldap_lookup.Server")
    @mock.patch("app.ldap_lookup.Connection")
    def test_rejected_search_is_not_reported_as_missing_user(self, connection, _server):
        conn = connection.return_value
        conn.search.return_value = False
        conn.result = {"description": "unavailable", "message": "directory is busy"}
        conn.entries = []

        with self.assertRaisesRegex(LdapLookupError, "directory is busy"):
            resolve_email(_cfg(), "jdoe")
        conn.unbind.assert_called_once()

    @mock.patch("app.ldap_lookup.Server")
    @mock.patch("app.ldap_lookup.Connection")
    def test_successful_empty_search_still_means_user_not_found(self, connection, _server):
        conn = connection.return_value
        conn.search.return_value = True
        conn.entries = []

        self.assertIsNone(resolve_email(_cfg(), "ghost"))
        conn.unbind.assert_called_once()


if __name__ == "__main__":
    unittest.main()
