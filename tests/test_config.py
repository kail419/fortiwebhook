"""Tests for configuration loading, secrets, and secure defaults."""
import os
import tempfile
import unittest
from unittest import mock

from app.config import DEFAULT_MAIL_SUBJECT, LEGACY_MAIL_SUBJECT, Config, _get_secret


class GetSecretTests(unittest.TestCase):
    def test_reads_plain_env_value(self):
        with mock.patch.dict(os.environ, {"MYSECRET": "abc"}, clear=True):
            self.assertEqual(_get_secret("MYSECRET"), "abc")

    def test_file_takes_precedence_and_is_stripped(self):
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("  file-secret\n")
            with mock.patch.dict(
                os.environ, {"MYSECRET_FILE": path, "MYSECRET": "env-secret"}, clear=True
            ):
                self.assertEqual(_get_secret("MYSECRET"), "file-secret")
        finally:
            os.unlink(path)

    def test_missing_file_falls_back_to_env(self):
        with mock.patch.dict(
            os.environ, {"MYSECRET_FILE": "/nonexistent/x", "MYSECRET": "env"}, clear=True
        ):
            self.assertEqual(_get_secret("MYSECRET"), "env")

    def test_default_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(_get_secret("NOPE", "fallback"), "fallback")


class SecureDefaultsTests(unittest.TestCase):
    def test_ldap_tls_on_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            cfg = Config.from_env()
        self.assertTrue(cfg.ldap_use_ssl)
        self.assertTrue(cfg.ldap_tls_validate)

    def test_secret_env_vars_loaded_via_get_secret(self):
        env = {
            "WEBHOOK_TOKEN": "tok", "LDAP_BIND_PASSWORD": "ldp", "SMTP_PASSWORD": "smp",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = Config.from_env()
        self.assertEqual(cfg.webhook_token, "tok")
        self.assertEqual(cfg.ldap_bind_password, "ldp")
        self.assertEqual(cfg.smtp_password, "smp")

    def test_legacy_mail_subject_is_migrated_without_env_changes(self):
        with mock.patch.dict(
            os.environ, {"MAIL_SUBJECT": LEGACY_MAIL_SUBJECT}, clear=True
        ):
            cfg = Config.from_env()
        self.assertEqual(cfg.mail_subject, DEFAULT_MAIL_SUBJECT)


if __name__ == "__main__":
    unittest.main()
