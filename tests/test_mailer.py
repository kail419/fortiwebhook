"""Tests for SMTP error handling (no network)."""
import unittest
from unittest import mock

from app.config import Config
from app.mailer import MailSendError, send_mail


class MailerTests(unittest.TestCase):
    @mock.patch("app.mailer.ssl.create_default_context")
    def test_bad_ca_file_becomes_controlled_mail_error(self, create_context):
        create_context.return_value.load_verify_locations.side_effect = OSError(
            "CA file missing"
        )
        cfg = Config(
            smtp_host="smtp.example.com",
            smtp_ca_cert="/missing/ca.pem",
            mail_from="alerts@example.com",
        )

        with self.assertRaisesRegex(MailSendError, "CA file missing"):
            send_mail(cfg, "user@example.com", "subject", "body")


if __name__ == "__main__":
    unittest.main()
