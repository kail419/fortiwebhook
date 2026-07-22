"""HTTP-layer tests via Flask's test client (no network). Run: python -m unittest -v"""
import unittest
from unittest import mock

from app.config import Config
from app.main import create_app
from app.mailer import MailSendError


def _cfg(**overrides) -> Config:
    cfg = Config(
        webhook_token="secret", ldap_server="dc", ldap_bind_dn="b",
        ldap_bind_password="p", ldap_base_dn="dc=x", smtp_host="smtp",
        mail_from="from@x",
    )
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = create_app(_cfg()).test_client()

    def test_health_ok(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "ok")

    def test_webhook_requires_token(self):
        resp = self.client.post("/webhook/fortigate", json={"user": "jdoe"})
        self.assertEqual(resp.status_code, 401)

    def test_webhook_rejects_bad_token(self):
        resp = self.client.post(
            "/webhook/fortigate", json={"user": "jdoe"},
            headers={"X-Webhook-Token": "wrong"},
        )
        self.assertEqual(resp.status_code, 401)

    def test_webhook_bad_body_is_400(self):
        resp = self.client.post(
            "/webhook/fortigate", data="not json",
            content_type="application/json",
            headers={"X-Webhook-Token": "secret"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_webhook_sent_is_200(self):
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch("app.notifier.send_mail"):
            resp = self.client.post(
                "/webhook/fortigate",
                json={"user": "jdoe", "ip": "1.1.1.1", "country": "X"},
                headers={"X-Webhook-Token": "secret"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["status"], "sent")

    def test_webhook_smtp_error_is_502(self):
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch("app.notifier.send_mail", side_effect=MailSendError("boom")):
            resp = self.client.post(
                "/webhook/fortigate",
                json={"user": "jdoe", "ip": "1.1.1.1"},
                headers={"X-Webhook-Token": "secret"},
            )
        self.assertEqual(resp.status_code, 502)

    def test_webhook_accepts_token_in_body(self):
        with mock.patch("app.notifier.resolve_email", return_value="jdoe@x"), \
             mock.patch("app.notifier.send_mail"):
            resp = self.client.post(
                "/webhook/fortigate",
                json={"user": "jdoe", "ip": "1.1.1.1", "token": "secret"},
            )
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
