"""Tests for EMS monitor environment configuration."""
import os
import unittest
from unittest import mock

from app.ems_config import EmsConfig


class EmsConfigTests(unittest.TestCase):
    def test_loads_api_and_field_mapping(self):
        env = {
            "EMS_API_URL": "https://ems.example.com/",
            "EMS_ENDPOINTS_PATH": "/fortiapi/endpoints",
            "EMS_API_TOKEN": "secret",
            "EMS_ALERT_TO": "soc@example.com",
            "EMS_GEOIP_DB": "/geo/country.mmdb",
            "EMS_ENDPOINTS_KEY": "result.items",
            "EMS_USER_FIELDS": "identity.email,identity.username",
            "EMS_HOME_COUNTRIES": "TW,Taiwan",
        }
        with mock.patch.dict(os.environ, env, clear=True):
            cfg = EmsConfig.from_env()
        self.assertEqual(cfg.api_url, "https://ems.example.com")
        self.assertEqual(cfg.endpoints_key, "result.items")
        self.assertEqual(cfg.user_fields, ["identity.email", "identity.username"])
        self.assertEqual(cfg.home_countries, ["TW", "Taiwan"])

    def test_token_file_is_supported(self):
        with mock.patch("builtins.open", mock.mock_open(read_data=" token\n")):
            with mock.patch.dict(
                os.environ, {"EMS_API_TOKEN_FILE": "/run/secrets/token"}, clear=True
            ):
                cfg = EmsConfig.from_env()
        self.assertEqual(cfg.api_token, "token")

    def test_requires_https_by_default(self):
        cfg = EmsConfig(
            api_url="http://ems.example.com",
            endpoints_path="/api/endpoints",
            api_token="token",
            alert_to="soc@example.com",
            geoip_db="/geo.mmdb",
        )
        errors = cfg.validation_errors("smtp.example.com", "alerts@example.com")
        self.assertIn("EMS_API_URL must use HTTPS (or set EMS_ALLOW_HTTP=true)", errors)

    def test_api_validation_does_not_require_smtp_or_geoip(self):
        cfg = EmsConfig(
            api_url="https://ems.example.com",
            endpoints_path="/api/endpoints",
            api_token="token",
            alert_to="",
            geoip_db="",
        )
        self.assertEqual(cfg.api_validation_errors(), [])


if __name__ == "__main__":
    unittest.main()
