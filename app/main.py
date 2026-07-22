"""Flask application exposing the FortiGate webhook receiver."""
from __future__ import annotations

import hmac
import logging
from typing import Optional

from flask import Flask, jsonify, request

from .config import Config
from .notifier import Notifier

log = logging.getLogger("ipsecalert")


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def create_app(config: Optional[Config] = None) -> Flask:
    config = config or Config.from_env()
    _setup_logging(config.log_level)

    missing = config.missing_required()
    if missing:
        log.warning("Incomplete configuration — the webhook will error until set: %s",
                    ", ".join(missing))

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    notifier = Notifier(config)

    def _token_ok() -> bool:
        expected = config.webhook_token
        if not expected:
            return False  # refuse everything until a token is configured
        body = request.get_json(force=True, silent=True) or {}
        provided = (
            request.headers.get(config.webhook_token_header)
            or (body.get("token") if isinstance(body, dict) else None)
            or request.args.get("token")
            or ""
        )
        return hmac.compare_digest(str(provided), str(expected))

    @app.get("/health")
    def health():
        return jsonify(status="ok", missing_config=config.missing_required()), 200

    @app.get("/")
    def index():
        return jsonify(service="IPsecAlert", endpoint="/webhook/fortigate"), 200

    @app.post("/webhook/fortigate")
    def webhook():
        if not _token_ok():
            log.warning("Rejected webhook: bad/missing token from %s", request.remote_addr)
            return jsonify(status="unauthorized"), 401

        payload = request.get_json(force=True, silent=True)
        if not isinstance(payload, dict):
            payload = request.form.to_dict() if request.form else None
        if not isinstance(payload, dict):
            return jsonify(status="bad-request", reason="expected-json-object"), 400

        payload.pop("token", None)  # never process or log the auth token as data
        result = notifier.handle(payload)
        http_status = 200 if result.get("status") in ("sent", "skipped") else 502
        return jsonify(result), http_status

    return app


# WSGI entry point for gunicorn: ``gunicorn app.main:app``
app = create_app()


if __name__ == "__main__":
    # Convenience runner for local testing (do not use in production).
    _cfg = Config.from_env()
    app.run(host=_cfg.listen_host, port=_cfg.listen_port)
