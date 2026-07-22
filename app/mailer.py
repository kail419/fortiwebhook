"""Send the alert e-mail over SMTP (plaintext + HTML multipart, UTF-8)."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr
from typing import List, Optional

from .config import Config

log = logging.getLogger("ipsecalert.mail")


class MailSendError(RuntimeError):
    """Raised when the message could not be handed off to the SMTP server."""


def _clean_header(value: str) -> str:
    """Strip CR/LF so untrusted values can't inject extra headers."""
    return (value or "").replace("\r", " ").replace("\n", " ").strip()


def send_mail(
    config: Config,
    to_addr: str,
    subject: str,
    text_body: str,
    html_body: Optional[str] = None,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
) -> None:
    cc = [a for a in (cc or []) if a]
    bcc = [a for a in (bcc or []) if a]

    msg = EmailMessage()
    msg["From"] = formataddr((_clean_header(config.mail_from_name), config.mail_from))
    msg["To"] = _clean_header(to_addr)
    msg["Subject"] = _clean_header(subject)
    if cc:
        msg["Cc"] = ", ".join(_clean_header(a) for a in cc)
    if config.mail_reply_to:
        msg["Reply-To"] = _clean_header(config.mail_reply_to)

    msg.set_content(text_body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    recipients = [to_addr, *cc, *bcc]

    # Validating context (default). Trust an internal CA if one is configured.
    context = ssl.create_default_context()
    if config.smtp_ca_cert:
        context.load_verify_locations(config.smtp_ca_cert)

    try:
        if config.smtp_use_ssl:
            server = smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port,
                timeout=config.smtp_timeout, context=context,
            )
        else:
            server = smtplib.SMTP(
                config.smtp_host, config.smtp_port, timeout=config.smtp_timeout,
            )
        with server:
            server.ehlo()
            if config.smtp_use_starttls and not config.smtp_use_ssl:
                server.starttls(context=context)
                server.ehlo()
            if config.smtp_username:
                server.login(config.smtp_username, config.smtp_password)
            server.send_message(msg, from_addr=config.mail_from, to_addrs=recipients)
    except (smtplib.SMTPException, OSError) as exc:
        raise MailSendError(f"SMTP send failed: {exc}") from exc

    log.info("Alert e-mail sent to=%s cc=%s bcc=%d", to_addr, cc, len(bcc))
