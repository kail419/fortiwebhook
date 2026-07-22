"""Resolve a login account name to an e-mail address via LDAP / Active Directory."""
from __future__ import annotations

import logging
import ssl
from typing import Optional

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

from .config import Config

log = logging.getLogger("ipsecalert.ldap")


class LdapLookupError(RuntimeError):
    """Raised when the directory cannot be reached or the query itself fails.

    This is distinct from 'user found but has no mailbox' (which returns None),
    so the caller can tell an infrastructure problem apart from missing data.
    """


def normalize_username(raw: str, strip_upn_suffix: bool = True) -> str:
    """Reduce ``CORP\\jdoe`` or ``jdoe@corp.local`` to the bare account ``jdoe``.

    FortiGate's ``%%user%%`` can arrive as a plain name, a down-level
    ``DOMAIN\\user`` name, or a UPN ``user@domain`` depending on how the VPN
    authenticates. The default AD filter matches ``sAMAccountName``, which never
    contains a domain, so we strip both forms.
    """
    name = (raw or "").strip()
    if "\\" in name:                       # DOMAIN\user  -> user
        name = name.rsplit("\\", 1)[-1]
    if strip_upn_suffix and "@" in name:   # user@domain  -> user
        name = name.split("@", 1)[0]
    return name.strip()


def resolve_email(config: Config, username: str) -> Optional[str]:
    """Return the e-mail for ``username``, or ``None`` if not found / no mailbox.

    Raises :class:`LdapLookupError` on connect / bind / search failures.
    """
    account = normalize_username(username, config.ldap_strip_upn_suffix)
    if not account:
        return None

    # Escape the value so a name like ``a)(uid=*`` cannot alter the filter.
    # Turn a malformed operator-supplied template into the same controlled
    # infrastructure error as other LDAP failures instead of leaking a 500.
    try:
        search_filter = config.ldap_user_filter.format(
            user=escape_filter_chars(account)
        )
    except (IndexError, KeyError, ValueError) as exc:
        raise LdapLookupError(f"Invalid LDAP_USER_FILTER: {exc}") from exc

    # Over LDAPS, verify the domain controller's certificate (unless explicitly
    # disabled). Point ldap_ca_cert at your internal root/chain so an internal-CA
    # DC cert validates; without validation LDAPS is trivially MITM'd.
    tls_config = None
    if config.ldap_use_ssl:
        tls_config = Tls(
            validate=ssl.CERT_REQUIRED if config.ldap_tls_validate else ssl.CERT_NONE,
            ca_certs_file=(config.ldap_ca_cert or None),
        )

    server = Server(
        config.ldap_server,
        port=(config.ldap_port or None),   # None => 389 (plain) / 636 (ssl)
        use_ssl=config.ldap_use_ssl,
        tls=tls_config,
        get_info=ALL,
        connect_timeout=config.ldap_timeout,
    )

    try:
        conn = Connection(
            server,
            user=config.ldap_bind_dn,
            password=config.ldap_bind_password,
            auto_bind=True,
            receive_timeout=config.ldap_timeout,
        )
    except (LDAPException, OSError, ValueError) as exc:
        raise LdapLookupError(f"LDAP bind/connect failed: {exc}") from exc

    try:
        search_succeeded = conn.search(
            search_base=config.ldap_base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=[config.ldap_email_attr],
            size_limit=2,
        )
        if not search_succeeded:
            result = conn.result or {}
            detail = result.get("message") or result.get("description") or "unknown error"
            raise LdapLookupError(f"LDAP search was rejected: {detail}")
        if not conn.entries:
            log.warning("No directory entry for account=%r (filter=%r)",
                        account, search_filter)
            return None
        if len(conn.entries) > 1:
            log.warning("%d entries matched account=%r; using the first",
                        len(conn.entries), account)

        attrs = conn.entries[0].entry_attributes_as_dict
        values = attrs.get(config.ldap_email_attr) or []
        email = str(values[0]).strip() if values else ""
        if not email:
            log.warning("account=%r has no %r attribute", account, config.ldap_email_attr)
            return None
        return email
    except LDAPException as exc:
        raise LdapLookupError(f"LDAP search failed: {exc}") from exc
    finally:
        try:
            conn.unbind()
        except Exception:  # pragma: no cover - best-effort cleanup
            pass
