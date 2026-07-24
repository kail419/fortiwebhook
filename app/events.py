"""FortiGate event catalog and classification.

Turns a FortiGate Automation webhook body into a known *event type* so the
notifier can title, prioritise, and route it. Classification uses, in order:

1. An explicit key in the body (``event`` / ``event_type``), matched against the
   catalog keys and any operator-defined aliases. This is the reliable path —
   set ``"event": "admin-login"`` in the stitch body.
2. A heuristic over standard FortiOS log fields (``type`` / ``subtype`` /
   ``action`` / ``eventtype`` / ``logid`` / ``logdesc``) for bodies that just
   forward raw ``%%log.<field>%%`` values.
3. A generic catch-all, so *any* FortiGate event still produces a useful alert
   (every provided field is shown).

The module is deliberately free of Flask/LDAP/SMTP imports so it can be unit
tested on its own.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, Mapping, Optional, Tuple

# Audiences an event can be routed to.
USER = "user"
TEAM = "team"
BOTH = "both"
AUDIENCES = (USER, TEAM, BOTH)

# FortiGate leaves unsupported log variables untouched, e.g. the literal
# "%%log.srccity%%". Treat such a token as missing data everywhere.
_UNEXPANDED = re.compile(r"^%%[^%\r\n]+%%$")


def clean_value(value: object) -> str:
    """Coerce a payload value to a trimmed string, dropping unexpanded vars."""
    if value is None:
        return ""
    text = str(value).strip()
    return "" if _UNEXPANDED.fullmatch(text) else text


def first_value(payload: Mapping, keys: Iterable[str]) -> str:
    """First non-empty cleaned value among ``keys`` (priority order)."""
    for key in keys:
        value = clean_value(payload.get(key))
        if value:
            return value
    return ""


@dataclass(frozen=True)
class EventType:
    key: str
    title_zh: str
    title_en: str
    audience: str = TEAM          # user | team | both
    severity: str = "warning"     # info | warning | critical
    category: str = "general"     # vpn | admin | config | threat | system | general
    # Extra payload fields worth highlighting for this event, on top of the
    # always-shown common set (device / time / source / message).
    detail_fields: Tuple[str, ...] = ()


# Catch-all for anything not in the catalog. Everything the body carries is
# still shown, so no FortiGate event is silently dropped.
GENERIC = EventType(
    key="fortigate-event",
    title_zh="FortiGate 事件",
    title_en="FortiGate event",
    audience=TEAM,
    severity="warning",
    category="general",
)

# Curated set of the common FortiGate Automation events. "user" events concern
# one person (their VPN session) and go to that person; everything else is an
# administrative / system / threat event for the security-IT team.
CATALOG: Tuple[EventType, ...] = (
    EventType("vpn-login", "VPN 連線登入", "VPN login",
              USER, "warning", "vpn"),
    EventType("vpn-logout", "VPN 連線結束", "VPN logout",
              USER, "info", "vpn"),
    EventType("admin-login", "管理者登入", "Admin login",
              TEAM, "warning", "admin", ("admin", "ui", "srcip")),
    EventType("admin-login-failed", "管理者登入失敗", "Admin login failed",
              TEAM, "critical", "admin", ("admin", "ui", "srcip", "status")),
    EventType("admin-logout", "管理者登出", "Admin logout",
              TEAM, "info", "admin", ("admin", "ui", "srcip")),
    EventType("config-change", "設定變更", "Configuration change",
              TEAM, "warning", "config", ("admin", "ui", "cfgpath", "cfgattr")),
    EventType("ips-attack", "IPS 入侵偵測", "IPS/IDS attack",
              TEAM, "critical", "threat",
              ("attack", "srcip", "dstip", "action", "severity")),
    EventType("virus-detected", "偵測到病毒/惡意程式", "Virus detected",
              TEAM, "critical", "threat",
              ("virus", "filename", "srcip", "dstip", "action")),
    EventType("dos-attack", "阻斷服務攻擊", "DoS attack",
              TEAM, "critical", "threat", ("srcip", "dstip", "action")),
    EventType("webfilter-block", "Web 過濾阻擋", "Web filter block",
              TEAM, "info", "threat", ("srcip", "url", "catdesc", "action")),
    EventType("app-control", "應用程式管制", "Application control",
              TEAM, "info", "threat", ("srcip", "app", "action")),
    EventType("ha-event", "HA 高可用性事件", "HA event",
              TEAM, "critical", "system", ("msg", "logdesc")),
    EventType("conserve-mode", "記憶體保護模式 (conserve)", "Conserve mode",
              TEAM, "warning", "system", ("msg", "logdesc")),
    EventType("link-down", "介面/連線中斷", "Interface / link down",
              TEAM, "warning", "system", ("msg", "logdesc")),
    EventType("license-expiry", "授權即將到期", "License expiry",
              TEAM, "warning", "system", ("msg", "logdesc")),
    EventType("fortiguard-update", "FortiGuard 更新", "FortiGuard update",
              TEAM, "info", "system", ("msg", "logdesc")),
)

_BY_KEY: Dict[str, EventType] = {event.key: event for event in CATALOG}
_BY_KEY[GENERIC.key] = GENERIC

# Bilingual labels for the fields shown in team alerts. Unknown fields fall back
# to their raw name so nothing is hidden.
FIELD_LABELS: Dict[str, str] = {
    "devname": "設備 / Device",
    "device": "設備 / Device",
    "user": "使用者 / User",
    "admin": "管理者 / Admin",
    "ui": "登入介面 / UI",
    "srcip": "來源 IP / Source IP",
    "dstip": "目的 IP / Dest IP",
    "action": "動作 / Action",
    "status": "結果 / Status",
    "level": "等級 / Level",
    "attack": "攻擊 / Attack",
    "attackid": "攻擊 ID / Attack ID",
    "severity": "嚴重度 / Severity",
    "virus": "病毒 / Virus",
    "filename": "檔名 / File",
    "url": "網址 / URL",
    "catdesc": "分類 / Category",
    "app": "應用程式 / App",
    "cfgpath": "設定路徑 / Config path",
    "cfgattr": "設定內容 / Config attr",
    "msg": "訊息 / Message",
    "logdesc": "描述 / Description",
    "logid": "Log ID",
    "srccountry": "國家 / Country",
    "srccity": "城市 / City",
    "time": "時間 / Time",
    "date": "日期 / Date",
}


def humanize_field(name: str) -> str:
    """Bilingual label for a FortiOS field, or the raw name if unknown."""
    return FIELD_LABELS.get(name, name)


def _norm_key(value: str) -> str:
    """Normalise an event key so 'Admin_Login' == 'admin-login'."""
    return re.sub(r"[\s_]+", "-", value.strip().lower())


def resolve_audience(event_type: EventType, overrides: Optional[Mapping[str, str]] = None) -> str:
    """Audience for an event, honouring an operator override by event key."""
    if overrides:
        override = overrides.get(event_type.key) or overrides.get(_norm_key(event_type.key))
        if override in AUDIENCES:
            return override
    return event_type.audience


def _heuristic(payload: Mapping) -> str:
    """Best-effort event key from standard FortiOS fields; '' if unsure."""
    subtype = first_value(payload, ("subtype",)).lower()
    action = first_value(payload, ("action",)).lower()
    eventtype = first_value(payload, ("eventtype",)).lower()
    status = first_value(payload, ("status",)).lower()
    logdesc = first_value(payload, ("logdesc", "msg")).lower()

    def present(*names: str) -> bool:
        return bool(first_value(payload, names))

    # --- VPN (IPsec / SSL-VPN): the one user-facing category ---
    if subtype == "vpn" or eventtype in ("ipsec", "ssl", "ssl-vpn", "sslvpn") or "vpn" in logdesc:
        if "logout" in action or "down" in action or "logout" in logdesc or "disconnect" in logdesc:
            return "vpn-logout"
        return "vpn-login"

    # --- Administrative access (management-plane login / logout) ---
    # Detected by the login/logout action or FortiOS's own phrasing, and scoped
    # to the system subtype, so a config edit (add/edit/delete, handled below) or
    # an end-user auth (subtype=user) is never mistaken for an admin login.
    if subtype in ("system", "") and (
        action in ("login", "logout")
        or any(term in logdesc for term in ("login", "logout", "logged in", "logged out"))
    ):
        if "logout" in action or "logout" in logdesc or "logged out" in logdesc:
            return "admin-logout"
        if status in ("failed", "failure", "fail") or "fail" in action or "fail" in logdesc:
            return "admin-login-failed"
        return "admin-login"

    # --- Configuration change ---
    if action in ("add", "edit", "delete") or present("cfgpath") or "configuration" in logdesc:
        return "config-change"

    # --- UTM / threat ---
    if subtype == "ips" or present("attack", "attackid") or "intrusion" in logdesc:
        return "ips-attack"
    if subtype == "virus" or present("virus") or "antivirus" in logdesc:
        return "virus-detected"
    if subtype in ("anomaly", "dos") or "denial of service" in logdesc:
        return "dos-attack"
    if subtype == "webfilter" or (present("url") and "block" in action):
        return "webfilter-block"
    if subtype in ("app-ctrl", "application", "app"):
        return "app-control"

    # --- System / appliance health ---
    if subtype == "ha" or "failover" in logdesc or "high availability" in logdesc:
        return "ha-event"
    if "conserve" in logdesc:
        return "conserve-mode"
    if ("interface" in logdesc or "link" in logdesc) and "down" in logdesc:
        return "link-down"
    if "license" in logdesc or "licence" in logdesc:
        return "license-expiry"
    if "fortiguard" in logdesc or subtype in ("update", "fortiguard"):
        return "fortiguard-update"

    return ""


def classify(payload: Mapping, aliases: Optional[Mapping[str, str]] = None) -> Tuple[EventType, bool]:
    """Classify a webhook body.

    Returns ``(event_type, had_type_hint)``. ``had_type_hint`` is ``False`` only
    when the body carries no event/type fields at all — the legacy VPN-login
    body — so the caller can keep the original backwards-compatible behaviour.
    """
    # 1) Explicit key set by the operator (most reliable).
    explicit = first_value(payload, ("event", "event_type", "eventkey"))
    if explicit:
        norm = _norm_key(explicit)
        if aliases:
            mapped = aliases.get(explicit) or aliases.get(norm)
            if mapped:
                norm = _norm_key(mapped)
        if norm in _BY_KEY:
            return _BY_KEY[norm], True

    # 2) Heuristic over standard FortiOS log fields.
    hint_fields = ("event", "event_type", "type", "subtype", "eventtype",
                   "logid", "action", "logdesc")
    had_hint = any(first_value(payload, (name,)) for name in hint_fields)

    key = _heuristic(payload)
    if key in _BY_KEY:
        return _BY_KEY[key], True

    # 3) Something was hinted but not recognised -> generic team alert.
    if had_hint:
        return GENERIC, True

    # 4) No hints at all -> the legacy VPN-login body.
    return _BY_KEY["vpn-login"], False
