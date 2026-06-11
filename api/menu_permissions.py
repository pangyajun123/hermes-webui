"""Menu permission resolution for host-embedded WebUI launches.

When configured, WebUI accepts an entry token from the shell URL or request
headers, exchanges it with an administrator-owned permission endpoint, and
returns a normalized menu allow-list to the browser. The raw entry token is
persisted only as a signed HttpOnly cookie so the root shell can recognize a
previous entry and clear it on logout without exposing it to ordinary JS.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookies
import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

PRIMARY_PANEL_IDS = (
    "chat",
    "tasks",
    "kanban",
    "skills",
    "memory",
    "workspaces",
    "profiles",
    "todos",
    "insights",
    "logs",
    "settings",
    "dashboard",
)

SETTINGS_SECTION_IDS = (
    "conversation",
    "appearance",
    "preferences",
    "providers",
    "plugins",
    "system",
)

_COOKIE_NAME = "hermes_menu_permissions"
_ENTRY_TOKEN_COOKIE_NAME = "hermes_entry_token"
_DEFAULT_ENTRY_LOGIN_REDIRECT_URL = "http://127.0.0.1:3100/webui-hermes"
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()

_PANEL_ALIASES = {
    "chat": {"chat", "conversation", "conversations", "session", "sessions"},
    "tasks": {"tasks", "task", "cron", "crons", "jobs", "job", "scheduled_jobs"},
    "kanban": {"kanban", "board", "boards"},
    "skills": {"skills", "skill"},
    "memory": {"memory", "memories"},
    "workspaces": {"workspaces", "workspace", "spaces", "space", "files", "file_browser"},
    "profiles": {"profiles", "profile", "agent_profiles"},
    "todos": {"todos", "todo", "current_task_list"},
    "insights": {"insights", "analytics", "usage", "usage_analytics"},
    "logs": {"logs", "log"},
    "settings": {"settings", "setting"},
    "dashboard": {"dashboard", "hermes_dashboard"},
}

_SETTINGS_ALIASES = {
    "conversation": {"conversation", "session_tools", "transcript"},
    "appearance": {"appearance", "theme", "themes"},
    "preferences": {"preferences", "preference", "prefs"},
    "providers": {"providers", "provider", "models", "model"},
    "plugins": {"plugins", "plugin"},
    "system": {"system", "access", "security", "auth"},
}

_TOKEN_STRING_FIELDS = (
    "id",
    "key",
    "code",
    "name",
    "path",
    "route",
    "menu",
    "menu_id",
    "menuId",
    "menu_code",
    "menuCode",
    "permission",
    "permission_code",
    "permissionCode",
    "authority",
    "panel",
    "section",
)

_TOKEN_CONTAINER_FIELDS = (
    "allowed",
    "authorities",
    "children",
    "data",
    "items",
    "menu",
    "menus",
    "menuPermissions",
    "menuList",
    "permissions",
    "permissionList",
    "list",
    "records",
    "result",
    "routes",
)


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _int_env(name: str, default: int, min_value: int, max_value: int) -> int:
    raw = os.getenv(name, "").strip()
    if raw:
        try:
            return max(min_value, min(int(raw), max_value))
        except (TypeError, ValueError):
            pass
    return default


def is_menu_permissions_enabled() -> bool:
    return bool(os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_URL", "").strip())


def is_entry_token_required() -> bool:
    """Return True when the root shell must arrive with a saved entry token."""
    if not is_menu_permissions_enabled():
        return False
    raw = os.getenv("HERMES_WEBUI_ENTRY_TOKEN_REQUIRED", "").strip()
    if raw:
        return raw.lower() in {"1", "true", "yes", "on"}
    return True


def entry_login_redirect_url() -> str:
    """Resolve the external login URL used when the root shell lacks a token."""
    raw = os.getenv("HERMES_WEBUI_ENTRY_LOGIN_URL", "").strip()
    value = raw or _DEFAULT_ENTRY_LOGIN_REDIRECT_URL
    if "\r" in value or "\n" in value:
        return _DEFAULT_ENTRY_LOGIN_REDIRECT_URL
    return value


def _all_permissions_payload(*, enabled: bool, source: str) -> dict[str, Any]:
    return _build_payload(PRIMARY_PANEL_IDS, SETTINGS_SECTION_IDS, enabled=enabled, source=source)


def _fail_closed_payload(source: str, message: str | None = None) -> dict[str, Any]:
    payload = _build_payload((), (), enabled=True, source=source)
    if message:
        payload["message"] = message
    return payload


def _build_payload(
    panels: tuple[str, ...] | list[str] | set[str],
    settings: tuple[str, ...] | list[str] | set[str],
    *,
    enabled: bool,
    source: str,
) -> dict[str, Any]:
    panel_set = {p for p in panels if p in PRIMARY_PANEL_IDS}
    settings_set = {s for s in settings if s in SETTINGS_SECTION_IDS}
    if settings_set:
        panel_set.add("settings")
    allowed_panels = [p for p in PRIMARY_PANEL_IDS if p in panel_set]
    allowed_settings = [s for s in SETTINGS_SECTION_IDS if s in settings_set]
    return {
        "enabled": bool(enabled),
        "source": source,
        "allowed_panels": allowed_panels,
        "allowed_settings_sections": allowed_settings,
        "denied_panels": [p for p in PRIMARY_PANEL_IDS if p not in panel_set],
        "denied_settings_sections": [s for s in SETTINGS_SECTION_IDS if s not in settings_set],
        "fetched_at": int(time.time()),
    }


def _token_candidates_from_query(parsed) -> list[str]:
    names = []
    primary = os.getenv("HERMES_WEBUI_MENU_TOKEN_PARAM", "token").strip() or "token"
    names.append(primary)
    for fallback in ("access_token", "auth_token"):
        if fallback not in names:
            names.append(fallback)
    try:
        query = urllib.parse.parse_qs(getattr(parsed, "query", "") or "")
    except Exception:
        return []
    values = []
    for name in names:
        for value in query.get(name, []):
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
    return values


def _token_from_request_sources(handler, parsed) -> str | None:
    for value in _token_candidates_from_query(parsed):
        return value
    headers = getattr(handler, "headers", None)
    if headers:
        source_header = os.getenv("HERMES_WEBUI_MENU_TOKEN_SOURCE_HEADER", "").strip()
        if source_header:
            value = headers.get(source_header, "")
            if value and value.strip():
                return value.strip()
        auth = headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            if token:
                return token
    return None


def _entry_token_cookie_ttl() -> int:
    return _int_env("HERMES_WEBUI_ENTRY_TOKEN_COOKIE_TTL", 86400 * 30, 60, 86400 * 365)


def _entry_token_cookie_value(token: str) -> str:
    stored = {"token": token, "created_at": int(time.time())}
    raw = json.dumps(stored, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(_signing_key(), b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def _entry_token_from_cookie_value(value: str) -> str | None:
    if not value or "." not in value:
        return None
    b64, sig = value.rsplit(".", 1)
    expected = hmac.new(_signing_key(), b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    padded = b64 + ("=" * (-len(b64) % 4))
    try:
        stored = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    created_at = int(stored.get("created_at") or 0)
    token = stored.get("token")
    if created_at <= 0 or time.time() - created_at > _entry_token_cookie_ttl():
        return None
    if not isinstance(token, str) or not token.strip():
        return None
    return token.strip()


def _entry_token_cookie(handler) -> str | None:
    cookie_header = getattr(handler, "headers", {}).get("Cookie", "")
    if not cookie_header:
        return None
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = cookie.get(_ENTRY_TOKEN_COOKIE_NAME)
    return morsel.value if morsel else None


def _saved_entry_token(handler) -> str | None:
    return _entry_token_from_cookie_value(_entry_token_cookie(handler) or "")


def _token_from_request(handler, parsed) -> str | None:
    return _token_from_request_sources(handler, parsed) or _saved_entry_token(handler)


def has_entry_token_for_request(handler, parsed) -> bool:
    return bool(_token_from_request(handler, parsed))


def missing_entry_token_redirect_url(handler, parsed) -> str | None:
    if not is_entry_token_required():
        return None
    if getattr(parsed, "path", "") not in {"/", "/index.html"}:
        return None
    if has_entry_token_for_request(handler, parsed):
        return None
    return entry_login_redirect_url()


def _split_token(raw: str) -> tuple[str, ...]:
    lower = raw.strip().lower()
    lower = lower.strip("/#")
    lower = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", lower)
    parts = [p for p in re.split(r"[^a-z0-9]+", lower) if p]
    return tuple(parts)


def _token_forms(raw: str) -> set[str]:
    parts = _split_token(raw)
    forms = set(parts)
    if parts:
        forms.add("_".join(parts))
        for prefix in ("menu", "menus", "webui", "hermes", "panel", "nav", "route"):
            if parts[0] == prefix and len(parts) > 1:
                forms.add("_".join(parts[1:]))
                forms.update(parts[1:])
    return {f for f in forms if f}


def _extract_permission_tokens(node: Any) -> list[str]:
    tokens: list[str] = []
    if node is None:
        return tokens
    if isinstance(node, str):
        return [node]
    if isinstance(node, (int, float)):
        return []
    if isinstance(node, list):
        for item in node:
            tokens.extend(_extract_permission_tokens(item))
        return tokens
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, bool) and value:
                tokens.append(str(key))
        for field in _TOKEN_STRING_FIELDS:
            value = node.get(field)
            if isinstance(value, str) and value.strip():
                tokens.append(value.strip())
        for field in _TOKEN_CONTAINER_FIELDS:
            if field in node:
                tokens.extend(_extract_permission_tokens(node.get(field)))
    return tokens


def normalize_menu_permissions(data: Any, *, source: str = "remote") -> dict[str, Any]:
    """Normalize common third-party menu response shapes into WebUI IDs."""
    tokens = _extract_permission_tokens(data)
    forms: set[str] = set()
    for token in tokens:
        forms.update(_token_forms(token))
    if forms.intersection({"*", "all", "admin", "administrator", "super_admin"}):
        return _all_permissions_payload(enabled=True, source=source)

    panels: set[str] = set()
    settings: set[str] = set()

    for panel, aliases in _PANEL_ALIASES.items():
        if forms.intersection(aliases):
            panels.add(panel)

    for section, aliases in _SETTINGS_ALIASES.items():
        if forms.intersection(aliases):
            settings.add(section)

    if "settings" in panels and not settings:
        settings.update(SETTINGS_SECTION_IDS)

    return _build_payload(panels, settings, enabled=True, source=source)


def _cache_key(endpoint: str, method: str, token: str) -> str:
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"{method.upper()}:{endpoint}:{token_hash}"


def _request_remote_permissions(token: str) -> Any:
    endpoint = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_URL", "").strip()
    method = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_METHOD", "GET").strip().upper() or "GET"
    if method not in {"GET", "POST"}:
        method = "GET"
    timeout = _int_env("HERMES_WEBUI_MENU_PERMISSIONS_TIMEOUT", 5, 1, 30)
    headers = {"Accept": "application/json"}
    token_header = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_HEADER", "Authorization").strip()
    if token_header:
        default_prefix = "Bearer " if token_header.lower() == "authorization" else ""
        prefix = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_HEADER_PREFIX", default_prefix)
        headers[token_header] = f"{prefix}{token}"
    data = None
    url = endpoint
    if method == "GET":
        query_param = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_QUERY_PARAM", "").strip()
        if query_param:
            parts = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            query.append((query_param, token))
            url = urllib.parse.urlunsplit(
                (parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(query), parts.fragment)
            )
    else:
        body_field = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_BODY_FIELD", "token").strip() or "token"
        data = json.dumps({body_field: token}).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        raw = response.read(2 * 1024 * 1024)
    return json.loads(raw.decode("utf-8"))


def _fetch_remote_permissions(token: str) -> dict[str, Any]:
    endpoint = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_URL", "").strip()
    method = os.getenv("HERMES_WEBUI_MENU_PERMISSIONS_METHOD", "GET").strip().upper() or "GET"
    ttl = _int_env("HERMES_WEBUI_MENU_PERMISSIONS_CACHE_TTL", 60, 0, 3600)
    key = _cache_key(endpoint, method, token)
    now = time.time()
    if ttl > 0:
        with _CACHE_LOCK:
            cached = _CACHE.get(key)
            if cached and now - cached[0] <= ttl:
                payload = dict(cached[1])
                payload["source"] = "cache"
                return payload

    data = _request_remote_permissions(token)
    payload = normalize_menu_permissions(data, source="remote")
    if ttl > 0:
        with _CACHE_LOCK:
            _CACHE[key] = (now, payload)
    return payload


def _cookie_ttl() -> int:
    return _int_env("HERMES_WEBUI_MENU_PERMISSIONS_COOKIE_TTL", 3600, 60, 86400)


def _signing_key() -> bytes:
    from api.auth import _signing_key as auth_signing_key

    return auth_signing_key()


def _cookie_value_for_payload(payload: dict[str, Any]) -> str:
    stored = {
        "allowed_panels": payload.get("allowed_panels", []),
        "allowed_settings_sections": payload.get("allowed_settings_sections", []),
        "fetched_at": int(payload.get("fetched_at") or time.time()),
    }
    raw = json.dumps(stored, separators=(",", ":"), sort_keys=True).encode("utf-8")
    b64 = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    sig = hmac.new(_signing_key(), b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{b64}.{sig}"


def _payload_from_cookie_value(value: str) -> dict[str, Any] | None:
    if not value or "." not in value:
        return None
    b64, sig = value.rsplit(".", 1)
    expected = hmac.new(_signing_key(), b64.encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    padded = b64 + ("=" * (-len(b64) % 4))
    try:
        stored = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    fetched_at = int(stored.get("fetched_at") or 0)
    if fetched_at <= 0 or time.time() - fetched_at > _cookie_ttl():
        return None
    return _build_payload(
        stored.get("allowed_panels") or (),
        stored.get("allowed_settings_sections") or (),
        enabled=True,
        source="cookie",
    )


def _permission_cookie(handler) -> str | None:
    cookie_header = getattr(handler, "headers", {}).get("Cookie", "")
    if not cookie_header:
        return None
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(cookie_header)
    except http.cookies.CookieError:
        return None
    morsel = cookie.get(_COOKIE_NAME)
    return morsel.value if morsel else None


def _set_cookie_header(handler, payload: dict[str, Any]) -> str:
    cookie = http.cookies.SimpleCookie()
    cookie[_COOKIE_NAME] = _cookie_value_for_payload(payload)
    cookie[_COOKIE_NAME]["httponly"] = True
    cookie[_COOKIE_NAME]["samesite"] = "Lax"
    cookie[_COOKIE_NAME]["path"] = "/"
    cookie[_COOKIE_NAME]["max-age"] = str(_cookie_ttl())
    try:
        from api.auth import _is_secure_context

        if _is_secure_context(handler):
            cookie[_COOKIE_NAME]["secure"] = True
    except Exception:
        pass
    return cookie[_COOKIE_NAME].OutputString()


def _set_entry_token_cookie_header(handler, token: str) -> str:
    cookie = http.cookies.SimpleCookie()
    cookie[_ENTRY_TOKEN_COOKIE_NAME] = _entry_token_cookie_value(token)
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["httponly"] = True
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["samesite"] = "Lax"
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["path"] = "/"
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["max-age"] = str(_entry_token_cookie_ttl())
    try:
        from api.auth import _is_secure_context

        if _is_secure_context(handler):
            cookie[_ENTRY_TOKEN_COOKIE_NAME]["secure"] = True
    except Exception:
        pass
    return cookie[_ENTRY_TOKEN_COOKIE_NAME].OutputString()


def _clear_cookie_header() -> str:
    cookie = http.cookies.SimpleCookie()
    cookie[_COOKIE_NAME] = ""
    cookie[_COOKIE_NAME]["httponly"] = True
    cookie[_COOKIE_NAME]["path"] = "/"
    cookie[_COOKIE_NAME]["max-age"] = "0"
    return cookie[_COOKIE_NAME].OutputString()


def _clear_entry_token_cookie_header() -> str:
    cookie = http.cookies.SimpleCookie()
    cookie[_ENTRY_TOKEN_COOKIE_NAME] = ""
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["httponly"] = True
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["path"] = "/"
    cookie[_ENTRY_TOKEN_COOKIE_NAME]["max-age"] = "0"
    return cookie[_ENTRY_TOKEN_COOKIE_NAME].OutputString()


def clear_entry_token_cookie_headers() -> list[str]:
    """Return Set-Cookie values that clear entry-token derived state."""
    return [_clear_cookie_header(), _clear_entry_token_cookie_header()]


def resolve_menu_permissions_for_request(handler, parsed) -> tuple[dict[str, Any], dict[str, str | list[str]]]:
    """Return normalized menu permissions plus response headers to persist them."""
    if not is_menu_permissions_enabled():
        return _all_permissions_payload(enabled=False, source="disabled"), {}

    incoming_token = _token_from_request_sources(handler, parsed)
    if incoming_token:
        try:
            payload = _fetch_remote_permissions(incoming_token)
            return payload, {
                "Set-Cookie": [
                    _set_cookie_header(handler, payload),
                    _set_entry_token_cookie_header(handler, incoming_token),
                ]
            }
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("Menu permission lookup failed: %s", exc)
            message = "Menu permissions unavailable"
            if _env_bool("HERMES_WEBUI_MENU_PERMISSIONS_FAIL_OPEN", False):
                payload = _all_permissions_payload(enabled=True, source="error-fail-open")
                return payload, {"Set-Cookie": _set_cookie_header(handler, payload)}
            return _fail_closed_payload("error", message), {"Set-Cookie": clear_entry_token_cookie_headers()}

    token = _saved_entry_token(handler)
    if token:
        try:
            payload = _fetch_remote_permissions(token)
            return payload, {
                "Set-Cookie": [
                    _set_cookie_header(handler, payload),
                    _set_entry_token_cookie_header(handler, token),
                ]
            }
        except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning("Menu permission lookup with saved entry token failed: %s", exc)
            if not _env_bool("HERMES_WEBUI_MENU_PERMISSIONS_FAIL_OPEN", False):
                return _fail_closed_payload("error", "Menu permissions unavailable"), {
                    "Set-Cookie": clear_entry_token_cookie_headers()
                }

    cookie_payload = _payload_from_cookie_value(_permission_cookie(handler) or "")
    if cookie_payload:
        return cookie_payload, {}

    if _env_bool("HERMES_WEBUI_MENU_PERMISSIONS_FAIL_OPEN", False):
        payload = _all_permissions_payload(enabled=True, source="missing-token-fail-open")
        return payload, {"Set-Cookie": _set_cookie_header(handler, payload)}
    return _fail_closed_payload("missing-token", "Menu permission token is missing"), {
        "Set-Cookie": clear_entry_token_cookie_headers()
    }
