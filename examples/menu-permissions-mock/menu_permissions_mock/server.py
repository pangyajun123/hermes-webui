"""Local mock API for Hermes WebUI menu permissions.

The WebUI calls this endpoint server-side when
HERMES_WEBUI_MENU_PERMISSIONS_URL is configured. This mock accepts any
non-empty token and returns the full menu allow-list supported by the current
WebUI implementation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

ROUTE_PATH = "/api/hermes/menu-permissions"

MENU_ITEMS: list[dict[str, Any]] = [
    {
        "id": "chat",
        "code": "chat",
        "parent_code": None,
        "name": "聊天",
        "name_en": "Chat",
        "path": "/chat",
        "sort_no": 10,
        "enabled": True,
    },
    {
        "id": "tasks",
        "code": "tasks",
        "parent_code": None,
        "name": "任务",
        "name_en": "Tasks",
        "path": "/tasks",
        "sort_no": 20,
        "enabled": True,
    },
    {
        "id": "kanban",
        "code": "kanban",
        "parent_code": None,
        "name": "看板",
        "name_en": "Kanban",
        "path": "/kanban",
        "sort_no": 30,
        "enabled": True,
    },
    {
        "id": "skills",
        "code": "skills",
        "parent_code": None,
        "name": "技能",
        "name_en": "Skills",
        "path": "/skills",
        "sort_no": 40,
        "enabled": True,
    },
    {
        "id": "memory",
        "code": "memory",
        "parent_code": None,
        "name": "记忆",
        "name_en": "Memory",
        "path": "/memory",
        "sort_no": 50,
        "enabled": True,
    },
    {
        "id": "workspaces",
        "code": "workspaces",
        "parent_code": None,
        "name": "工作区",
        "name_en": "Spaces",
        "path": "/workspaces",
        "sort_no": 60,
        "enabled": True,
    },
    {
        "id": "profiles",
        "code": "profiles",
        "parent_code": None,
        "name": "配置",
        "name_en": "Agent profiles",
        "path": "/profiles",
        "sort_no": 70,
        "enabled": True,
    },
    {
        "id": "todos",
        "code": "todos",
        "parent_code": None,
        "name": "待办",
        "name_en": "Current task list",
        "path": "/todos",
        "sort_no": 80,
        "enabled": True,
    },
    {
        "id": "insights",
        "code": "insights",
        "parent_code": None,
        "name": "统计",
        "name_en": "Insights",
        "path": "/insights",
        "sort_no": 90,
        "enabled": True,
    },
    {
        "id": "logs",
        "code": "logs",
        "parent_code": None,
        "name": "日志",
        "name_en": "Logs",
        "path": "/logs",
        "sort_no": 100,
        "enabled": True,
    },
    {
        "id": "settings",
        "code": "settings",
        "parent_code": None,
        "name": "设置",
        "name_en": "Settings",
        "path": "/settings",
        "sort_no": 110,
        "enabled": True,
    },
    {
        "id": "dashboard",
        "code": "dashboard",
        "parent_code": None,
        "name": "Hermes 仪表盘",
        "name_en": "Hermes Dashboard",
        "path": "/dashboard",
        "sort_no": 120,
        "enabled": True,
    },
    {
        "id": "settings.conversation",
        "code": "settings.conversation",
        "parent_code": "settings",
        "name": "对话",
        "name_en": "Conversation",
        "path": "/settings/conversation",
        "sort_no": 111,
        "enabled": True,
    },
    {
        "id": "settings.appearance",
        "code": "settings.appearance",
        "parent_code": "settings",
        "name": "外观",
        "name_en": "Appearance",
        "path": "/settings/appearance",
        "sort_no": 112,
        "enabled": True,
    },
    {
        "id": "settings.preferences",
        "code": "settings.preferences",
        "parent_code": "settings",
        "name": "偏好",
        "name_en": "Preferences",
        "path": "/settings/preferences",
        "sort_no": 113,
        "enabled": True,
    },
    {
        "id": "settings.providers",
        "code": "settings.providers",
        "parent_code": "settings",
        "name": "提供商",
        "name_en": "Providers",
        "path": "/settings/providers",
        "sort_no": 114,
        "enabled": True,
    },
    {
        "id": "settings.plugins",
        "code": "settings.plugins",
        "parent_code": "settings",
        "name": "插件",
        "name_en": "Plugins",
        "path": "/settings/plugins",
        "sort_no": 115,
        "enabled": True,
    },
    {
        "id": "settings.system",
        "code": "settings.system",
        "parent_code": "settings",
        "name": "系统",
        "name_en": "System",
        "path": "/settings/system",
        "sort_no": 116,
        "enabled": True,
    },
]

PERMISSION_CODES = [item["code"] for item in MENU_ITEMS]
LIMITED_PERMISSION_CODES = ["chat", "tasks", "settings.system", "settings.providers"]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _token_fingerprint(token: str | None) -> str | None:
    if not token:
        return None
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def _codes_for_token(token: str | None) -> list[str]:
    if (token or "").strip() == "limited-token":
        return LIMITED_PERMISSION_CODES
    return PERMISSION_CODES


def build_permissions_payload(token: str | None) -> dict[str, Any]:
    """Build the mock response shape consumed by WebUI's normalizer."""
    codes = _codes_for_token(token)
    code_set = set(codes)
    menus = [item for item in MENU_ITEMS if item["code"] in code_set]
    return {
        "ok": True,
        "source": "hermes-menu-permissions-mock",
        "token_present": bool(token),
        "token_fingerprint": _token_fingerprint(token),
        "data": {
            "menus": menus,
            "permissions": codes,
        },
    }


def _extract_bearer_token(headers) -> str | None:
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        token = auth[7:].strip()
        if token:
            return token
    return None


class MenuPermissionsHandler(BaseHTTPRequestHandler):
    server_version = "HermesMenuPermissionsMock/1.0"

    def do_OPTIONS(self) -> None:
        self._send_json({"ok": True}, status=HTTPStatus.NO_CONTENT)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json({"ok": True, "route": ROUTE_PATH})
            return
        if parsed.path != ROUTE_PATH:
            self._send_json({"ok": False, "error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return
        query = parse_qs(parsed.query)
        token = (query.get("token") or query.get("access_token") or query.get("auth_token") or [""])[0].strip()
        token = token or _extract_bearer_token(self.headers)
        self._handle_permissions(token)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != ROUTE_PATH:
            self._send_json({"ok": False, "error": "not found"}, status=HTTPStatus.NOT_FOUND)
            return

        body = self._read_json_body()
        query = parse_qs(parsed.query)
        token = ""
        if isinstance(body, dict):
            for key in ("token", "access_token", "auth_token"):
                value = body.get(key)
                if isinstance(value, str) and value.strip():
                    token = value.strip()
                    break
        if not token:
            token = (query.get("token") or query.get("access_token") or query.get("auth_token") or [""])[0].strip()
        token = token or _extract_bearer_token(self.headers)
        self._handle_permissions(token)

    def _handle_permissions(self, token: str | None) -> None:
        if _env_bool("MENU_PERMISSIONS_MOCK_REQUIRE_TOKEN", True) and not token:
            self._send_json(
                {
                    "ok": False,
                    "error": "missing token",
                    "message": "Pass token in JSON body, query string, or Authorization: Bearer header.",
                },
                status=HTTPStatus.UNAUTHORIZED,
            )
            return
        payload = build_permissions_payload(token)
        self.log_message(
            "resolved token=%s menus=%s permissions=%s",
            payload["token_fingerprint"] or "none",
            len(payload["data"]["menus"]),
            ",".join(payload["data"]["permissions"]),
        )
        self._send_json(payload)

    def _read_json_body(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return None
        raw = self.rfile.read(min(length, 1024 * 1024))
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _send_json(self, payload: Any, *, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", "0" if status == HTTPStatus.NO_CONTENT else str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        if status != HTTPStatus.NO_CONTENT:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[menu-permissions-mock] {self.address_string()} - {fmt % args}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Hermes menu permissions mock API.")
    parser.add_argument("--host", default=os.getenv("MENU_PERMISSIONS_MOCK_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MENU_PERMISSIONS_MOCK_PORT", "8791")))
    args = parser.parse_args(argv)

    server = ThreadingHTTPServer((args.host, args.port), MenuPermissionsHandler)
    print(f"Menu permissions mock listening on http://{args.host}:{args.port}{ROUTE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping menu permissions mock.")
    finally:
        server.server_close()
    return 0
