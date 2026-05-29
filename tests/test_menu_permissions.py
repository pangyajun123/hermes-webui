"""Regression tests for entry-token menu permission filtering."""

import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
PANELS_JS = (ROOT / "static" / "panels.js").read_text(encoding="utf-8")
BOOT_JS = (ROOT / "static" / "boot.js").read_text(encoding="utf-8")
STYLE_CSS = (ROOT / "static" / "style.css").read_text(encoding="utf-8")
ROUTES_PY = (ROOT / "api" / "routes.py").read_text(encoding="utf-8")


def test_normalize_common_menu_permission_shapes():
    from api.menu_permissions import normalize_menu_permissions

    payload = normalize_menu_permissions(
        {
            "data": {
                "menus": [
                    {"code": "menu.tasks"},
                    {"permission": "settings.providers"},
                    {"id": "workspace"},
                    {"children": [{"menuCode": "logs:read"}]},
                ]
            }
        }
    )

    assert payload["enabled"] is True
    assert "tasks" in payload["allowed_panels"]
    assert "workspaces" in payload["allowed_panels"]
    assert "logs" in payload["allowed_panels"]
    assert "settings" in payload["allowed_panels"]
    assert payload["allowed_settings_sections"] == ["providers"]


def test_disabled_permission_endpoint_preserves_current_all_menus(monkeypatch):
    import api.menu_permissions as menu_permissions

    monkeypatch.delenv("HERMES_WEBUI_MENU_PERMISSIONS_URL", raising=False)
    payload, headers = menu_permissions.resolve_menu_permissions_for_request(
        SimpleNamespace(headers={}),
        SimpleNamespace(query=""),
    )

    assert headers == {}
    assert payload["enabled"] is False
    for panel in ("chat", "tasks", "kanban", "settings"):
        assert panel in payload["allowed_panels"]
    assert payload["allowed_settings_sections"] == [
        "conversation",
        "appearance",
        "preferences",
        "providers",
        "plugins",
        "system",
    ]


def test_query_token_fetches_remote_permissions_without_echoing_token(monkeypatch):
    import api.menu_permissions as menu_permissions

    monkeypatch.setenv("HERMES_WEBUI_MENU_PERMISSIONS_URL", "https://example.test/menus")

    def fake_fetch(token):
        assert token == "secret-entry-token"
        return menu_permissions.normalize_menu_permissions(["chat", "settings.system"])

    monkeypatch.setattr(menu_permissions, "_fetch_remote_permissions", fake_fetch)
    monkeypatch.setattr(menu_permissions, "_set_cookie_header", lambda _handler, _payload: "hermes_menu_permissions=fake")

    payload, headers = menu_permissions.resolve_menu_permissions_for_request(
        SimpleNamespace(headers={}),
        SimpleNamespace(query="token=secret-entry-token"),
    )

    assert headers["Set-Cookie"] == "hermes_menu_permissions=fake"
    assert payload["allowed_panels"] == ["chat", "settings"]
    assert payload["allowed_settings_sections"] == ["system"]
    assert "secret-entry-token" not in json.dumps(payload)


def test_static_menu_permission_wiring():
    assert "menuPermissions:__MENU_PERMISSIONS_JSON__" in INDEX_HTML
    assert "menuTokenParam:__MENU_TOKEN_PARAM_JSON__" in INDEX_HTML
    assert "history.replaceState" in INDEX_HTML
    assert "__MENU_PERMISSIONS_JSON__" in ROUTES_PY
    assert "__MENU_TOKEN_PARAM_JSON__" in ROUTES_PY
    assert '"/api/menu-permissions"' in ROUTES_PY
    assert "resolve_menu_permissions_for_request" in ROUTES_PY

    for symbol in (
        "_applyMenuPermissions",
        "_isPanelAllowed",
        "_isSettingsSectionAllowed",
        "_firstAllowedPanel",
        "nav-tab-permission-hidden",
        "side-menu-item-permission-hidden",
    ):
        assert symbol in PANELS_JS

    switch_block = PANELS_JS[PANELS_JS.find("async function switchPanel") :][:1200]
    assert "_isPanelAllowed(nextPanel)" in switch_block
    settings_block = PANELS_JS[PANELS_JS.find("function switchSettingsSection") :][:1000]
    assert "_firstAllowedSettingsSection" in settings_block
    assert "_applyMenuPermissions()" in BOOT_JS
    assert ".nav-tab-permission-hidden" in STYLE_CSS
    assert ".side-menu-item-permission-hidden" in STYLE_CSS
