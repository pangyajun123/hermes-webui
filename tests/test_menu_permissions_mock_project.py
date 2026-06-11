"""Static checks for the local menu-permissions mock project."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
MOCK_ROOT = ROOT / "examples" / "menu-permissions-mock"


def test_mock_menu_codes_match_webui_permission_ids():
    sys.path.insert(0, str(MOCK_ROOT))
    try:
        from menu_permissions_mock import PERMISSION_CODES
        from api.menu_permissions import PRIMARY_PANEL_IDS, SETTINGS_SECTION_IDS

        expected = set(PRIMARY_PANEL_IDS) | {f"settings.{section}" for section in SETTINGS_SECTION_IDS}
        assert set(PERMISSION_CODES) == expected
    finally:
        try:
            sys.path.remove(str(MOCK_ROOT))
        except ValueError:
            pass


def test_mock_payload_uses_supported_route_and_container_names():
    sys.path.insert(0, str(MOCK_ROOT))
    try:
        from menu_permissions_mock.server import ROUTE_PATH, build_permissions_payload

        payload = build_permissions_payload("demo-token")
        assert ROUTE_PATH == "/api/hermes/menu-permissions"
        assert "data" in payload
        assert "menus" in payload["data"]
        assert "permissions" in payload["data"]
        assert "demo-token" not in str(payload)
    finally:
        try:
            sys.path.remove(str(MOCK_ROOT))
        except ValueError:
            pass


def test_mock_supports_limited_token_for_visible_menu_filtering():
    sys.path.insert(0, str(MOCK_ROOT))
    try:
        from menu_permissions_mock.server import build_permissions_payload
        from api.menu_permissions import normalize_menu_permissions

        payload = build_permissions_payload("limited-token")
        assert payload["data"]["permissions"] == ["chat", "tasks", "settings.providers"]
        normalized = normalize_menu_permissions(payload)
        assert normalized["allowed_panels"] == ["chat", "tasks", "settings"]
        assert normalized["allowed_settings_sections"] == ["providers"]
    finally:
        try:
            sys.path.remove(str(MOCK_ROOT))
        except ValueError:
            pass
