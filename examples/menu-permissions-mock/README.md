# Hermes menu permissions mock

本目录是一个本地菜单权限 mock 服务，用于联调
`HERMES_WEBUI_MENU_PERMISSIONS_URL`。

它只依赖 Python 标准库，默认监听：

```bash
http://127.0.0.1:8791/api/hermes/menu-permissions
```

## 启动

```bash
cd examples/menu-permissions-mock
python3 -m menu_permissions_mock --host 127.0.0.1 --port 8791
```

## 测试接口

POST:

```bash
curl -sS \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer demo-token' \
  -d '{"token":"demo-token"}' \
  http://127.0.0.1:8791/api/hermes/menu-permissions
```

GET:

```bash
curl -sS \
  'http://127.0.0.1:8791/api/hermes/menu-permissions?token=demo-token'
```

## WebUI 对接配置

推荐用 POST：

```bash
HERMES_WEBUI_MENU_PERMISSIONS_URL=http://127.0.0.1:8791/api/hermes/menu-permissions \
HERMES_WEBUI_MENU_PERMISSIONS_METHOD=POST \
HERMES_WEBUI_MENU_TOKEN_PARAM=token \
HERMES_WEBUI_MENU_PERMISSIONS_BODY_FIELD=token \
./start.sh
```

然后用带入口 token 的地址打开 WebUI：

```text
http://127.0.0.1:8787/?token=demo-token
```

服务默认要求 token 非空。内置两个演示 token：

- `demo-token`：返回完整菜单权限。
- `limited-token`：只返回 `chat`、`tasks`、`settings.providers`，用于验证菜单隐藏效果。

其他任意非空 token 默认返回完整菜单权限。
如需临时允许无 token 调试：

```bash
MENU_PERMISSIONS_MOCK_REQUIRE_TOKEN=0 python3 -m menu_permissions_mock
```
