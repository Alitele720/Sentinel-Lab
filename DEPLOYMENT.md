# 部署指南

本文说明 Sentinel Lab 的本地运行、局域网演示、环境变量、后台访问控制、代理 IP 信任和端口扫描抓包配置。

## 环境准备

建议使用 Python 3.10 或更高版本。

安装依赖：

```powershell
python -m pip install -r requirements.txt
```

创建配置文件：

```powershell
Copy-Item .env.example .env
```

部署前请修改 `.env` 中的示例值，尤其是 `IDS_SECRET_KEY`、后台用户名和后台密码。

## 环境变量

当前配置由 `ids_app/deploy.py` 从 `.env` 和系统环境变量加载。

| 变量 | 说明 |
| --- | --- |
| `IDS_SECRET_KEY` | Flask 会话密钥，部署时必须修改。 |
| `IDS_HOST` | 监听地址。本地可用 `127.0.0.1`，局域网演示可用 `0.0.0.0`。 |
| `IDS_PORT` | 监听端口，默认 `5000`。 |
| `IDS_PRODUCTION_MODE` | 生产模式标记，当前默认 `true`。 |
| `IDS_START_WATCHER` | 是否启动后台日志消费线程，默认 `true`。 |
| `IDS_SYNC_INGEST_REAL_REQUESTS` | 是否在请求结束后同步消费真实请求日志，默认 `true`。 |
| `IDS_ADMIN_ALLOWED_IPS` | 允许访问后台的 IP 白名单，逗号分隔。 |
| `IDS_ADMIN_AUTH_ENABLED` | 是否启用后台账号密码认证。 |
| `IDS_ADMIN_USERNAME` | 后台用户名。 |
| `IDS_ADMIN_PASSWORD` | 后台密码。 |
| `IDS_EXPOSE_LABS` | 是否向非管理员开放实验路由。 |
| `IDS_TRUST_PROXY` | 是否信任反向代理传入的真实客户端 IP。 |
| `IDS_TRUSTED_PROXY_IPS` | 可信反向代理 IP 列表，逗号分隔。 |
| `IDS_PORTSCAN_CAPTURE_ENABLED` | 是否启用真实端口扫描抓包。 |
| `IDS_PORTSCAN_CAPTURE_INTERFACE` | 抓包网卡名称，留空时由 scapy 使用默认网卡。 |
| `IDS_PORTSCAN_CAPTURE_FILTER` | scapy 抓包过滤器，默认 `tcp`。 |

## 本地运行

```powershell
python app.py
```

默认访问：

```text
http://127.0.0.1:5000
```

如果安装了 `waitress`，`app.py` 会优先使用 Waitress；否则使用 Flask 内置服务器。

## 局域网演示

局域网演示建议配置：

```env
IDS_HOST=0.0.0.0
IDS_PORT=5000
IDS_SECRET_KEY=换成足够随机的密钥
IDS_ADMIN_ALLOWED_IPS=127.0.0.1,::1,你的管理主机IP
IDS_ADMIN_AUTH_ENABLED=true
IDS_ADMIN_USERNAME=admin
IDS_ADMIN_PASSWORD=换成强密码
IDS_EXPOSE_LABS=true
```

启动后，在同一局域网的浏览器访问：

```text
http://服务器局域网IP:5000
```

后台登录地址：

```text
http://服务器局域网IP:5000/admin/login
```

## WSGI 启动

可以通过 `wsgi.py` 启动：

```powershell
waitress-serve --host=0.0.0.0 --port=5000 wsgi:app
```

如果使用其他 WSGI 服务器，请将入口指向：

```text
wsgi:app
```

## 后台访问控制

后台页面包括：

```text
/ops
/dashboard
/alerts
/logs
/rules
/config
/blacklist
```

访问后台需要满足两层条件：

- 客户端 IP 在 `IDS_ADMIN_ALLOWED_IPS` 中。
- 当 `IDS_ADMIN_AUTH_ENABLED=true` 时，必须通过 `/admin/login` 登录。

建议在任何非本机环境都启用后台登录，并把 `IDS_ADMIN_ALLOWED_IPS` 限制为可信管理主机。

## 实验接口开关

实验接口用于教学演示 SQL、XSS、暴力破解和异常探测流程。默认不建议暴露给不可信用户：

```env
IDS_EXPOSE_LABS=false
```

当 `IDS_EXPOSE_LABS=false` 时，实验路由只允许已授权管理员访问；开启后，非管理员也可以访问这些实验路由。公开演示前应确认环境是受控的。

课堂演示、本机实验或受控局域网环境可以临时开启：

```env
IDS_EXPOSE_LABS=true
```

注意：当前代码已经移除 `/lab/portscan` 和 `/api/connection-events`，端口扫描不再通过后台表单或公开 API 模拟。

## 反向代理配置

默认情况下，系统不信任 `X-Forwarded-For`，会使用真实连接 IP：

```env
IDS_TRUST_PROXY=false
```

只有在确定请求来自可信反向代理时，才开启代理 IP 信任：

```env
IDS_TRUST_PROXY=true
IDS_TRUSTED_PROXY_IPS=你的代理IP
```

`X-Forwarded-For` 只会在请求来源 IP 属于 `IDS_TRUSTED_PROXY_IPS` 时生效。不要在不确定代理链路的情况下开启该选项，否则攻击者可能伪造来源 IP。

## 端口扫描抓包

真实端口扫描检测依赖 scapy 抓包。Windows 环境需要：

- 安装 Npcap。
- 用管理员权限启动 PowerShell 或终端。
- 确保防火墙和网络环境允许另一台主机向本机发起端口探测。

启用配置：

```env
IDS_PORTSCAN_CAPTURE_ENABLED=true
IDS_PORTSCAN_CAPTURE_INTERFACE=
IDS_PORTSCAN_CAPTURE_FILTER=tcp
```

启动 Sentinel Lab 后，从另一台局域网主机执行：

```powershell
nmap 服务器局域网IP
```

系统会把入站 TCP SYN 包转换为 `connection_events`，达到阈值后生成 `port_scan` 告警。抓包状态会出现在 `/api/stats` 和仪表盘相关展示中。

## 数据和日志

项目运行时会在 `data/` 下生成数据库和日志文件：

```text
data/ids.db
data/access.log
data/access.bad.log
```

其中 `data/ids.db` 保存请求、告警、规则、配置、黑名单、端口阻断和连接事件；`data/access.log` 保存正常结构化访问日志；`data/access.bad.log` 保存无法解析或结构不合法的日志行，便于在 `/logs` 页面排查。

这些文件包含本地运行数据，不应提交到 GitHub。当前 `.gitignore` 已忽略 `data/`、`*.db` 和 `*.log`。

## 安全建议

- 不要把真实 `.env` 上传到 GitHub。
- 不要使用默认后台密码部署。
- 不要把实验接口暴露给不可信用户。
- 不要把该项目直接作为生产防护系统使用。
- 公网环境应额外使用防火墙、反向代理访问控制和 HTTPS。
