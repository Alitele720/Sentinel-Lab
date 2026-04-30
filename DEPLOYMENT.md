# 部署指南

本文说明 Sentinel Lab 的本地运行、局域网演示和基础部署方式。项目适合教学和实验环境，不建议直接暴露到公网。

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

修改 `.env` 中的示例值，尤其是 `IDS_SECRET_KEY`、后台用户名和后台密码。

## 环境变量

常用配置项如下：

| 变量 | 说明 |
| --- | --- |
| `IDS_SECRET_KEY` | Flask 会话密钥，部署时必须修改 |
| `IDS_HOST` | 监听地址，本地可用 `127.0.0.1`，局域网演示可用 `0.0.0.0` |
| `IDS_PORT` | 监听端口，默认 `5000` |
| `IDS_ADMIN_ALLOWED_IPS` | 允许访问后台的 IP 白名单 |
| `IDS_ADMIN_AUTH_ENABLED` | 是否启用后台账号密码认证 |
| `IDS_ADMIN_USERNAME` | 后台用户名 |
| `IDS_ADMIN_PASSWORD` | 后台密码 |
| `IDS_TRUST_PROXY` | 是否信任反向代理传入的真实 IP |
| `IDS_TRUSTED_PROXY_IPS` | 可信反向代理 IP 列表 |
| `IDS_EXPOSE_LABS` | 是否开放实验接口 |
| `IDS_SYNC_INGEST_REAL_REQUESTS` | 是否同步消费真实请求日志 |
| `IDS_START_WATCHER` | 是否启动后台日志消费线程 |

## 本地运行

```powershell
python app.py
```

默认访问：

```text
http://127.0.0.1:5000
```

如果已安装 `waitress`，`app.py` 会优先使用 Waitress 启动；否则使用 Flask 内置服务器。

## 局域网演示

局域网演示时建议使用以下配置：

```env
IDS_HOST=0.0.0.0
IDS_PORT=5000
IDS_ADMIN_ALLOWED_IPS=127.0.0.1,::1,你的管理主机IP
IDS_ADMIN_AUTH_ENABLED=true
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

也可以通过 `wsgi.py` 启动：

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
/rules
/config
/blacklist
```

建议始终开启：

```env
IDS_ADMIN_AUTH_ENABLED=true
```

并将 `IDS_ADMIN_ALLOWED_IPS` 设置为可信管理主机 IP。非白名单 IP 不能进入后台。

## 实验接口开关

实验接口包括 SQL、XSS、暴力破解和端口扫描模拟入口。公开或半公开环境建议关闭：

```env
IDS_EXPOSE_LABS=false
```

课堂演示、本地实验或受控局域网环境可以临时开启：

```env
IDS_EXPOSE_LABS=true
```

## 反向代理配置

默认情况下，系统不信任 `X-Forwarded-For`，会使用真实连接 IP。

如果部署在可信反向代理后面，可以开启：

```env
IDS_TRUST_PROXY=true
IDS_TRUSTED_PROXY_IPS=127.0.0.1
```

只应把真实可信的代理 IP 写入 `IDS_TRUSTED_PROXY_IPS`。不要在不确定代理链路的情况下开启该选项，否则攻击者可能伪造来源 IP。

## 数据和日志

项目运行时会在 `data/` 下生成数据库和日志文件，例如：

```text
data/ids.db
data/access.log
data/access.bad.log
```

这些文件包含本地运行数据，不应提交到 GitHub。当前 `.gitignore` 已忽略 `data/`、`*.db` 和 `*.log`。

## 安全建议

- 不要把真实 `.env` 上传到 GitHub
- 不要使用默认后台密码部署
- 不要将实验接口暴露给不可信用户
- 不要把该项目直接作为生产防护系统使用
- 公网环境请额外使用防火墙、反向代理访问控制和 HTTPS

更多安全边界见 [SECURITY.md](SECURITY.md)。
