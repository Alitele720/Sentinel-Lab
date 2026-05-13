# Sentinel Lab

本项目是南京邮电大学网络安全课程设计内容，用于课程实践、课堂演示和授权实验环境。

Sentinel Lab 是一个基于 `Flask + SQLite` 的 Web IDS 与蜜罐演示平台。当前代码采用 `ids_app` 应用工厂结构，`app.py` 用于本地/局域网启动，`wsgi.py` 用于 WSGI 部署。

项目把公开蜜罐页面、请求日志、规则检测、告警生成、自动封禁、端口阻断和后台展示放在同一个教学应用中，方便演示一条完整的检测链路：

```text
Web 请求 / TCP SYN 抓包事件 -> 日志或连接事件 -> 检测规则 -> 告警 -> 黑名单/端口阻断 -> 后台展示
```

> 本项目仅用于教学、演示和授权实验环境，不是生产级 IDS 产品。不要将它用于未授权测试或攻击活动。

## 功能亮点

- 模块化 Flask 应用：`ids_app/web.py` 创建应用并注册公开路由和后台路由。
- SQLite 持久化：保存请求日志、连接事件、告警、规则、配置、黑名单、端口阻断和登录尝试。
- Web 攻击检测：支持 SQL 注入、XSS、暴力破解和敏感路径扫描。
- 真实端口扫描检测：可选用 `scapy`/Npcap 捕获入站 TCP SYN 包，并生成 `port_scan` 告警。
- 自动处置：高危行为可写入 IP 黑名单，并可演示应用层端口阻断。
- 管理后台：提供仪表盘、告警列表、运行日志、规则管理、配置管理、黑名单与端口阻断管理。
- 安全入口：后台支持 IP 白名单、账号密码登录、可信代理 IP 解析和实验接口暴露开关。
- 数据导出：支持告警 CSV 导出。
- 自动化测试：`tests/test_app.py` 覆盖核心检测、后台访问控制、配置、日志查看、统计接口和端口扫描抓包解析。

## 技术栈

- Python 3
- Flask 3
- SQLite
- Waitress
- scapy
- HTML / CSS / JavaScript

## 文档导航

- [ARCHITECTURE.md](ARCHITECTURE.md)：系统结构、模块职责、检测链路和数据表说明。
- [DEPLOYMENT.md](DEPLOYMENT.md)：本地运行、局域网演示、环境变量和端口扫描抓包配置。
- [TESTING.md](TESTING.md)：自动化测试和手工演示测试指南。

## 项目结构

```text
.
|-- app.py                  # 本地和局域网启动入口
|-- wsgi.py                 # WSGI 部署入口
|-- requirements.txt        # Python 依赖
|-- ids_app/                # 应用核心代码
|-- templates/              # Flask 页面模板
|-- static/                 # 静态资源
|-- tests/                  # 自动化测试
|-- ARCHITECTURE.md         # 架构说明
|-- DEPLOYMENT.md           # 部署说明
|-- TESTING.md              # 测试说明
`-- .env.example            # 环境变量示例
```

## 快速开始

### 1. 安装依赖

```powershell
python -m pip install -r requirements.txt
```

### 2. 创建环境变量文件

```powershell
Copy-Item .env.example .env
```

根据需要修改 `.env`。公开上传 GitHub 时不要提交真实 `.env` 文件。

### 3. 启动项目

```powershell
python app.py
```

默认访问地址：

```text
http://127.0.0.1:5000
```

如果安装了 `waitress`，`app.py` 会优先使用 Waitress 启动；否则回退到 Flask 内置服务器。

## 主要页面和接口

| 路径                 | 说明                                              |
| -------------------- | ------------------------------------------------- |
| `/`                  | 公开蜜罐首页                                      |
| `/portal`            | 登录诱饵页，可用于暴力破解演示                    |
| `/search`            | 搜索诱饵页，可用于 SQL 注入演示                   |
| `/contact`           | 联系表单，可用于 XSS 演示                         |
| `/health`            | 健康检查接口                                      |
| `/admin/login`       | 后台登录                                          |
| `/ops`               | 后台入口，进入仪表盘                              |
| `/dashboard`         | 仪表盘                                            |
| `/alerts`            | 告警列表                                          |
| `/logs`              | 运行日志，可查看 `access.log` 和 `access.bad.log` |
| `/rules`             | 检测规则管理                                      |
| `/config`            | 阈值与策略配置                                    |
| `/blacklist`         | 黑名单与端口阻断管理                              |
| `/api/stats`         | 仪表盘统计接口                                    |
| `/export/alerts.csv` | 告警 CSV 导出                                     |

后台实验路由仍支持 SQL 注入、XSS、暴力破解和异常探测辅助演示；端口扫描不再提供页面或 API 模拟提交。`/lab/portscan` 和 `/api/connection-events` 已从当前代码中移除。端口扫描告警来自真实 TCP SYN 抓包或测试代码直接写入的连接事件。

## 演示场景

建议使用非白名单的实验 IP 进行演示，例如：

```text
10.10.10.66
10.10.10.67
10.10.10.88
10.10.10.99
```

默认白名单包含 `127.0.0.1` 和 `::1`，不要用它们模拟攻击来源，否则会绕过部分封禁效果。

### SQL 注入

访问 `/search` 并提交：

```text
' or 1=1 --
```

预期结果：`/alerts` 中出现 `sql_injection` 告警。

### XSS

在 `/contact` 中提交：

```html
<script>alert(1)</script>
```

预期结果：`/alerts` 中出现 `xss` 告警。

### 暴力破解

在 `/portal` 连续提交错误密码。达到低危、高危或封禁阈值后，系统会生成 `bruteforce` 告警；达到封禁阈值后，来源 IP 会进入黑名单，并可联动端口阻断。

### 敏感路径扫描

连续访问以下路径可触发扫描探测判断：

```text
/admin
/.env
/phpmyadmin
/wp-admin
/manager/html
```

预期结果：`/alerts` 中出现 `scan_probe` 告警。

### 端口扫描抓包

端口扫描检测依赖真实 TCP SYN 抓包。Windows 环境需要安装 Npcap，并以管理员权限启动服务。启用配置示例：

```env
IDS_PORTSCAN_CAPTURE_ENABLED=true
IDS_PORTSCAN_CAPTURE_INTERFACE=
IDS_PORTSCAN_CAPTURE_FILTER=tcp
```

从另一台局域网主机扫描运行 Sentinel Lab 的机器：

```powershell
nmap 你的服务器局域网IP
```

预期结果：系统从 TCP SYN 包生成 `connection_events`，达到阈值后生成 `port_scan` 告警；高危扫描可触发黑名单和端口阻断。

### 运行日志和实验清理

后台 `/logs` 页面可查看 `data/access.log` 中的结构化访问日志，以及 `data/access.bad.log` 中被隔离的坏日志。仪表盘提供“清空实验记录”操作，会清空请求、告警、连接事件、黑名单、端口阻断和日志内容，但保留检测规则与系统配置。

## 测试

运行基础回归测试：

```powershell
python -m unittest tests.test_app
```

更多测试场景见 [TESTING.md](TESTING.md)。

## 部署

本地演示可直接运行：

```powershell
python app.py
```

WSGI 方式可使用：

```powershell
waitress-serve --host=0.0.0.0 --port=5000 wsgi:app
```

更多部署建议见 [DEPLOYMENT.md](DEPLOYMENT.md)。



