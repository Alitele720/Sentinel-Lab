# Sentinel Lab

Sentinel Lab 是一个基于 `Flask + SQLite` 的 Web IDS 与蜜罐演示平台，适合网络安全课程设计、课堂展示、本地攻防实验和 GitHub 项目展示。

项目把 Web 请求、实验连接事件、规则检测、告警生成、自动封禁和后台展示放在同一个应用中，便于演示一条完整的检测链路。

```text
请求 / 连接事件 -> 日志记录 -> 规则检测 -> 告警生成 -> 自动封禁 -> 后台展示
```

> 本项目仅用于教学、演示和授权实验环境，不是生产级 IDS 产品。请勿将本项目用于未授权测试或攻击活动。

## 功能亮点

- 基于 `Flask` 的模块化 Web 应用
- 使用 `SQLite` 保存请求日志、连接事件、告警、规则、配置和黑名单
- 支持 SQL 注入、XSS、暴力破解、敏感路径扫描和端口扫描演示
- 支持规则匹配、阈值检测、告警冷却和高危来源自动封禁
- 支持应用层 IP 黑名单和端口阻断演示
- 提供仪表盘、告警列表、规则管理、策略配置和黑名单管理页面
- 支持告警 CSV 导出
- 包含基础回归测试，方便修改后验证功能

## 技术栈

- Python 3
- Flask 3
- SQLite
- Waitress
- HTML / CSS / JavaScript

## 文档导航

- [ARCHITECTURE.md](ARCHITECTURE.md)：系统架构、检测链路和核心模块说明
- [DEPLOYMENT.md](DEPLOYMENT.md)：本地运行、LAN 演示和部署配置
- [TESTING.md](TESTING.md)：单元测试和手工演示测试指南
- [SECURITY.md](SECURITY.md)：安全边界、授权使用和敏感文件处理说明

## 项目结构

```text
.
|-- app.py                  # 本地运行入口
|-- wsgi.py                 # WSGI 部署入口
|-- requirements.txt        # Python 依赖
|-- ids_app/                # 应用核心代码
|-- templates/              # 页面模板
|-- static/                 # 静态资源
|-- tests/                  # 单元测试
|-- ARCHITECTURE.md         # 架构说明
|-- DEPLOYMENT.md           # 部署说明
|-- TESTING.md              # 测试说明
|-- SECURITY.md             # 安全说明
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

如果已安装 `waitress`，项目会优先使用 Waitress 启动；否则回退到 Flask 内置服务器。

## 主要页面和接口

| 路径 | 说明 |
| --- | --- |
| `/` | 蜜罐首页 |
| `/portal` | 登录页面，可用于暴力破解演示 |
| `/search` | 搜索页面，可用于 SQL 注入演示 |
| `/contact` | 联系表单，可用于 XSS 演示 |
| `/health` | 健康检查接口 |
| `/admin/login` | 后台登录 |
| `/ops` | 后台入口 |
| `/dashboard` | 仪表盘 |
| `/alerts` | 告警列表 |
| `/rules` | 检测规则管理 |
| `/config` | 阈值与策略配置 |
| `/blacklist` | 黑名单与端口阻断管理 |
| `/api/stats` | 仪表盘统计接口 |
| `/export/alerts.csv` | 告警 CSV 导出 |

## 演示场景

建议使用实验 IP 进行演示，例如：

```text
10.10.10.66
10.10.10.67
10.10.10.88
10.10.10.99
```

如果 `127.0.0.1` 在白名单中，不建议用它模拟攻击来源，否则可能绕过部分封禁效果。

### SQL 注入

在 `/search` 页面输入：

```text
' or 1=1 --
```

预期结果：`/alerts` 页面出现 SQL 注入告警。

### XSS

在 `/contact` 页面提交：

```html
<script>alert(1)</script>
```

预期结果：`/alerts` 页面出现 XSS 告警。

### 暴力破解

在 `/portal` 页面连续提交错误用户名或密码，达到阈值后会触发暴力破解告警，严重时会自动加入黑名单。

### 敏感路径扫描

连续访问以下路径可触发扫描探测判断：

```text
/admin
/.env
/phpmyadmin
/wp-admin
/manager/html
```

### 端口扫描实验

在后台实验入口提交端口范围，例如：

```text
demo_ip = 10.10.10.99
start_port = 20
end_port = 39
```

预期结果：生成连接事件，达到阈值后生成 `port_scan` 告警，高危扫描可触发自动封禁。

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

## 上传 GitHub 前检查

- 不提交 `.env`、真实密钥、真实账号密码
- 不提交 `data/` 下的数据库和日志
- 不提交 `__pycache__/`、`.pyc`、测试缓存等运行产物
- 不提交本地 ZIP 压缩包，除非它们是正式发布资产
- 确认 `.env.example` 只包含示例值
- 确认文档中的命令和路径与当前代码一致

当前 `.gitignore` 已覆盖 `.env`、`data/`、`*.db`、`*.log`、`__pycache__/` 和 `*.zip` 等常见敏感文件与运行产物。

## License

当前项目未声明开源许可证。如需复用、分发或二次开发，请联系作者或自行补充合适的许可证文件。
