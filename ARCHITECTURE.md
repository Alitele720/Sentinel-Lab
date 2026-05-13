# 架构说明

本文说明 Sentinel Lab 当前代码中的系统定位、模块职责、检测链路、数据表和安全边界。

## 系统定位

Sentinel Lab 是面向教学和演示的 Web IDS / 蜜罐实验平台。它通过公开诱饵页面、结构化请求日志、真实 TCP SYN 抓包事件、规则检测和后台可视化，展示可疑行为从记录到处置的完整闭环。

```text
可疑行为 -> 日志/连接事件 -> 检测逻辑 -> 告警 -> 黑名单/端口阻断 -> 后台展示
```

项目不是生产级 IDS，也不会下发系统防火墙规则。当前端口阻断是应用层访问控制演示。

## 总体链路

系统有两条主要输入链路。

Web 请求链路：

```text
Web 请求 -> data/access.log -> request_logs -> SQL/XSS/暴力破解/敏感路径扫描 -> attack_events
```

`data/access.log` 保存正常结构化请求日志。无法解析的坏 JSON 或字段结构不合法的日志会写入 `data/access.bad.log`，供后台 `/logs` 页面排查。

端口扫描链路：

```text
Npcap/scapy TCP SYN 抓包 -> connection_events -> port_scan 检测 -> attack_events
```

告警生成后，系统会根据阈值和配置联动处置：

```text
attack_events -> blacklist / port_blocks -> 请求拦截 -> 仪表盘和管理页展示
```

## 核心模块

| 模块 | 职责 |
| --- | --- |
| `app.py` | 本地和局域网启动入口，创建应用、打印访问地址，并优先使用 Waitress 运行。 |
| `wsgi.py` | WSGI 部署入口，暴露 `app` 对象。 |
| `ids_app/web.py` | Flask 应用工厂，初始化数据目录和数据库，加载部署配置，注册路由和请求钩子。 |
| `ids_app/routes_public.py` | 公开蜜罐页面、探测路径、健康检查和兜底 404。 |
| `ids_app/routes_admin.py` | 后台页面、运行日志、实验动作、实验记录清理、统计接口、规则配置、黑名单和 CSV 导出。 |
| `ids_app/detection.py` | 请求日志消费、载荷归一化、规则匹配、告警生成、连接事件入库和端口扫描检测。 |
| `ids_app/lab.py` | 教学实验辅助逻辑，构造模拟请求记录、登录尝试记录和测试连接事件。 |
| `ids_app/portscan_capture.py` | 可选的真实端口扫描抓包入口，将入站 TCP SYN 包转换为连接事件。 |
| `ids_app/storage.py` | SQLite 初始化、默认配置和规则写入、表单校验、历史乱码修复、黑名单/端口阻断状态管理。 |
| `ids_app/security.py` | 后台访问控制、会话认证、白名单检查、可信代理 IP 解析和实验入口权限。 |
| `ids_app/deploy.py` | `.env` 和环境变量加载，生成 Flask 配置。 |
| `ids_app/runtime.py` | 运行时路径、数据库/日志文件位置、后台线程状态和测试覆盖用的路径重定向。 |
| `ids_app/constants.py` | 默认阈值、默认检测规则、攻击类型标签、敏感路径和显示格式常量。 |

应用启动时会初始化数据库、补齐默认配置和规则，并调用 `repair_legacy_text_encoding()` 修复历史数据库中“UTF-8 被按 GBK/GB18030 误解码”留下的用户可见中文乱码。

## 检测能力

### SQL 注入和 XSS

系统会把路径、查询参数、表单数据和 JSON 内容归一化为统一文本，进行 URL 解码、HTML 实体解码、大小写统一和空白压缩。随后按启用规则进行关键字或正则匹配，分数达到阈值后生成 `sql_injection` 或 `xss` 告警。

规则存放在 `rules` 表中，默认只允许管理 SQL 注入和 XSS 规则。

### 暴力破解

`/portal` 真实提交和后台实验动作都会写入登录尝试记录。系统按来源 IP 和时间窗口统计失败次数，达到低危、高危或封禁阈值后生成 `bruteforce` 告警。达到封禁阈值时，可自动写入 `blacklist` 并联动 `port_blocks`。

### 敏感路径扫描

系统按来源 IP 统计短时间窗口内的唯一访问路径数、404 次数和敏感路径命中次数。达到阈值后生成 `scan_probe` 告警；更高风险的扫描模式可触发自动封禁。

### 端口扫描

端口扫描检测基于 `connection_events` 表。生产式演示中，这些事件由 `ids_app/portscan_capture.py` 通过 `scapy` 捕获入站 TCP SYN 包生成；测试中也可以直接写入连接事件。

检测逻辑按来源 IP、目标 IP、协议和时间窗口统计唯一目标端口数量。达到低阈值生成 `port_scan` 告警，达到高阈值可自动加入黑名单并触发端口阻断。

## 数据表

SQLite 连接启用 WAL、`busy_timeout` 和较宽松的同步策略，以便请求线程、日志 watcher 和可选抓包线程并发读写时减少锁冲突。

| 表 | 说明 |
| --- | --- |
| `request_logs` | Web 请求日志，包含来源、路径、状态码、参数、归一化载荷和登录结果。 |
| `connection_events` | TCP 连接探测事件，用于端口扫描检测和流量统计。 |
| `attack_events` | SQLi、XSS、暴力破解、路径扫描和端口扫描告警。 |
| `rules` | SQL 注入和 XSS 检测规则。 |
| `system_config` | 阈值、白名单、黑名单时长和端口阻断策略配置。 |
| `blacklist` | IP 黑名单记录。 |
| `port_blocks` | 应用层端口阻断记录。 |
| `login_attempts` | 登录成功和失败记录，用于暴力破解检测。 |

## 访问控制和处置

所有非静态请求都会经过请求守卫：

- 后台路由由 `ADMIN_ALLOWED_IPS` 和后台登录状态保护。
- 公开蜜罐请求会解析有效来源 IP，并检查白名单、黑名单和端口阻断状态。
- 白名单 IP 不参与封禁和端口阻断。
- 命中黑名单或端口阻断时，HTML 请求返回阻断页面，JSON 请求返回 403 JSON。

告警冷却机制会减少重复告警；当风险等级升级或自动封禁状态变化时，仍会生成新的可见告警。

## 边界说明

- 本项目是教学演示系统，不是生产级入侵检测产品。
- 端口扫描抓包依赖本机权限、Npcap/scapy 和网络环境，不能保证覆盖所有扫描行为。
- `port_blocks` 是应用层阻断演示，不会修改操作系统防火墙。
- 默认规则和阈值适合演示，不适合作为生产环境唯一防线。
