# 架构说明

本文介绍 Sentinel Lab 的系统定位、核心模块、检测链路和数据流。

## 系统定位

Sentinel Lab 是一个面向教学和演示的 Web IDS / 蜜罐实验平台。它不是基于原始网络流量的生产级 IDS，而是通过 Web 请求日志、实验连接事件、检测规则和阈值策略展示安全检测的完整闭环。

核心目标是让使用者能够看到：

```text
可疑行为如何被记录 -> 如何进入检测逻辑 -> 如何生成告警 -> 如何触发处置 -> 如何在后台展示
```

## 总体链路

系统有两类主要输入。

第一类是 Web 请求：

```text
Web 请求 -> access.log -> request_logs -> SQL / XSS / 暴力破解 / 扫描探测 -> attack_events
```

第二类是连接事件：

```text
端口扫描实验 -> connection_events -> 端口扫描检测 -> attack_events
```

告警生成后，系统会根据规则和阈值继续联动：

```text
attack_events -> blacklist / port_blocks -> 访问控制 -> 后台展示
```

## 核心模块

| 模块 | 职责 |
| --- | --- |
| `app.py` | 本地运行入口，创建应用并启动服务 |
| `wsgi.py` | WSGI 部署入口 |
| `ids_app/web.py` | Flask 应用工厂，请求前后钩子，路由注册 |
| `ids_app/routes_public.py` | 公开蜜罐页面和探测路径 |
| `ids_app/routes_admin.py` | 后台页面、实验接口、统计接口 |
| `ids_app/detection.py` | 日志消费、规则匹配、告警生成、端口扫描检测 |
| `ids_app/lab.py` | 实验请求和连接事件构造 |
| `ids_app/storage.py` | SQLite 初始化、查询、配置、规则和黑名单管理 |
| `ids_app/security.py` | 来源 IP 解析、后台访问控制、会话认证 |
| `ids_app/deploy.py` | `.env` 和环境变量加载 |
| `ids_app/runtime.py` | 运行时路径、日志文件和后台线程状态 |

## 检测能力

### SQL 注入

系统会对路径、查询参数、表单和 JSON 内容进行归一化，然后根据规则表中的 SQL 注入特征进行匹配。命中规则后累积分值，达到阈值则生成 `sql_injection` 告警。

示例特征包括：

- `' or 1=1`
- `union select`
- `sleep(`
- `benchmark(`
- `information_schema`

### XSS

XSS 检测与 SQL 注入共用内容归一化和规则匹配流程。达到阈值后生成 `xss` 告警。

示例特征包括：

- `<script`
- `javascript:`
- `onerror=`
- `onload=`
- `document.cookie`

### 暴力破解

登录失败会写入登录尝试记录。系统按来源 IP 和时间窗口统计失败次数，达到不同阈值后生成低危、高危或封禁级别的 `bruteforce` 告警。

### 敏感路径扫描

系统会统计同一来源在时间窗口内的访问模式，包括唯一路径数量、404 数量和敏感路径命中数量。达到阈值后生成扫描探测类告警。

### 端口扫描

端口扫描实验会生成连接事件。系统按来源 IP、目标 IP 和协议聚合时间窗口内的唯一目标端口数量，达到阈值后生成 `port_scan` 告警，高危扫描可以自动封禁。

## 数据表概览

| 表 | 说明 |
| --- | --- |
| `request_logs` | Web 请求日志 |
| `connection_events` | 连接事件，用于端口扫描检测和流量统计 |
| `attack_events` | 攻击和异常行为告警 |
| `rules` | SQL 注入和 XSS 检测规则 |
| `system_config` | 阈值、白名单、端口阻断等配置 |
| `blacklist` | IP 黑名单 |
| `port_blocks` | 应用层端口阻断记录 |
| `login_attempts` | 登录成功和失败记录 |

## 告警和处置

所有检测最终都会通过统一流程写入 `attack_events`。当事件达到高危条件时，系统可以继续执行自动处置：

- 写入 `blacklist`，阻断来源 IP
- 写入 `port_blocks`，演示应用层端口阻断
- 在 `/dashboard`、`/alerts`、`/blacklist` 中展示结果

为避免短时间内重复刷屏，系统对相同来源和相同攻击类型的告警使用冷却机制；但当风险等级升级时，仍会生成新的告警。

## 边界说明

- 本项目是日志型和实验事件型 IDS 演示，不做底层抓包
- 端口扫描事件来自实验模拟，不等同于操作系统级网络探针
- 端口阻断是应用层演示，不是防火墙规则下发
- 检测能力以规则、阈值和演示链路为主，不适合作为生产环境唯一防线
