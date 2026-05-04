# 测试指南

本文说明 Sentinel Lab 的自动化测试和手工演示测试方法。建议每次修改代码或文档中的运行说明后，都执行一次基础回归测试。

## 自动化测试

运行单元测试：

```powershell
python -m unittest tests.test_app
```

测试覆盖内容包括：

- 公开页面访问
- 后台页面访问控制
- `.env` 配置加载
- SQL 注入检测
- XSS 检测
- 暴力破解检测
- 敏感路径扫描检测
- 真实端口扫描抓包事件检测
- 黑名单和端口阻断逻辑
- 统计接口返回结构

## 手工测试准备

启动服务：

```powershell
python app.py
```

本机访问：

```text
http://127.0.0.1:5000
```

局域网访问时，将地址替换为服务器局域网 IP：

```text
http://服务器局域网IP:5000
```

建议在 `.env` 中开启实验接口：

```env
IDS_EXPOSE_LABS=true
```

如果要测试后台认证，建议开启：

```env
IDS_ADMIN_AUTH_ENABLED=true
```

## 普通访问测试

访问以下页面：

```text
/
/portal
/search?q=test
/contact
/health
```

预期结果：

- 页面或接口正常返回
- 后台可以看到请求记录
- 不应产生攻击告警

## SQL 注入测试

访问：

```text
/search?q=' or 1=1 --
```

也可以测试：

```text
/search?q=union select 1,2
```

预期结果：

- 页面正常返回
- `/alerts` 出现 SQL 注入告警
- 告警来源 IP 与测试来源一致

## XSS 测试

打开：

```text
/contact
```

在表单中提交：

```html
<script>alert(1)</script>
```

也可以提交：

```html
<img src=x onerror=alert(1)>
```

预期结果：

- 表单正常提交
- `/alerts` 出现 XSS 告警
- 请求路径显示为 `/contact`

## 暴力破解测试

打开：

```text
/portal
```

连续提交错误登录信息，例如：

```text
username = admin
password = wrong
```

预期结果：

- 多次失败后产生 `bruteforce` 告警
- 达到高危或封禁阈值后，来源 IP 进入 `/blacklist`
- 被封禁来源再次访问公开页面时返回阻断页面

## 敏感路径扫描测试

连续访问：

```text
/admin
/.env
/phpmyadmin
/wp-admin
/manager/html
```

预期结果：

- 页面大多返回 404 或拒绝信息
- `/alerts` 出现扫描探测类告警
- `/dashboard` 中请求和告警统计增加

## 端口扫描测试

端口扫描检测依赖 Npcap 和抓包权限。先安装 Npcap，然后用管理员权限启动 PowerShell，并在 `.env` 中开启：

```env
IDS_PORTSCAN_CAPTURE_ENABLED=true
IDS_PORTSCAN_CAPTURE_INTERFACE=
IDS_PORTSCAN_CAPTURE_FILTER=tcp
```

启动服务后，从另一台局域网主机执行端口扫描，例如：

```powershell
nmap 你的服务器局域网IP
```

预期结果：

- 系统从 TCP SYN 包生成连接事件
- 达到阈值后出现 `port_scan` 告警
- 高危扫描可自动加入黑名单
- `/dashboard` 的连接事件统计增加

## 后台访问控制测试

后台入口：

```text
/admin/login
/ops
/dashboard
/alerts
/rules
/config
/blacklist
```

建议测试以下场景：

- 非白名单 IP 访问后台，应被拒绝
- 白名单 IP 访问后台登录页，应能看到登录表单
- 使用正确账号密码登录后，应能进入后台页面
- 退出登录后，再次访问后台应要求重新登录

## 反向代理 IP 信任测试

默认配置：

```env
IDS_TRUST_PROXY=false
```

预期结果：系统忽略 `X-Forwarded-For`，记录真实连接 IP。

开启可信代理：

```env
IDS_TRUST_PROXY=true
IDS_TRUSTED_PROXY_IPS=你的代理IP
```

预期结果：只有来自可信代理 IP 的请求，才会使用 `X-Forwarded-For` 中的客户端 IP。

## 通过标准

一次完整测试建议确认：

- 公开页面可以访问
- 后台页面受 IP 白名单和登录认证保护
- 攻击样例可以生成正确类型的告警
- 告警来源 IP 正确
- 高危行为可以触发黑名单或端口阻断
- 被封禁来源再次访问会被拦截
- `/api/stats` 能返回仪表盘数据
- `python -m unittest tests.test_app` 全部通过
