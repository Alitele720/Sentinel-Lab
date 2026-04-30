# 安全说明

Sentinel Lab 是教学和演示项目。请仅在本地、课程实验、靶场或已明确授权的网络环境中使用。

## 授权使用

允许的使用场景：

- 本地学习和课程设计
- 课堂演示和答辩展示
- 自建靶场或实验虚拟机
- 已获得授权的安全测试环境

禁止的使用场景：

- 未经授权扫描、测试或攻击第三方系统
- 将实验接口暴露给不可信用户
- 将本项目作为生产环境的唯一安全防护

## 敏感文件

不要提交以下内容到 GitHub：

- `.env`
- 真实密钥和真实密码
- `data/` 下的数据库和日志
- `*.db`
- `*.log`
- 本地压缩包或导出的私有数据

可以提交 `.env.example`，但其中只能包含示例值。

## 默认配置风险

公开或半公开环境中，请至少修改：

```env
IDS_SECRET_KEY=replace-with-a-strong-secret
IDS_ADMIN_USERNAME=your-admin-name
IDS_ADMIN_PASSWORD=replace-with-a-strong-password
IDS_ADMIN_AUTH_ENABLED=true
IDS_EXPOSE_LABS=false
```

后台 IP 白名单也应设置为可信管理主机：

```env
IDS_ADMIN_ALLOWED_IPS=127.0.0.1,::1,你的管理主机IP
```

## 反向代理注意事项

只有在明确知道代理链路可信时，才开启：

```env
IDS_TRUST_PROXY=true
```

并且必须配置可信代理 IP：

```env
IDS_TRUSTED_PROXY_IPS=你的代理IP
```

否则攻击者可能通过伪造 `X-Forwarded-For` 影响来源 IP 判断。

## 漏洞反馈

如果你在项目中发现安全问题，请优先在私有渠道联系维护者，不要在公开 Issue 中贴出真实密钥、日志、数据库或可复现攻击细节。
