# DSH A2A Registry

面向 DeepSeek Harness 的自助多租户披露注册站。包含 OIDC 登录、账号与组织创建／切换、成员与设备管理、披露读取／导入／提问、审计及 PostgreSQL 租户隔离。

本仓库可以独立安装、构建和运行，不依赖原来的 Felix 工作目录，也不包含 Harness 的聊天应用、Agent 执行器、模型提供方或终端工具。Harness 作为外部客户端通过 Registry Sync WebSocket 协议连接。

## 启动

需要 Node.js 24 或更新版本，以及 npm。

```sh
git clone https://github.com/FelixWBY/dsh-a2a-registry.git
cd dsh-a2a-registry
npm ci
npm run build
npm start
```

打开 <http://127.0.0.1:3081/>。默认先启动注册站页面与状态接口；没有配置身份服务时，会明确显示未配置，并拒绝受保护业务访问。

```sh
# 修改监听端口
npm start -- --port 3181

# 使用配置文件接入存储、身份与业务提供方
npm start -- --patch /absolute/path/registry.patch.yml

# 独立进程启动、安全响应头与未登录访问检查
npm test
```

`DSH_HOME` 默认是本仓库下的 `.registry/`，运行数据和凭据不会进入 Git。源码由固定版本的 tsx 运行；前端通过 esbuild 和 Vite 构建。`package-lock.json` 锁定安装依赖，内部 workspace 包全部随仓库提供。

## 登录与部署

标准 OIDC Authorization Code + PKCE 已实现。首次登录按 Issuer 与 Subject 建立账号，用户可以自助创建并切换组织；组织访问还必须通过有效成员关系和组织内目录授权。正式环境需提供 Issuer、Client ID、客户端 Secret、会话 Secret 和 HTTPS 公共地址。未配置的服务不会降级为测试身份。

- [独立部署说明](deploy/README.md)
- [中文 PRD 与剩余 P 项](design/a2a-registry/SSOT.md)
- [原始设计输入](design/a2a-registry/sources/dsh-a2a-disclosure-registry-design.source.txt)
- [提取的源包清单](docs/source-packages.json)

本地 Keycloak 示例保留在 `deploy/registry/`，通过 Docker Desktop 启动固定版本容器，并在第一次运行时生成独立的本地测试凭据；本地 SaaS 控制面使用独立 PostgreSQL schema。本仓库不提供真实密码、设备私钥、生产数据库或本地运行快照。

多租户控制面、按组织运行时路由、组织邀请与成员生命周期同步、PostgreSQL 强制 RLS、支付提供方中立的持久化订单核心，以及 SaaS 披露正文的窄提供方接线层已实现。Harness 候选已具备生产连接、发布、导入／刷新、自动无工具提问消费和浏览器发布管理源码。公网生产尚需完成正式身份服务、旧数据迁移、真实设备绑定与联合验收、托管 KMS 与密钥生命周期、Harness 正式打包和受保护完整运行包、浏览器导入／刷新入口、Stripe／支付宝真实适配器、真实域名与部署验收。已提供的配置模板不能替代这些外部服务。

## 结构

| 目录 | 内容 |
| --- | --- |
| `src/dsh.ts` | 只启动 Registry profile 的独立入口 |
| `apps/web` | 浏览器页面壳 |
| `packages/client/ui-registry` | 注册站页面及交互 |
| `packages/bundle/registry-app` | HTTP API、OIDC、WSS、审计与维护 |
| `packages/a2a` | Registry 所需的 A2A 协议与领域实现 |
| `packages/storage` | JSON / SQLite / PostgreSQL 存储；PostgreSQL 支持显式租户键与强制 RLS |
| `vendor` | 固定来源的 Cordis 基础组件 |
| `deploy` | Caddy、systemd、备份恢复、OIDC 示例 |

订单与支付已提供 PostgreSQL 持久化订单与事件表、组织级幂等、防重放状态机、Owner 设置页和默认关闭的支付提供方边界；未配置时相关接口返回 HTTP 501。仓库不包含 Stripe／支付宝真实适配器或商户凭据，正式上线仍须接入服务端价格白名单、托管结账、签名 Webhook，并完成实网支付、退款和争议验收，见 `deploy/payments/README.md`。

## 来源与许可证

本项目从 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 的 `76fda72979` 基线及本地 Registry 开发版本提取，是独立维护的衍生项目，不是 DeepSeek 官方发布的注册站。原始版权和 [MIT 许可证](LICENSE) 保留；第三方组件见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。内部 `@deepseek-ai/*` 名称保留用于协议和模块兼容，包均为 private，不会发布到 npm。
