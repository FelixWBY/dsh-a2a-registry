# 独立注册站部署

在本仓库执行 `npm ci && npm run build`，以 `npm start` 启动。无需安装或访问 Felix / Harness 源码。生产前置检查及业务协议验证仍依赖真实配置，不默认生成可公开使用的账户或密钥。

本地 PostgreSQL 使用 Docker Desktop + WSL 2，配置、迁移与启停命令见 [PostgreSQL 部署说明](postgres/README.md)。支付默认关闭；商户适配器的安全边界见 [订单与支付说明](payments/README.md)。

## 本地 OIDC

启动 Docker Desktop，然后在仓库根目录执行：

```powershell
pwsh -File deploy/registry/start-local-keycloak.ps1 -NodePath C:\tools\node\node.exe
```

脚本在 3182 启动固定版本的 Keycloak 开发容器，在 3181 启动本仓库的 Registry；凭据首次随机生成并保存在限制访问且被忽略的 `.artifacts/registry-oidc-local/private-runtime.json`，不会输出密码。两项服务都只绑定回环地址。Keycloak realm 中的 `registry-owner` 必须与 Registry 目录成员匹配。

普通服务器或已有身份服务可以直接使用 OIDC patch：

```sh
npm start -- --patch /etc/dsh/registry-production.patch.yml
```

`registry/registry-single-host.example.patch.yml` 是生产组合模板，`registry/registry.env.example` 列出所需环境变量。模板中依赖的组织设备认证、披露操作与 KMS provider 需要按实际部署提供。缺少它们时启动会明确失败。

## 公网入口

把代码安装到 `/opt/dsh-a2a-registry`，Registry 只监听回环 3081；使用 `registry/Caddyfile.example` 在正式域名提供 HTTPS/WSS。`registry/dsh-registry.service.example` 已指向独立启动器。确保服务用户可以写入自己的 DSH_HOME 与三套数据库目录，不能读取 Harness 设备私钥。

不要将本地 Keycloak 的 `start-dev`、测试身份或回环 HTTP 配置直接作为公网生产配置。

```sh
node deploy/registry/check-production-environment.mjs registry
node --import tsx/esm deploy/registry/verify-public-registry.mjs
node --import tsx/esm deploy/registry/verify-registry-device.mjs
```

验证脚本从模板规定的环境变量读取配置。设备验证应在掌握设备凭据的 Harness 一侧执行，不能把设备私钥放入公网 Registry 服务环境。

## Harness 接入

Harness 仍是单独安装的外部程序。`registry/harness-production-publication.example.patch.yml`、`registry/harness.env.example` 与 `registry/dsh-harness.service.example` 属于外部 Harness 的配置参考；其中 `/opt/deepseek-harness` 是 Harness 自身的安装路径，不是 Registry 的构建依赖。

生产发布、导入和提问需具备真实设备 scope 与数据密钥；网页 OIDC 账号会话不能替代设备凭据。

## 备份与恢复

`registry/backup-registry-state.mjs`、`registry/backup-sqlite.mjs`、`registry/verify-registry-restore.mjs` 提供三库备份、摘要验证和隔离恢复检查。按各脚本的 `--help` 与生产环境模板使用，恢复到新路径，保留原介质。

告警恢复演练工具 `verify-operational-alert-recovery.mjs` 需用 `node --import tsx/esm` 运行，并将 `REGISTRY_DRILL_TLS_DIR` 设为独立测试证书目录，包含 `ca.pem`、`server.pem`、`server-key.pem`，服务端证书必须包含 IP SAN `127.0.0.1`。本仓库不提交任何私钥；不要使用生产证书进行此演练。

## 上线前需要部署者提供

| 类别 | 必需输入 | 当前缺少时的行为 |
| --- | --- | --- |
| 组织与身份 | 正式组织 ID、初始 Owner 成员 ID/名称；正式 OIDC issuer、client ID、client secret、允许的回调地址，以及能稳定映射到成员 ID 的 claim | 保持身份未配置；本地 Keycloak 只能用于本机验收 |
| Harness | 每台实例的稳定 instance ID、独立设备私钥与短期 token；仅授予需要的 `disclosure.sync`／`a2a.receive` scope；公网 WSS 地址与设备公钥登记 | 不能连接生产 Registry；不会退化为网页账号或共享测试密钥 |
| 密钥管理 | 选定的生产 KMS／秘密管理服务、披露数据密钥的生成、作用域授权、轮换、恢复和销毁流程 | 不发布生产披露；不从仓库或普通 `.env` 读取披露私钥 |
| 公网部署 | 正式域名、DNS 控制权、ACME 邮箱、HTTPS 告警接收地址、异机备份位置、Linux 服务账号和 PostgreSQL 生产连接信息 | 只允许回环本地运行；不宣称已公网可用 |
| 支付（可选） | 是否首发收费；若收费，选择 Stripe／支付宝并提供商户账号、产品/Price、Webhook 验签资料、退款/税务/发票规则 | 支付 provider 保持关闭，方案和结账接口返回未配置，不产生交易 |

秘密只写入部署平台的 secret store 或受限的主机文件，不要通过聊天发送，也不要提交到 Git。准备好非秘密项后，先填写 `registry.env.example`、`harness.env.example` 和 `edge.env.example` 的副本，再运行对应范围的 `check-production-environment.mjs`。
