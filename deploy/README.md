# 独立注册站部署

在本仓库执行 `npm ci && npm run build`，以 `npm start` 启动。无需安装或访问 Felix / Harness 源码。生产前置检查及业务协议验证仍依赖真实配置，不默认生成可公开使用的账户或密钥。

本地 PostgreSQL 使用 Docker Desktop + WSL 2，配置、迁移与启停命令见 [PostgreSQL 部署说明](postgres/README.md)。支付默认关闭；商户适配器的安全边界见 [订单与支付说明](payments/README.md)。

## 本地 OIDC

启动 Docker Desktop，然后在仓库根目录执行：

```powershell
pwsh -File deploy/registry/start-local-keycloak.ps1 -NodePath C:\tools\node\node.exe
```

脚本在 3182 启动固定版本的 Keycloak 开发容器，在 3181 启动本仓库的 Registry，并在 3183 通过 Caddy 的本地内部 CA 提供设备同步 WSS；Registry 使用本地 PostgreSQL 中隔离的 `registry_saas_local` schema。凭据首次随机生成并保存在限制访问且被忽略的 `.artifacts/registry-oidc-local/private-runtime.json`，不会输出密码。脚本返回 WSS 地址和根证书路径；本地 Harness 必须显式信任该证书，例如把返回路径设置为 `NODE_EXTRA_CA_CERTS`。这些服务只绑定回环地址，内部 CA 只用于本机验收，不能替代公网受信任证书。Keycloak 允许本地自助注册；首次登录后可在 Registry 自助创建组织，也可通过 Owner／Admin 生成的一次性链接加入已有组织。

普通服务器或已有身份服务可以直接使用 OIDC patch：

```sh
npm start -- --patch /etc/dsh/registry-production.patch.yml
```

`registry/registry-single-host.example.patch.yml` 是生产基础模板；继续叠加 `registry/registry-postgres.example.patch.yml` 才启用多组织 SaaS 控制面、组织运行时路由和 PostgreSQL RLS。`registry/registry.env.example` 列出所需环境变量。SaaS 的设备认证由已确认的 v5 绑定内建提供；披露操作与 KMS 提供方仍须按实际部署提供，生产模板会在缺失时失败关闭。

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

Harness 仍是单独安装的外部程序。其中 `/opt/deepseek-harness` 是 Harness 自身的安装路径，不是 Registry 的构建依赖。

`registry/enroll-registry-device.mjs` 提供设备自助绑定：`start` 在 Harness 侧生成并保留 Ed25519 私钥和设备 secret，只向 Registry 提交公钥与 secret 摘要；组织成员在返回的审批地址核对临时配对码后，运行 `confirm` 完成挑战签名，再用 `export-env` 导出连接所需的五项环境变量。状态文件和导出文件都包含长期敏感凭据，必须放入受限目录或部署秘密管理，不能提交到 Git。

`registry/harness-registry-connection.example.patch.yml` 是最小连接模板，只启用生产设备鉴权、在线状态和断线重连，不会启用披露发布、导入、提问、KMS 或任何远程工具执行。它可以先用于验证真实绑定和 WSS 链路。`registry/harness-production-publication.example.patch.yml` 才是完整披露链路的配置参考，但仍须由部署者提供生产披露授权、密钥发布／刷新、导入和提问实现。`registry/harness.env.example` 与 `registry/dsh-harness.service.example` 分别提供环境变量和进程托管参考。

设备在发起绑定前自行生成 Ed25519 私钥和独立的 32 字节设备 secret，只把公钥与 secret 摘要提交给 Registry。人工配对码只用于成员审核，不能当设备 token。绑定确认后，Harness 使用由组织 ID、绑定 ID 和原始 secret 组成的 `dsh1` token 发起 WSS 连接，并对每次 Registry 随机挑战签名；Registry 在每个操作前重新检查绑定、成员、scope 和密钥。生产发布、导入和提问还需具备相应设备 scope 与数据密钥；网页 OIDC 账号会话不能替代设备凭据。

## 备份与恢复

`registry/backup-registry-state.mjs`、`registry/backup-sqlite.mjs`、`registry/verify-registry-restore.mjs` 提供三库备份、摘要验证和隔离恢复检查。按各脚本的 `--help` 与生产环境模板使用，恢复到新路径，保留原介质。

告警恢复演练工具 `verify-operational-alert-recovery.mjs` 需用 `node --import tsx/esm` 运行，并将 `REGISTRY_DRILL_TLS_DIR` 设为独立测试证书目录，包含 `ca.pem`、`server.pem`、`server-key.pem`，服务端证书必须包含 IP SAN `127.0.0.1`。本仓库不提交任何私钥；不要使用生产证书进行此演练。

## 上线前需要部署者提供

| 类别 | 必需输入 | 当前缺少时的行为 |
| --- | --- | --- |
| 账号、组织与身份 | 正式 OIDC issuer、client ID、client secret、允许的回调地址，以及能稳定映射到成员 ID 的不可变 claim；旧单组织迁移时还需明确旧组织 ID、初始 Owner 主体和显示名称 | 保持身份未配置；本地 Keycloak 只能用于本机验收；不会自动认领旧组织 |
| Harness | 每台实例的独立设备私钥、独立设备 secret、确认后的 `dsh1` token；仅授予需要的 `disclosure.sync`／`a2a.receive` scope；公网 WSS 地址与设备公钥登记 | 不能连接生产 Registry；不会退化为人工配对码、网页账号或共享测试密钥 |
| 密钥管理 | 选定的生产 KMS／秘密管理服务、披露数据密钥的生成、作用域授权、轮换、恢复和销毁流程 | 不发布生产披露；不从仓库或普通 `.env` 读取披露私钥 |
| 公网部署 | 正式域名、DNS 控制权、ACME 邮箱、HTTPS 告警接收地址、异机备份位置、Linux 服务账号和 PostgreSQL 生产连接信息 | 只允许回环本地运行；不宣称已公网可用 |
| 支付（可选） | 是否首发收费；若收费，选择 Stripe／支付宝并提供商户账号、产品/Price、Webhook 验签资料、退款/税务/发票规则 | 支付 provider 保持关闭，方案和结账接口返回未配置，不产生交易 |

秘密只写入部署平台的 secret store 或受限的主机文件，不要通过聊天发送，也不要提交到 Git。准备好非秘密项后，先填写 `registry.env.example`、`harness.env.example` 和 `edge.env.example` 的副本，再运行对应范围的 `check-production-environment.mjs`。
