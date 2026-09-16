# 独立注册站部署

在本仓库执行 `npm ci && npm run build`，以 `npm start` 启动。无需安装或访问 Felix / Harness 源码。生产前置检查及业务协议验证仍依赖真实配置，不默认生成可公开使用的账户或密钥。

## 本地 OIDC

Windows 安装 Java 21 与 Keycloak，设置 `JAVA_HOME`，然后执行：

```powershell
pwsh -File deploy/registry/start-local-keycloak.ps1 -KeycloakPath C:\tools\keycloak -NodePath C:\tools\node\node.exe
```

脚本在 3182 启动 Keycloak，在 3181 启动本仓库的 Registry；凭据首次随机生成并保存在忽略的 `.artifacts/registry-oidc-local/private-runtime.json`。仅绑定回环地址。Keycloak realm 中的 `registry-owner` 必须与 Registry 目录成员匹配。

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
