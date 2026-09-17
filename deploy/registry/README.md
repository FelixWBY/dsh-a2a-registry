# Registry 部署模板

请按[独立部署说明](../README.md)操作。本目录提供独立 Registry、外部 Harness、OIDC 和多租户 PostgreSQL 所需的配置模板及本地运维工具，不再使用原单体仓库的启动命令。

生产基础配置叠加 `registry-postgres.example.patch.yml` 后启用 SaaS 模式、自助组织创建／切换、按组织延迟加载运行时、PostgreSQL RLS、持久导入队列和加密提问邮箱。所有 `.example` 文件均需替换为自己的环境配置，不包含真实凭据。`DSH_REGISTRY_MAILBOX_KEY` 必须是秘密管理器注入的规范 base64url 32 字节根密钥；Registry 按组织派生邮箱密钥，轮换前必须先完成现有密文的迁移演练，不能直接替换后丢失回复解密能力。

SaaS 设备同步使用 v5 绑定内建认证：Harness 在本机生成 Ed25519 密钥和独立的 32 字节设备 secret，只把公钥与 secret 摘要提交给 Registry。成员审批并由 Harness 签名确认后，本机保存 `dsh1` 设备 token 和私钥；连接 WSS 时仍须签署 Registry 的一次性随机挑战。人工配对码、网页账号会话和共享测试密钥都不能替代设备凭据。

## 设备自助绑定

在 Harness 主机使用 Node.js 24 运行绑定工具。状态和输出必须使用绝对路径，所在目录须提前建立；工具不会覆盖已有文件。`start` 默认申请披露同步与 A2A 接收两项权限，并用 `wx` 独占方式创建状态文件；POSIX 主机会固定为 0600。Windows 不支持用 Node mode 位设置 NTFS DACL，必须在运行前把父目录的 ACL 限制为当前 Harness 服务账号（以及必要的 `SYSTEM`／管理员恢复账号），不能依赖 `chmod`：

```powershell
$privateDir = 'C:\dsh-private'
New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
$harnessPrincipal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $privateDir '/inheritance:r' '/grant:r' "${harnessPrincipal}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw '无法设置 Harness 私有目录 ACL' }
```

上述命令应由实际运行 Harness 的 Windows 账号执行；若由管理员代建目录，请把 `$harnessPrincipal` 明确改为该服务账号。确认 ACL 设置成功后再运行：

```powershell
node deploy/registry/enroll-registry-device.mjs start `
  --registry-origin https://registry.example.com/ `
  --organization-id my-organization `
  --instance-name "我的 DeepSeek Harness" `
  --state C:\dsh-private\registry-device.json
```

`start` 成功后会直接显示 `approvalUrl`、`bindingId`、一次性 `pairingCode` 和 `expiresAt`，不会显示长期 device secret、token 或私钥。打开 `approvalUrl`，登录 Registry 后输入输出中的绑定标识和一次性设备码，在对应组织审批该设备；不要为了取码而打开包含私钥和 raw secret 的状态 JSON。审批完成后由设备签名确认，再独占生成 Harness 环境文件：

```powershell
node deploy/registry/enroll-registry-device.mjs confirm `
  --state C:\dsh-private\registry-device.json

node deploy/registry/enroll-registry-device.mjs export-env `
  --state C:\dsh-private\registry-device.json `
  --output C:\dsh-private\harness-registry.env
```

确认成功会原子替换状态文件，删除配对码和独立 raw secret 字段；同一个设备 secret 已封装进 `dsh1` token，因此 token 与 Ed25519 PKCS8 私钥仍是长期敏感凭据。导出的五个变量可供只启用鉴权、在线状态与重连的 `harness-registry-connection.example.patch.yml` 使用，也可供启用完整披露链路的 `harness-production-publication.example.patch.yml` 使用；后者还必须配置 KMS 与披露权威实现。两个文件都含设备凭据，必须只允许 Harness 服务账号读取，不能上传、发送或提交到 Git；需要重做时请先在 Registry 撤销旧设备，再由运维人员明确移走旧文件。

在连接某个 Harness 源码版本前，先运行无秘密的线协议兼容检查：

```powershell
npm run verify:harness-compatibility -- --harness-root C:\path\to\deepseek-harness
```

检查会由当前 Registry 编码一个带签名事件和固定检查点的 v1 导入帧，再调用目标 Harness 的严格解码器读取；失败时不得启动真实接入。v1 帧只携带稳定操作标识，目标 Harness 以 `targetInstanceId + operationId` 确定本地 Session，Registry 会独立计算并核对完成回执中的 Session 标识。检查器不读取设备凭据，并把子进程环境缩减为运行 Node 所需的系统变量，但它会执行目标源码，因此只能指向可信 checkout，且不应从带生产秘密的交互 shell 运行。该检查不代替 WSS 握手、披露密钥分发、模型执行和离线恢复验收。

PostgreSQL 必须在停服后按 `deploy/postgres/split-registry-runtime-role.sql`、独立 `registry_migrator` 的 `migrate-postgres-schemas.mjs`、同一权限脚本的顺序执行完整 `split → migrate → split`。在线 Registry 只注入 `registry_app` URL，并以 `schemaMode: validate` 做只读启动校验；迁移 URL 不得进入服务环境。

本地开发先启动仓库提供的 PostgreSQL 容器。首次初始化或结构升级时，先停止 3081／3181 两个 Registry，再显式运行 `start-local-keycloak.ps1 -UpgradeDatabase`；它执行一次 `split → migrate → split` 后启动站点。日常运行只执行 `start-local-keycloak.ps1`，不会改数据库结构，只由在线进程做只读校验。脚本启动固定版本 Keycloak、打开用户自助注册，并用固定版本 Caddy 在 `wss://localhost:3183/a2a/v1/sync` 提供本地 TLS 设备同步入口；内部 CA 根证书路径会随启动结果返回。Harness 连接此本地地址时须把返回路径设为该进程的 `NODE_EXTRA_CA_CERTS`，不能关闭 TLS 校验。生成的凭据和 CA 数据只写入 Git 忽略且限制当前用户访问的 `.artifacts`。`-RegistryOnly` 不启动或停止现有 Keycloak／Caddy，只复用已经就绪的本地容器。本地 Keycloak 与内部 CA 均不得用于生产。

已有单组织 PostgreSQL storage v1 上线前必须停写、备份并迁移。使用默认只读计划、显式 schema 和预期计数的 [v1 到 v2 迁移工具](migrate-postgres-storage-v1-to-v2.md)；不要把硬编码 `registry` 的旧 SQL 用到其他 schema。
