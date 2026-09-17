# Registry 部署模板

请按[独立部署说明](../README.md)操作。本目录提供独立 Registry、外部 Harness、OIDC 和多租户 PostgreSQL 所需的配置模板及本地运维工具，不再使用原单体仓库的启动命令。

生产基础配置叠加 `registry-postgres.example.patch.yml` 后启用 SaaS 模式、自助组织创建／切换、按组织延迟加载运行时、PostgreSQL RLS、持久导入队列和加密提问邮箱。把 `registry-production.example.patch.yml` 安装为 `/etc/dsh/registry-production.patch.yml`，只在该最终 overlay 增加部署专属 provider；systemd 示例会对启动所用的同一组三层 patch 运行 `verify-production-graph.mjs`。真实 KMS 适配器只能实现独立 `registryDisclosureContentProvider`，不得注册或替换整套 `registryDisclosureOperations`；其条目标识必须是 `registry-disclosure-content-provider`，同时完整保留 Registry 运行时配置并设置 `saas.disclosureContentProvider: true`，再把服务名加入该运行时的 `inject`。生产图门禁要求这三项同时存在或同时缺省，使 Loader 建立启动与卸载依赖。生产 credentials provider 仅解析服务启动环境，文件、`.env` 和写入路径全部关闭。所有 `.example` 文件均不包含真实凭据；除只读安装的基础层外，部署副本应放在仓库外。`DSH_REGISTRY_MAILBOX_KEY` 必须是秘密管理器注入的规范 base64url 32 字节根密钥；Registry 按组织派生邮箱密钥，轮换前必须先完成现有密文的迁移演练，不能直接替换后丢失回复解密能力。

SaaS 设备同步使用 v5 绑定内建认证：Harness 在本机生成 Ed25519 密钥和独立的 32 字节设备 secret，只把公钥与 secret 摘要提交给 Registry。成员审批并由 Harness 签名确认后，本机保存 `dsh1` 设备 token 和私钥；连接 WSS 时仍须签署 Registry 的一次性随机挑战。人工配对码、网页账号会话和共享测试密钥都不能替代设备凭据。

## 正式 OIDC 验收

选定正式身份服务并创建机密客户端后，先由部署平台把 client secret 注入一个专用进程环境变量，再运行在线符合性检查。命令行只接收环境变量名，不能接收 secret 值；检查器不会显示 client ID、secret、端点响应正文或随机探测 token：

```powershell
npm run verify:production-oidc -- `
  --issuer https://identity.example.com/realms/registry `
  --client-id dsh-a2a-registry `
  --client-secret-env DSH_REGISTRY_OIDC_CLIENT_SECRET
```

检查器要求发现文档中的 `issuer` 与命令行逐字匹配，Authorization、Token、Introspection 和 JWKS URL 均为无用户信息、无片段的 HTTPS 地址；受信任身份服务可以把这些端点部署在不同 HTTPS origin。发现文档必须支持 Authorization Code、PKCE `S256`，并在声明 grant 或 scope 列表时分别包含 `authorization_code` 和 `openid`。随后检查器只生成一个新的随机不存在 token，使用与当前 Registry 运行时一致的 `client_secret_post` 调用 Introspection；只接受 HTTP 200、`application/json` 和精确的 `{"active":false}`，重定向、超时、超限正文、额外状态字段及任何协议错误都失败关闭。

该过程不打开登录页、不执行用户登录，也不会申请、读取或保存真实 token。`--allow-loopback-http` 只供仓库内回环 mock 和本机身份服务验收，正式验收禁止使用。通过只证明发现文档、PKCE、客户端认证和不存在 token 的失败关闭契约可用；部署者仍须另外完成真实注册／登录／退出，以及管理员停用真实测试账号后“下一次请求立即失效”的演练，才能关闭 P-ID。

## 设备自助绑定

在 Harness 主机使用 Node.js 24 运行绑定工具。状态和输出必须使用绝对路径，所在目录须提前建立；工具不会覆盖已有文件。`start` 默认申请披露同步与 A2A 接收两项权限，并用 `wx` 独占方式创建状态文件；POSIX 主机会固定为 0600。Windows 不支持用 Node mode 位设置 NTFS DACL，必须在运行前把父目录的 ACL 限制为当前 Harness 服务账号（以及必要的 `SYSTEM`／管理员恢复账号），不能依赖 `chmod`。绑定工具和 Harness 启动器共用同一套 Windows 路径门禁：只接受本地固定盘、非卷根、逐级不含 junction／符号链接等重解析点的路径；凭据父目录必须关闭继承，父目录和文件不能含 Deny 条目，所有者和全部 Allow 条目只能是当前账号、`SYSTEM` 或本机管理员，并且当前账号必须拥有修改权限。门禁还会沿整条祖先目录链拒绝可由其他账号删除、换名或改写 ACL 的命名空间，防止检查后替换父目录。任何一项不满足时，`start` 会在创建状态文件和访问 Registry 前失败，`confirm` 会在读取状态或发出确认请求前失败，`export-env` 会在读取状态和创建环境文件前失败：

```powershell
$privateDir = 'C:\dsh-private'
New-Item -ItemType Directory -Path $privateDir -Force | Out-Null
$harnessPrincipal = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
& icacls.exe $privateDir '/inheritance:r' '/grant:r' "${harnessPrincipal}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw '无法设置 Harness 私有目录 ACL' }
```

上述命令应由实际运行 Harness 的 Windows 账号执行；若由管理员代建目录，请把 `$harnessPrincipal` 明确改为该服务账号。`/grant:r` 不会清除其他账号已有的显式 Allow，路径门禁仍会逐条复核并拒绝；不要把状态、token、私钥或环境文件内容放进命令行或诊断输出。确认 ACL 设置成功后再运行：

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

确认成功会在再次复核路径和 ACL 后原子替换状态文件，删除配对码和独立 raw secret 字段；同一个设备 secret 已封装进 `dsh1` token，因此 token 与 Ed25519 PKCS8 私钥仍是长期敏感凭据。导出的五个变量可供只启用鉴权、在线状态与重连的 `harness-registry-connection.example.patch.yml` 使用，也可供启用完整披露链路的 `harness-production-publication.example.patch.yml` 使用；后者还必须配置 KMS 与披露权威实现。两个文件都含设备凭据，必须只允许 Harness 服务账号读取，不能上传、发送或提交到 Git；需要重做时请先在 Registry 撤销旧设备，再由运维人员明确移走旧文件。

在连接某个 Harness 源码版本前，先运行无秘密的线协议兼容检查：

```powershell
npm run verify:harness-compatibility -- `
  --harness-root C:\path\to\deepseek-harness `
  --node-path C:\path\to\node.exe `
  --overlay C:\path\to\dsh-a2a-registry\deploy\registry\harness-registry-connection.example.patch.yml `
  --publication-overlay C:\path\to\dsh-a2a-registry\deploy\registry\harness-production-publication.example.patch.yml
```

检查使用显式指定的目标 Node.js 24 或更高版本。Registry 会生成内部一致且真实签名的披露事件与检查点，再把连接、披露注册回执、事件／检查点回执、导入派发／释放和纯文本问题派发、运行、完成、失败及授权释放的代表性 v1 服务端帧交给目标 Harness 的源码与已构建 codec 解码；目标 codec 会反向编码连接、披露注册／事件／检查点、导入完成／重试释放和问题运行／完成／失败等客户端帧，由 Registry 解码。

目标源码和已构建 web-app／session-controller 还会用各自的 app-boot 与 schema 分别解析实际 connection-only overlay 和完整 publication overlay。最后已构建 CLI 会为两层 overlay 分别创建临时工作目录与临时 `DSH_HOME` 执行 `--dump-config`：前者必须只合成生产连接，后者必须同时合成生产连接、披露发布、确定会话导入和手动纯文本问题消费，且不得混入测试或 loopback provider；完成后删除临时目录，不写目标 Harness 的真实 profile。

检查器不读取或要求设备 token、设备私钥及 enrollment 文件，子进程环境只包含 Node 运行所需的系统变量和公开占位值；任一源码、构建产物、CLI、schema 或 overlay 缺失／漂移都不得启动真实接入。它会执行目标 checkout，因此只能指向可信目录，也不应从带生产秘密的交互 shell 运行。固定伪签名和静态状态分支只验证 v1 codec 与配置兼容，不证明 WSS 挑战已由真实设备私钥签署，也不把完成与失败样本解释成同一次真实请求的状态轨迹；该检查仍不代替真实 WSS 认证、Registry Presence、披露密钥分发、模型执行和离线恢复验收。v1 导入帧只携带稳定操作标识，目标 Harness 仍须以 `targetInstanceId + operationId` 确定本地 Session，Registry 会独立核对完成回执中的 Session 标识。

Windows 本地验收可在 `export-env` 后用 `start-bound-harness.ps1` 从独立的 Harness 源码 checkout 启动上述连接专用 overlay。启动器显式绑定 `127.0.0.1:3080`，不会停止或替换占用该端口的进程，也不会修改 Harness 源码；CLI 从源码的已构建 `apps/cli/lib/bin.js` 读取，工作目录、DSH_HOME 和日志均在外部私有目录。它只接受绑定工具导出的五个变量且每项恰好一次，校验 token 所属组织和 Ed25519 PKCS8 私钥，不会显示变量值。启动器拒绝带 `NODE_OPTIONS` 的调用，Node 子进程只继承 Windows 运行所需的白名单环境变量和显式设备配置；`NODE_PATH` 与其他环境中的 `DSH_*` 不会传入。TLS 必须通过 `NODE_EXTRA_CA_CERTS` 信任明确指定的 PEM CA，不能设置 `NODE_TLS_REJECT_UNAUTHORIZED=0` 或改用明文 WebSocket。

先在真实 Harness 服务账号下创建三个私有目录，并在写入 enrollment 状态／环境文件前关闭继承。启动器会再次检查目录与环境文件的实际 ACL：Allow 条目只可属于当前账号、`SYSTEM` 或本机管理员，私有目录本身必须已关闭继承。日志可能包含一次性 Web 启动 URL，也按凭据处理。以下示例只授权当前账号与 `SYSTEM`；如确需管理员恢复权限，可另外授予 `*S-1-5-32-544`：

```powershell
$privateRoot = 'C:\dsh-private'
$dshHome = Join-Path $privateRoot 'home'
$logDir = Join-Path $privateRoot 'logs'
$currentPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent().Name
foreach ($directory in @($privateRoot, $dshHome, $logDir)) {
  New-Item -ItemType Directory -Path $directory -Force | Out-Null
  & icacls.exe $directory '/inheritance:r' '/grant:r' "${currentPrincipal}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F'
  if ($LASTEXITCODE -ne 0) { throw "无法限制目录 ACL：$directory" }
}
```

Harness checkout、Node.js 可执行文件、启动器、overlay 与 CA 证书同样是凭据信任边界。它们的所有者必须是当前服务账号、`SYSTEM` 或本机管理员，且不能向其他账号授予写入、修改、删除或更改 ACL 的权限；HarnessRoot、启动器目录和 CA 父目录还必须关闭 ACL 继承。普通 `D:\Felix` 或 Registry 开发 checkout 若继承了 `Authenticated Users: Modify`，就不能承载真实设备凭据；应先在本地固定磁盘的全新私有根目录中安装可信副本，再关闭这些根目录的继承。不支持 UNC、映射盘、可移动介质、卷根或任何穿过 junction／符号链接的路径。对已存在的目录，`/grant:r` 不会自动移除其他账号早已存在的显式 Allow，因此优先使用未占用的新路径，并以启动器的 ACL 检查结果为准。

确认 `apps/cli/lib/bin.js` 已由对应 Harness checkout 构建、线协议检查通过、3080 空闲后启动。所有路径必须是绝对路径；不要把环境文件内容复制进命令行：

```powershell
pwsh -NoProfile -File 'C:\dsh-runtime\dsh-a2a-registry\deploy\registry\start-bound-harness.ps1' `
  -HarnessRoot 'C:\dsh-runtime\deepseek-harness' `
  -NodePath 'C:\path\to\node.exe' `
  -EnvFile 'C:\dsh-private\harness-registry.env' `
  -CaCertificate 'C:\dsh-private\registry-ca.pem' `
  -DshHome 'C:\dsh-private\home' `
  -LogDirectory 'C:\dsh-private\logs'
```

启动器最多等待 30 秒，只有新 PID 真正拥有 `127.0.0.1:3080` 监听时才报告成功；失败清理也只针对该新 PID。成功输出包含 PID、overlay、DSH_HOME 与 stdout／stderr 路径，但“本地监听就绪”不等于 Registry Presence 已完成 WSS 认证；还必须在注册站节点页确认该实例在线。停止时按该 PID 精确结束 Harness；不要按进程名批量终止，也不要把日志或私有目录提交到 Git。

PostgreSQL 必须在停服后按 `deploy/postgres/split-registry-runtime-role.sql`、独立 `registry_migrator` 的 `migrate-postgres-schemas.mjs`、同一权限脚本的顺序执行完整 `split → migrate → split`。在线 Registry 只注入 `registry_app` URL，并以 `schemaMode: validate` 做只读启动校验；迁移 URL 不得进入服务环境。

生产探针分为两层：`/healthz` 只报告进程存活；SaaS `/readyz` 会同时通过实际 storage pool 与 tenancy pool 读取权威 schema 版本标记，并拒绝任何非 PostgreSQL 的 domain 路由。数据库失联、任一标记缺失或应用尚未加载完成时 readiness 返回 503，恢复后无需重启即可回到 200。读取使用单飞、2 秒 HTTP 有界等待、1.5 秒查询超时和 1 秒结果缓存；新建连接仍受连接池 10 秒硬上限约束，避免网络半开时永久占住探针。不要把 `/healthz` 改成 Caddy 的流量就绪门禁。公网验证还会以不跟随跳转的方式直连 HTTP 80，只接受同域、同路径与查询、无凭据的 HTTPS 443 永久跳转；端口 80 不得代理 Registry 业务响应。

本地开发先启动仓库提供的 PostgreSQL 容器。首次初始化或结构升级时，先停止 3081／3181 两个 Registry，再显式运行 `start-local-keycloak.ps1 -UpgradeDatabase`；它执行一次 `split → migrate → split` 后启动站点。日常运行只执行 `start-local-keycloak.ps1`，不会改数据库结构，只由在线进程做只读校验。脚本启动固定版本 Keycloak、打开用户自助注册，并用固定版本 Caddy 在 `wss://localhost:3183/a2a/v1/sync` 提供本地 TLS 设备同步入口；内部 CA 根证书路径会随启动结果返回。Harness 连接此本地地址时须把返回路径设为该进程的 `NODE_EXTRA_CA_CERTS`，不能关闭 TLS 校验。生成的凭据和 CA 数据只写入 Git 忽略且限制当前用户访问的 `.artifacts`。`-RegistryOnly` 不启动或停止现有 Keycloak／Caddy，只复用已经就绪的本地容器。本地 Keycloak 与内部 CA 均不得用于生产。

已有单组织 PostgreSQL storage v1 上线前必须停写、备份并迁移。使用默认只读计划、显式 schema 和预期计数的 [v1 到 v2 迁移工具](migrate-postgres-storage-v1-to-v2.md)；不要把硬编码 `registry` 的旧 SQL 用到其他 schema。
