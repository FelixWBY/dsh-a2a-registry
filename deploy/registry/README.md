# Registry 部署模板

请按[独立部署说明](../README.md)操作。本目录提供独立 Registry、外部 Harness、OIDC 和多租户 PostgreSQL 所需的配置模板及本地运维工具，不再使用原单体仓库的启动命令。

生产基础配置叠加 `registry-postgres.example.patch.yml` 后启用 SaaS 模式、自助组织创建／切换、按组织延迟加载运行时、PostgreSQL RLS、持久导入队列、加密提问邮箱、单实例 software-local disclosure KMS、固定 checkpoint 正文投影和受认证的 Harness publication bridge。把 `registry-production.example.patch.yml` 安装为 `/etc/dsh/registry-production.patch.yml`，只在该最终 overlay 增加支付等部署专属可选 provider；systemd 示例会对启动所用的同一组三层 patch 运行 `verify-production-graph.mjs`。正文适配器已固定使用条目 `registry-disclosure-content-provider` 和包 `@deepseek-ai/dsh-registry-disclosure-content-app`，只注入 `registryDisclosureKeyProvider`，并显式限制事件数、明密文字节和受信任密钥数；Registry 运行时对应设置 `saas.disclosureContentProvider: true` 并注入 `registryDisclosureContentProvider`。它只能实现该独立服务，不得注册或替换整套 `registryDisclosureOperations`。生产图门禁会拒绝正文 provider 缺失、改包、缺少密钥依赖、隐式／无效边界或运行时未启用。支付适配器的固定条目标识仍是 `registry-billing-provider`，必须同时设置 `saas.billingProvider: true` 并注入 `registryBillingProvider`；支付三项可以同时缺省。生产 credentials provider 仅解析服务启动环境，文件、`.env` 和写入路径全部关闭。所有 `.example` 文件均不包含真实凭据；除只读安装的基础层外，部署副本应放在仓库外。`DSH_REGISTRY_MAILBOX_KEY` 必须是秘密管理器注入的规范 base64url 32 字节根密钥；Registry 按组织派生邮箱密钥，轮换前必须先完成现有密文的迁移演练，不能直接替换后丢失回复解密能力。software-local disclosure KMS 继续把 `DSH_REGISTRY_DISCLOSURE_ROOT_KEY_ID`／`DSH_REGISTRY_DISCLOSURE_ROOT_KEY` 作为 active 单根兼容配置；有界恢复窗口可额外成对注入 `DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY_ID`／`DSH_REGISTRY_DISCLOSURE_PREVIOUS_ROOT_KEY`。已有组织按持久版本选择 active 或 previous，新组织只使用 active，重复版本、缺半个 previous、非环境来源、非规范材料或材料复用都会失败关闭。逐组织验证 API 会认证完整 KEK／DEK 层级并只返回版本、数量和元数据摘要；停服数据库重包裹命令会先验证精确 tenancy/storage RLS，再在排他表锁内临时解除 storage FORCE RLS 做全租户 owner／DEK 对账，恢复并复核 FORCE RLS 后才允许逐组织替换 owner 包裹。它不创建 owner，不输出密钥或密文，任何孤儿租户、旧前缀、额外 owner、无 owner DEK 或策略漂移都会整单回滚。尚未完成的是生产副本上的真实轮换／隔离恢复演练、组织 KEK 多版本、分批 DEK 重包裹、销毁和外部维护审计。该实现明确不是 HSM，也不支持多副本并发写；扩容前必须替换为分布式／硬件托管 provider。

## software-local 根密钥停服重包裹

先验证可恢复备份，停止全部 Registry 实例并禁用 systemd、Windows 服务或其他 supervisor 的自动重启。由秘密管理器向一次性维护进程注入专用 `registry_migrator` 连接 URL、active／previous 两组版本标识和根密钥；维护环境不得包含在线 `DSH_REGISTRY_POSTGRES_URL`。先运行默认 plan，保存只含组织、版本、数量和摘要的输出；确认清单正确后才运行 execute：

```powershell
node --import tsx/esm deploy/registry/rewrap-software-kms-root.mjs --schema registry
node --import tsx/esm deploy/registry/rewrap-software-kms-root.mjs --schema registry `
  --execute --confirm-quiesced --confirm-backup-verified
```

不要把数据库密码或根密钥写进参数、脚本正文、终端历史或输出。命令会使用 serializable 单事务、schema advisory lock 和四表排他锁；精确校验 RLS 与 tenancy policy fingerprint，做不受租户 RLS 过滤的全局 KMS owner／DEK 对账，认证全部已有层次，然后 plan 回滚或 execute 整单提交。任一 Registry 会话、策略漂移、孤儿／旧前缀／额外 owner、无 owner DEK、未知根版本、认证失败或并发变更都会失败并回滚。成功后先仅用 active root 在隔离恢复副本验证，再更新生产服务配置并恢复 supervisor；在这些证据完成前不得移除 previous root 或销毁旧备份。

新 SaaS 设备使用 v6 绑定：Harness 在本机生成 Ed25519 密钥、独立的 WSS 设备 secret 和 disclosure bridge secret，只把公钥与两个域分离摘要提交给 Registry。成员审批并由 Harness 签名确认后，本机分别保存 `dsh1`、`dshb1` 和私钥；连接 WSS 仍须签署 Registry 的一次性随机挑战，HTTPS bridge 则在每次请求重新验证当前绑定、成员和 `disclosure.sync`。旧 v4/v5 记录继续支持原有读取或 WSS 兼容，但不能获得 bridge 权限。人工配对码、网页账号会话和共享测试密钥都不能替代设备凭据。

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

确认成功会在再次复核路径和 ACL 后原子替换状态文件，删除配对码和两个独立 raw secret 字段；WSS 设备 secret 与 disclosure bridge secret 分别封装进 `dsh1`、`dshb1` token。导出的六个设备变量可供只启用鉴权、在线状态与重连的 `harness-registry-connection.example.patch.yml` 使用，也可与独立注入的 `DEEPSEEK_API_KEY` 一起供 `harness-production-publication.example.patch.yml` 调用内建 HTTPS bridge，并启用发布、WSS Session 导入／刷新及固定 `deepseek-official/deepseek-flash` 路由的自动纯文本问题消费。该自动分支在完整上下文持久化后执行，固定禁止工具、命令、ambient context 和非文本输入；通用 Session API 只能读取，不能接管其模型、prompt、队列、取消或 fork。Registry PostgreSQL 层已经装配正文投影 provider。环境文件包含长期敏感凭据，必须只允许 Harness 服务账号读取，不能上传、发送或提交到 Git；需要重做时请先在 Registry 撤销旧设备，再由运维人员明确移走旧文件。

升级前遗留的 V1 待确认状态仍可完成 `confirm`，V1 已确认状态仍可 `export-env`；两者都只保留原有 `dsh1`，导出严格五项变量，仅支持 connection-only WSS。工具不会把旧 secret 复用为 `dshb1`，也不会把 V1 状态静默升级为可发布状态。要启用 HTTPS disclosure publication，必须撤销旧设备并重新绑定。`check-production-environment.mjs harness`／`all` 对应公网完整 publication，固定要求新六项设备配置和独立的 `DEEPSEEK_API_KEY` 模型凭据。它还要求 `DSH_REGISTRY_DISCLOSURE_BRIDGE_URL` 精确指向同一 `REGISTRY_DOMAIN` 的 `/a2a/v1/disclosure-publication` HTTPS 地址，不接受显式端口、凭据、查询或片段。

在连接某个 Harness 源码版本前，先运行无秘密的线协议兼容检查：

```powershell
npm run verify:harness-compatibility -- `
  --harness-root C:\path\to\deepseek-harness `
  --node-path C:\path\to\node.exe `
  --overlay C:\path\to\dsh-a2a-registry\deploy\registry\harness-registry-connection.example.patch.yml `
  --publication-overlay C:\path\to\dsh-a2a-registry\deploy\registry\harness-production-publication.example.patch.yml
```

检查使用显式指定的目标 Node.js 24 或更高版本。Registry 会生成内部一致且真实签名的披露事件与检查点，再把连接、披露注册回执、事件／检查点回执、导入派发／释放和纯文本问题派发、运行、完成、失败及授权释放的代表性 v1 服务端帧交给目标 Harness 的源码与已构建 codec 解码；目标 codec 会反向编码连接、披露注册／事件／检查点、导入完成／重试释放和问题运行／完成／失败等客户端帧，由 Registry 解码。

目标源码和已构建 web-app／session-controller 还会用各自的 app-boot 与 schema 分别解析实际 connection-only overlay 和 publication overlay，并执行 Web 跨字段组合校验。最后已构建 CLI 会为两层 overlay 分别创建临时工作目录与临时 `DSH_HOME` 执行 `--dump-config`：前者必须只合成生产连接，后者必须同时合成生产连接、披露发布、确定会话导入／刷新和固定模型的自动无工具问题消费者，且不得混入测试或 loopback provider；完成后删除临时目录，不写目标 Harness 的真实 profile。

检查器不读取或要求设备 token、设备私钥及 enrollment 文件，子进程环境只包含 Node 运行所需的系统变量和公开占位值；任一源码、构建产物、CLI、schema 或 overlay 缺失／漂移都不得启动真实接入。若开发 checkout 新增依赖后的 pnpm 链接尚未刷新，检查器只会对 Web 包已经声明为 `workspace:`、包名一致且真实 `lib` 入口存在的固定发布依赖使用临时解析回退，正常解析始终优先，临时目录在结束时删除；这不构成 packed-install 验收。它会执行目标 checkout，因此只能指向可信目录，也不应从带生产秘密的交互 shell 运行。固定伪签名和静态状态分支只验证 v1 codec 与配置兼容，不证明 WSS 挑战已由真实设备私钥签署，也不把完成与失败样本解释成同一次真实请求的状态轨迹；该检查仍不代替真实 WSS 认证、Registry Presence、披露密钥分发、模型执行和离线恢复验收。v1 导入帧只携带稳定操作标识，目标 Harness 仍须以 `targetInstanceId + operationId` 确定本地 Session，Registry 会独立核对完成回执中的 Session 标识。

Windows 本地验收不能直接从普通开发 checkout 启动。先把已审查、干净提交的 Harness 按官方发布边界构建并打成 dsh、vendor 和 Landlock tarball，再用 `prepare-bound-harness-runtime.ps1` 在仓库外生成一个受保护、版本化的实体运行包。准备器只接受三组受保护输入：dsh 和 vendor 目录必须由 `publish-order.txt` 精确覆盖，Landlock 目录必须只有 entry 包；所有包必须属于 `@deepseek-ai`，dsh 发布族必须同版本。源包先逐字节复制到受保护 staging 并核对复制前后摘要，npm 只读取该副本；安装后的 lockfile 会固定外部依赖版本与 integrity，实际落盘的依赖树则拒绝混入未由输入 tarball 提供的 DeepSeek 包。省略的跨平台 optional 包仍可出现在 lockfile 中，但不得落盘。准备器固定使用 `--ignore-scripts --omit=optional` 做 hoisted 安装，不复制 pnpm link farm，也不允许第三方生命周期脚本以当前账号执行；外部第三方依赖仍从指定 HTTPS npm registry 获取。默认 `ConnectionOnly` 保持旧行为；显式使用 `-RuntimeMode Production` 时，准备器会在同一无秘密隔离环境中先验证 connection-only，再用公开占位 ID、URL 和临时路径验证完整 publication／import／question overlay。两种模式都不会读取 token、私钥或模型密钥，也不会把凭据写入运行包。准备器会实体复制 CLI 到启动器要求的 `apps/cli/lib/bin.js`，复制 Node.js 24+ 和两层 overlay，执行 `--version` 与所选模式的 `--dump-config` 烟测，递归拒绝 junction／符号链接，并分别关闭运行包、Harness、Node 和启动器信任根的 ACL 继承，再生成包含已验收模式、禁用生命周期脚本、秘密外部注入约束、tarball 来源和逐文件 SHA-256 的构建证据。整个结果先写同盘随机 staging，再通过目标必须不存在的目录重命名发布；失败只清理本次 staging。

正式 tarball 必须来自干净且受保护的工作树，输出目录也必须预先放在只允许构建账号、`SYSTEM` 和管理员写入的固定盘命名空间内。准备器脚本及其同目录路径门禁本身是启动前信任根，必须先由发布流程核对受审查提交或发行摘要并保护该目录；脚本不能在自身已经被替换后完成可信的自证。`build:official` 会把当前提交写进构建产物，但不会替你拒绝未提交源码；因此当前存在脏改动的 checkout 只能做本地候选验证，不能标作生产发布。发布链与官方工作流保持一致：

```powershell
pnpm install --frozen-lockfile
pnpm run release:verify --family dsh
pnpm run build:official
$packRoot = 'C:\trusted-build\dsh-0.1.2-rc.1-packs'
pnpm run release:pack --family dsh --out "$packRoot/npm"
pnpm run release:pack --family vendor --out "$packRoot/npm-vendor"
pnpm --dir native/landlock-run run build:ts
pnpm --dir native/landlock-run/packages/entry pack --pack-destination "$packRoot/npm-landlock"
pnpm run release:verify-packed-install --family dsh `
  --from "$packRoot/npm" --from "$packRoot/npm-vendor" --from "$packRoot/npm-landlock"
```

在一个全新的固定盘父目录中准备版本化运行包。父目录与最终内容只允许当前服务账号、`SYSTEM` 和本机管理员写入；下例先创建父目录，再让准备器原子发布子目录。典型实体运行树连同 Node 24 约占 270–390 MiB，这是本地复制与 npm 安装，不是 Docker 镜像下载；第三方依赖的首次网络下载量另计。

```powershell
$runtimeParent = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.dsh-runtime'
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
$icaclsPath = Join-Path $systemDirectory 'icacls.exe'
New-Item -ItemType Directory -Path $runtimeParent | Out-Null
& $icaclsPath $runtimeParent '/inheritance:r' '/grant:r' `
  "*${currentSid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'
if ($LASTEXITCODE -ne 0) { throw '无法限制运行目录 ACL。' }

$runtimeRoot = Join-Path $runtimeParent 'bound-0.1.2-rc.1-reviewed'
Remove-Item Env:NODE_OPTIONS, Env:NODE_PATH -ErrorAction SilentlyContinue
& 'C:\trusted-build\dsh-a2a-registry\deploy\registry\prepare-bound-harness-runtime.ps1' `
  -TarballDirectory @("$packRoot\npm", "$packRoot\npm-vendor", "$packRoot\npm-landlock") `
  -NodePath 'C:\path\to\node.exe' `
  -DestinationRoot $runtimeRoot `
  -RuntimeMode Production
```

上述 Production 产物必须在真实设备切换前由 `start-bound-harness.ps1 -RuntimeMode Production` 完成本机 Web 启动验收。它证明正式 tarball 的实体依赖闭包、完整 Registry overlay 和受保护文件边界可用，但不声称 Agent／PTY／本机持久化所需的原生 optional 产物可用。若后续功能需要 `node-pty`、`koffi` 等安装产物，必须另做“无秘密构建账号生成并签名 → 最终服务账号只物化和复核”的两阶段交付，再实跑相应功能；当前准备器没有开启生命周期脚本的开关，也不得在已经保存设备密钥的服务账号中执行第三方安装脚本。

Windows 本地验收在 `export-env` 后从该运行包内的 `start-bound-harness.ps1` 启动。不要从 Registry 开发 checkout 运行这个启动器，因为它必须先加载同目录的路径门禁；准备器已把启动器、门禁和两层 overlay 一起放进受保护目录。启动前会复核运行包、Harness、Node 和 launcher 四个信任根的受保护 ACL，单独检查关键执行／配置文件 ACL，递归拒绝重解析点，并逐文件验证 `runtime-files.sha256`、构建证据、Node 精确版本和 CLI 精确版本；`HarnessRoot`／`NodePath` 只能指向当前运行包的固定位置。默认 `ConnectionOnly` 严格接受旧版五项或新版六项设备变量并固定选择连接专用 overlay；`Production` 必须严格包含六项设备变量、`DSH_REGISTRY_DISCLOSURE_BRIDGE_URL`、`DSH_DISCLOSURE_STATE_PATH` 和 `DEEPSEEK_API_KEY`，并且运行包构建证据已经记录完整模式合成通过。Production 的 state 路径、环境文件、CA、真实 `DSH_HOME` 和日志都必须位于运行包外的私有 ACL 目录；启动器只从该文件向子进程注入，不把值写回包或回显。两种模式都会验证 token、组织与 Ed25519 PKCS8 私钥；存在 `dshb1` 时还会验证它与 `dsh1` 属于同一组织和绑定且 secret 相互独立。启动器只绑定 `127.0.0.1`，端口默认是 3080，也可用 `-Port` 选择独立空闲端口；它不会停止或替换占用端口的进程。它拒绝带 `NODE_OPTIONS` 或 `NODE_PATH` 的调用，Node 子进程只继承 Windows 运行所需的白名单环境变量和显式配置；其他环境中的 `DSH_*` 不会传入。TLS 必须通过 `NODE_EXTRA_CA_CERTS` 信任明确指定的 PEM CA，不能设置 `NODE_TLS_REJECT_UNAUTHORIZED=0` 或改用明文 WebSocket。

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

受保护运行包与 `.dsh-private` 必须是两个独立目录；运行包不读取、复制或创建 enrollment、设备密钥、CA、真实 `DSH_HOME` 或日志。Node.js、Harness、启动器、overlay 与 CA 证书都是凭据信任边界。它们的所有者必须是当前服务账号、`SYSTEM` 或本机管理员，且不能向其他账号授予写入、修改、删除或更改 ACL 的权限；HarnessRoot、启动器目录和 CA 父目录还必须关闭 ACL 继承。不支持 UNC、映射盘、可移动介质、卷根或任何穿过 junction／符号链接的路径。对已存在的目录，`/grant:r` 不会自动移除其他账号早已存在的显式 Allow，因此只在未占用的新版本目录发布，并以准备器和启动器的 ACL 检查结果为准。

Production 的 Windows 环境文件是在新绑定导出的六行后追加 `DSH_REGISTRY_DISCLOSURE_BRIDGE_URL`、`DSH_DISCLOSURE_STATE_PATH` 和 `DEEPSEEK_API_KEY`，总计恰好九行；不要加入注释、空值、`DSH_HOME`、`REGISTRY_DOMAIN` 或其他变量。同步与 bridge 地址必须是同一公网主机、无显式端口的固定 `/a2a/v1/sync` WSS 和 `/a2a/v1/disclosure-publication` HTTPS 路径；本机 3183 等开发联调仍从开发 checkout 运行，不走这个 Production 保护启动器。state 目录必须预先创建并像 home／logs 一样关闭 ACL 继承。`DEEPSEEK_API_KEY` 只由主机秘密管理写入这个包外文件，不应出现在 PowerShell 命令历史、构建账号环境、运行包或聊天记录中。

确认线协议检查通过、运行包的 `runtime-files.sha256` 已保存、所选端口空闲后启动。所有路径必须是绝对路径；不要把环境文件内容复制进命令行。下例使用 3180，避免影响已运行在 3080 的 Harness：

```powershell
pwsh -NoProfile -File "$runtimeRoot\launcher\start-bound-harness.ps1" `
  -HarnessRoot "$runtimeRoot\harness" `
  -NodePath "$runtimeRoot\node\node.exe" `
  -EnvFile 'C:\dsh-private\harness-registry.env' `
  -CaCertificate 'C:\dsh-private\registry-ca.pem' `
  -DshHome 'C:\dsh-private\home' `
  -LogDirectory 'C:\dsh-private\logs' `
  -RuntimeMode Production `
  -Port 3180
```

启动器最多等待 30 秒，只有新 PID 真正拥有所选 `127.0.0.1:<端口>` 监听时才报告成功；失败清理也只针对该新 PID。成功输出包含 URL、PID、overlay、DSH_HOME 与 stdout／stderr 路径，但“本地监听就绪”不等于 Registry Presence 已完成 WSS 认证；还必须在注册站节点页确认该实例在线。停止时按该 PID 精确结束 Harness；不要按进程名批量终止，也不要把日志或私有目录提交到 Git。

PostgreSQL 必须在停服后按 `deploy/postgres/split-registry-runtime-role.sql`、独立 `registry_migrator` 的 `migrate-postgres-schemas.mjs`、同一权限脚本的顺序执行完整 `split → migrate → split`。在线 Registry 只注入 `registry_app` URL，并以 `schemaMode: validate` 做只读启动校验；迁移 URL 不得进入服务环境。

生产探针分为两层：`/healthz` 只报告进程存活；SaaS `/readyz` 会同时通过实际 storage pool 与 tenancy pool 读取权威 schema 版本标记，并拒绝任何非 PostgreSQL 的 domain 路由。数据库失联、任一标记缺失或应用尚未加载完成时 readiness 返回 503，恢复后无需重启即可回到 200。读取使用单飞、2 秒 HTTP 有界等待、1.5 秒查询超时和 1 秒结果缓存；新建连接仍受连接池 10 秒硬上限约束，避免网络半开时永久占住探针。不要把 `/healthz` 改成 Caddy 的流量就绪门禁。公网验证还会以不跟随跳转的方式直连 HTTP 80，只接受同域、同路径与查询、无凭据的 HTTPS 443 永久跳转；端口 80 不得代理 Registry 业务响应。

本地开发先启动仓库提供的 PostgreSQL 容器。首次初始化或结构升级时，先停止 3081／3181 两个 Registry，再显式运行 `start-local-keycloak.ps1 -UpgradeDatabase`；它执行一次 `split → migrate → split` 后启动站点。日常运行只执行 `start-local-keycloak.ps1`，不会改数据库结构，只由在线进程做只读校验。脚本启动固定版本 Keycloak、打开用户自助注册，并用固定版本 Caddy 同时提供 `wss://localhost:3183/a2a/v1/sync` 和 `https://localhost:3183/a2a/v1/disclosure-publication`；本地 software-local KMS 根密钥只保存在受限的 `.artifacts` 私有配置中并以环境凭据注入。内部 CA 根证书路径会随启动结果返回。Harness 连接这两个本地地址时须把返回路径设为该进程的 `NODE_EXTRA_CA_CERTS`，不能关闭 TLS 校验。生成的凭据和 CA 数据只写入 Git 忽略且限制当前用户访问的 `.artifacts`。`-RegistryOnly` 不启动或停止现有 Keycloak／Caddy，只复用已经就绪的本地容器。本地 Keycloak、software-local 根密钥与内部 CA 均不得用于生产。

已有单组织 PostgreSQL storage v1 上线前必须停写、备份并迁移。使用默认只读计划、显式 schema 和预期计数的 [v1 到 v2 迁移工具](migrate-postgres-storage-v1-to-v2.md)；不要把硬编码 `registry` 的旧 SQL 用到其他 schema。
