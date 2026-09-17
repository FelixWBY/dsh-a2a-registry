# 独立注册站部署

在本仓库执行 `npm ci && npm run build`，以 `npm start` 启动。无需安装或访问 Felix / Harness 源码。生产前置检查及业务协议验证仍依赖真实配置，不默认生成可公开使用的账户或密钥。

本地 PostgreSQL 使用 Docker Desktop + WSL 2，配置、迁移与启停命令见 [PostgreSQL 部署说明](postgres/README.md)。支付默认关闭；商户适配器的安全边界见 [订单与支付说明](payments/README.md)。

## 本地 OIDC

启动 Docker Desktop，然后在仓库根目录执行：

```powershell
pwsh -File deploy/registry/start-local-keycloak.ps1 -NodePath C:\tools\node\node.exe
```

脚本在 3182 启动固定版本的 Keycloak 开发容器，在 3181 启动本仓库的 Registry，并在 3183 通过 Caddy 的本地内部 CA 提供设备同步 WSS；Registry 使用本地 PostgreSQL 中隔离的 `registry_saas_local` schema。凭据首次随机生成并保存在限制访问且被忽略的 `.artifacts/registry-oidc-local/private-runtime.json`，不会输出密码。脚本返回 WSS 地址和根证书路径；本地 Harness 必须显式信任该证书，例如把返回路径设置为 `NODE_EXTRA_CA_CERTS`。这些服务只绑定回环地址，内部 CA 只用于本机验收，不能替代公网受信任证书。Keycloak 允许本地自助注册；首次登录后可在 Registry 自助创建组织，也可通过 Owner／Admin 生成的一次性链接加入已有组织。

浏览器登录必须使用支持 Token Introspection 的 OIDC 服务。Registry Cookie 只保存经过 HMAC 的随机会话 ID 和期限，Access Token 仅保留在当前 Registry 进程的有界内存中；每个新的受保护 HTTP 请求都会向身份服务重新确认 `active`、`sub`，并在响应提供时核对 `exp`、`client_id` 和 `iss`。停用用户或不一致响应会立即删除本地会话，身份服务超时或协议失败会拒绝受保护请求。`maxActiveSessions` 是单进程硬上限，满额时新会话失败关闭；`maxSessionsPerSubject` 限制同一 OIDC 主体的并发会话，超额时按签发时间和会话 ID 确定性淘汰最旧会话。当前只支持单副本，Registry 重启会使全部浏览器会话失效并要求重新登录。正式身份服务必须实测用户停用后下一次 introspection 返回非活动状态，不能只凭发现文档存在该端点就宣称验收完成。

正式身份服务接线前先运行无真实用户、无真实 token 的在线符合性检查。client secret 只能由部署秘密管理注入指定环境变量，命令行只传该变量名：

```sh
npm run verify:production-oidc -- \
  --issuer https://identity.example.com/realms/registry \
  --client-id dsh-a2a-registry \
  --client-secret-env DSH_REGISTRY_OIDC_CLIENT_SECRET
```

该检查严格核对发现文档 issuer、必需 HTTPS 端点、Authorization Code、PKCE S256 和可选 grant／scope 声明，再用随机不存在 token 验证 Introspection 只返回精确的非活动对象；不会跟随重定向，也不会把 secret、响应正文或随机 token 写入输出。身份服务可以把受信任端点部署在不同 HTTPS origin。`--allow-loopback-http` 只允许本机回环测试，不能出现在生产验收。工具通过仍不等于真实身份闭环完成；正式注册、登录、退出和管理员停用后下一请求失效必须另行实测。

普通服务器或已有身份服务使用仓库内已经过配置图门禁的基础层和 PostgreSQL 层，再叠加部署者自己的最终 overlay。先把空的 `registry-production.example.patch.yml` 复制到 `/etc/dsh/registry-production.patch.yml`；以后只在这份部署文件中增加经过审查的 KMS、支付或其他生产 provider：

```sh
npm start -- \
  --patch deploy/registry/registry-single-host.example.patch.yml \
  --patch deploy/registry/registry-postgres.example.patch.yml \
  --patch /etc/dsh/registry-production.patch.yml
```

`registry/registry-single-host.example.patch.yml` 是生产基础模板，内建 provider 只解析启动进程继承的环境变量，不能读取 `.env`、本地凭据文件或写入秘密；继续叠加 `registry/registry-postgres.example.patch.yml` 才启用多组织 SaaS 控制面、组织运行时路由和 PostgreSQL RLS。由于 Loader 的 `config` patch 是整体替换，PostgreSQL 层显式携带完整 OIDC、API、限流、告警和同步配置，不能删成看似等价的局部片段。`verify-production-graph.mjs` 会按启动顺序合成同一组 patch，并在缺少 credentials、非回环监听、非 PostgreSQL domain、迁移模式、不安全共库、本地／测试插件或非 introspection OIDC 时阻止启动。`registry/registry.env.example` 列出所需环境变量。SaaS 的设备认证、按租户持久导入队列和加密提问邮箱均由 Registry 内建提供；真实 Harness 仍需实现提问消费、隔离执行与回复提交。Registry 已提供独立 `registryDisclosureContentProvider` 接线层，但模板尚未配置真实实现，因此固定 checkpoint 正文读取接口仍返回 501；生产 overlay 必须使用固定条目标识 `registry-disclosure-content-provider`、显式设置 `saas.disclosureContentProvider: true`，并将 `registryDisclosureContentProvider` 加入运行时 `inject`。生产图门禁要求三项同时存在或同时缺省，避免并发加载、卸载或热替换留下失效实例；KMS 缺失本身不会阻止 Registry 启动。

## 公网入口

把代码安装到 `/opt/dsh-a2a-registry`，Registry 只监听回环 3081；使用 `registry/Caddyfile.example` 在正式域名提供 HTTPS/WSS。`registry/dsh-registry.service.example` 已指向独立启动器。确保服务用户可以写入自己的 DSH_HOME 与三套数据库目录，不能读取 Harness 设备私钥。

三个 systemd 示例都会在执行预检前清除 `NODE_OPTIONS`、`NODE_PATH`、`NODE_TLS_REJECT_UNAUTHORIZED` 和动态链接器注入变量，避免全局服务环境或秘密文件在预检启动前加载代码、改写模块解析或关闭 TLS 校验；生产所需变量必须逐项写入对应的受限环境文件。示例同时用 `LimitCORE=0` 禁止生成可能含会话、设备或数据库凭据的 core dump，并用 `PrivateDevices=true` 隐藏主机设备节点。这些设置不会关闭 Registry、Harness 或 Caddy 需要的普通网络与工作目录访问。不要盲目追加 `MemoryDenyWriteExecute=true`、`PrivateNetwork=true` 或未验证的系统调用过滤：它们可能破坏 Node.js JIT、公网 WSS／OIDC 或 Harness 工作区。

不要将本地 Keycloak 的 `start-dev`、测试身份或回环 HTTP 配置直接作为公网生产配置。

```sh
node deploy/registry/check-production-environment.mjs registry
node deploy/registry/verify-production-oidc.mjs --issuer https://identity.example.com/realms/registry --client-id dsh-a2a-registry --client-secret-env DSH_REGISTRY_OIDC_CLIENT_SECRET
node --import tsx/esm deploy/registry/verify-public-registry.mjs
node --import tsx/esm deploy/registry/verify-registry-device.mjs
```

`registry` 范围是公网 SaaS 门禁：必须显式提供使用 `registry_app` 角色的 PostgreSQL URL 和 SaaS 初始化信息，单组织 SQLite 配置不能通过。公网验证还会从服务端状态接口确认实时 `registryTenantRouter` 已加载，不以浏览器缓存或单纯的 `standard` 部署标签代替。设备验证应在掌握设备凭据的 Harness 一侧执行，不能把设备私钥放入公网 Registry 服务环境。

设备验证会使用同一凭据完成两轮独立的 WSS 挑战、认证和心跳：第一轮主动断开，第二轮必须取得新的挑战并以同一设备公钥重新认证。它证明公网链路允许设备重连，但不代替 Harness 自身的持久离线队列、进程重启恢复和业务消费验收。

公网验证器会先直接访问正式域名的 HTTP 80 端口，并以 `manual` 模式检查跳转而不自动跟随。每次生成新的随机探测值，同时覆盖首页、状态 API、WSS 路径、不可预知路径和 GET／POST，避免边缘层只对白名单探针伪造通过。所有探测都只接受 301／308 永久跳转，`Location` 必须是不含用户名或密码的同域 HTTPS 443 地址，并完整保留各自请求的路径与查询；跨域、非 HTTPS、非 443、相对跳转、错误路径或附加片段都会失败。端口 80 只能承担该跳转，Registry 页面、API 与 WSS 均只由 443 提供。

`/healthz` 只用于判断 Registry 进程是否存活。`/readyz` 还会等待应用加载完成，并在 SaaS 模式分别通过实际 storage pool 与 tenancy pool 核对 PostgreSQL 权威版本标记；非 PostgreSQL domain 路由、数据库中断或标记缺失时返回 503，数据库恢复后会自动恢复为 200。该数据库探针按进程单飞、短暂缓存，HTTP 决策在 2 秒内失败关闭，底层查询与新建连接也分别受 1.5 秒和 10 秒硬上限约束。Caddy 的上游健康检查使用 `/readyz`。

## Harness 接入

Harness 仍是单独安装的外部程序。其中 `/opt/deepseek-harness` 是 Harness 自身的安装路径，不是 Registry 的构建依赖。

`registry/enroll-registry-device.mjs` 提供设备自助绑定：`start` 在 Harness 侧生成并保留 Ed25519 私钥和设备 secret，只向 Registry 提交公钥与 secret 摘要；组织成员在返回的审批地址核对临时配对码后，运行 `confirm` 完成挑战签名，再用 `export-env` 导出连接所需的五项环境变量。状态文件和导出文件都包含长期敏感凭据，必须放入受限目录或部署秘密管理，不能提交到 Git。

`registry/harness-registry-connection.example.patch.yml` 是最小连接模板，只启用生产设备鉴权、在线状态和断线重连，不会启用披露发布、导入、提问、KMS 或任何远程工具执行。它可以先用于验证真实绑定和 WSS 链路。`registry/harness-production-publication.example.patch.yml` 才是完整披露链路的配置参考，但仍须由部署者提供生产披露授权、密钥发布／刷新、导入和提问实现。`registry/harness.env.example` 与 `registry/dsh-harness.service.example` 分别提供环境变量和进程托管参考。

设备在发起绑定前自行生成 Ed25519 私钥和独立的 32 字节设备 secret，只把公钥与 secret 摘要提交给 Registry。人工配对码只用于成员审核，不能当设备 token。绑定确认后，Harness 使用由组织 ID、绑定 ID 和原始 secret 组成的 `dsh1` token 发起 WSS 连接，并对每次 Registry 随机挑战签名；Registry 在每个操作前重新检查绑定、成员、scope 和密钥。生产发布、导入和提问还需具备相应设备 scope 与数据密钥；网页 OIDC 账号会话不能替代设备凭据。

## 备份与恢复

`registry/backup-registry-state.mjs` 和 `registry/backup-sqlite.mjs` 只覆盖纯 SQLite 部署。PostgreSQL SaaS 使用 `registry/backup-postgres-saas-state.mjs`：它把一个 PostgreSQL custom archive、admission SQLite、alert-outbox SQLite 和 exact v2 manifest 发布为一个不可拆分的停服备份集合。v2 manifest 还保存两张 schema v3 计费表的固定列签名、稳定行数和规范 SHA-256 摘要，不保存订单、事件或支付正文。

### PostgreSQL SaaS 停服备份

生产契约是一套专用 PostgreSQL cluster 只承载一个权威 Registry 数据库和一个 SaaS schema，不能与其他业务数据库共享。`registry_backup` 是 cluster 级、持久但凭据仅离线注入的专用账号：固定 `LOGIN + NOINHERIT + CONNECTION LIMIT 2 + BYPASSRLS`，只能 `CONNECT` 权威数据库、`USAGE` 目标 schema、`SELECT` 目标表／序列，没有角色成员关系、写权限、`CREATE` 或 `TEMP`。不能给它 `pg_read_all_data`，也不能把它用于第二个数据库或 schema；误授外部权限时在线启动和备份都会失败关闭。下方 provisioning 会先拒绝存在其他用户数据库的 cluster，再撤销维护／模板数据库的 `PUBLIC CONNECT`，因此不会在共享 cluster 上静默收权。管理员在 Registry 停服后用秘密管理注入随机密码，并幂等执行：

```powershell
$env:REGISTRY_BACKUP_PASSWORD = '<由秘密管理注入，至少 24 字符>'
Get-Content -Raw deploy/postgres/provision-registry-backup-role.sql |
  psql -v ON_ERROR_STOP=1 --set=target_schema=registry_saas
Remove-Item Env:\REGISTRY_BACKUP_PASSWORD
```

管理员连接信息同样只放 `PGHOST`、`PGUSER`、`PGPASSWORD`、`PGDATABASE` 等进程环境变量，不写入命令行或仓库。上述 SQL 会原子撤销目标外权限、清理双向角色成员关系、设置未来对象的只读默认权限并复核最终 ACL。旧 schema 共库只允许作为迁移期状态；本地只给 `registry_saas_local` 授权，不能把这种共库布局当成正式备份拓扑。

先为每个组织运行下方语义 `capture`，再停止全部 Registry 进程，并确认 admission/outbox 文件不再被写入。`--quiesced` 是运维人员的明确停服承诺；数据库会话检查只能证明检查时没有 Registry 连接，不能单独证明某个空闲进程已经退出。备份父目录必须事先创建，并把 ACL 限制为备份操作员和系统管理员；不要把输出写入共享目录。在 Windows 上先执行：

```powershell
$backupRoot = 'D:\secure-backups'
New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls.exe $backupRoot /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法限制备份目录 ACL' }
```

随后从秘密管理临时注入两个离线 URL 和两个绝对 SQLite 路径：

```powershell
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = '<registry_migrator URL>'
$env:DSH_REGISTRY_POSTGRES_BACKUP_URL = '<registry_backup URL>'
$env:DSH_REGISTRY_ADMISSION_SQLITE_PATH = 'D:\registry-state\admission.sqlite'
$env:DSH_REGISTRY_ALERT_OUTBOX_SQLITE_PATH = 'D:\registry-state\alert-outbox.sqlite'
node deploy/registry/backup-postgres-saas-state.mjs create --schema registry_saas --quiesced "$backupRoot\registry-20260917"
Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL,Env:\DSH_REGISTRY_POSTGRES_BACKUP_URL
```

迁移账号持有同一事务内的 schema advisory lock 和所有目标表 `SHARE` 锁，备份账号执行 `pg_dump`；计费摘要由同一受限备份账号在 `REPEATABLE READ READ ONLY` 快照中按主键分页计算，两个 SQLite 文件使用 SQLite backup API。工具还比较 SQLite 主文件和非空 WAL 的前后文件状态与摘要，以及 PostgreSQL 序列状态。任一步失败、发现活跃 Registry 连接或检测到源变化时只删除临时目录，不发布目标目录。可用 `DSH_REGISTRY_PG_DUMP_PATH`／`DSH_REGISTRY_PG_RESTORE_PATH` 指定名称严格匹配的绝对工具路径；否则从 `PATH` 查找。离线验证不需要数据库凭据：

```powershell
node deploy/registry/backup-postgres-saas-state.mjs verify D:\secure-backups\registry-20260917
```

验证会核对 manifest exact shape、每个文件的 SHA-256／大小、两个 SQLite `quick_check`，并解析真实 `pg_restore --list` 输出，要求 `billing_orders` 和 `billing_provider_events` 在目标 schema 下各有且仅有一条 `TABLE` 和一条 `TABLE DATA`，且 owner 与对象 OID 成对。把整个目录复制到异机受限介质；凭据不在 manifest 内，必须单独备份。manifest 没有数字签名：这些检查用于发现损坏、漏表和误恢复，不能证明备份来源可信，也不能抵御能同时替换 archive 与 manifest 的攻击者。

### 只恢复到新隔离目标

本切片不自动改数据库。恢复必须先验证备份，再在全新的专用 cluster 创建全新的空数据库和全新的 sidecar 路径；目标 schema 必须不存在。不要运行会预建 `registry` schema 的本地初始化脚本。连接到明确的隔离目标数据库后，以管理员运行 `deploy/postgres/create-registry-backup-role.sql`；它从环境创建／核对三个角色、收紧 cluster 数据库连接权限，并拒绝已有用户 schema 或关系的数据库：

```powershell
$env:PGHOST = '127.0.0.1'
$env:PGPORT = '55432'
$env:PGUSER = 'postgres'
$env:PGPASSWORD = '<隔离实例管理员密码>'
$env:PGDATABASE = 'registry_restore_empty'
$env:REGISTRY_APP_PASSWORD = '<由秘密管理注入，至少 24 字符>'
$env:REGISTRY_MIGRATOR_PASSWORD = '<由秘密管理注入，至少 24 字符>'
$env:REGISTRY_BACKUP_PASSWORD = '<由秘密管理注入，至少 24 字符>'
Get-Content -Raw deploy/postgres/create-registry-backup-role.sql | psql -v ON_ERROR_STOP=1
$adminPassword = $env:PGPASSWORD
$migratorPassword = $env:REGISTRY_MIGRATOR_PASSWORD
Remove-Item Env:\PGPASSWORD,Env:\REGISTRY_APP_PASSWORD,Env:\REGISTRY_MIGRATOR_PASSWORD,Env:\REGISTRY_BACKUP_PASSWORD
```

archive 需要创建目标 schema，因此只在这次隔离恢复窗口临时给 migrator 当前数据库 `CREATE`，并在 `finally` 中撤销。实际 archive 仍仅由 `registry_migrator` 以 `--no-owner --single-transaction` 恢复；禁止 `--clean`，禁止指向现有数据库：

```powershell
$env:PGUSER = 'postgres'
$env:PGPASSWORD = $adminPassword
psql -v ON_ERROR_STOP=1 -c 'grant create on database registry_restore_empty to registry_migrator'
if ($LASTEXITCODE -ne 0) { throw '无法开启隔离恢复窗口' }
try {
  $env:PGUSER = 'registry_migrator'
  $env:PGPASSWORD = $migratorPassword
  pg_restore --exit-on-error --single-transaction --no-owner --no-tablespaces --no-password `
    --dbname $env:PGDATABASE D:\secure-backups\registry-20260917\registry.pgdump
  if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL 恢复失败' }
} finally {
  $env:PGUSER = 'postgres'
  $env:PGPASSWORD = $adminPassword
  psql -v ON_ERROR_STOP=1 -c 'revoke create, temporary on database registry_restore_empty from registry_migrator'
  if ($LASTEXITCODE -ne 0) { throw '无法关闭隔离恢复窗口；禁止启动 Registry' }
  Remove-Item Env:\PGPASSWORD
  $adminPassword = $null
  $migratorPassword = $null
}
```

恢复完成后继续保持停服，用目标集群的迁移账号运行幂等离线 schema 迁移，再拆分在线权限。租户策略指纹从规范化 `pg_get_expr` 表达式、策略结构和角色名生成，并在固定的 `pg_catalog` 搜索路径下反解析，因此不包含源集群对象 OID。旧备份可能仍保存基于 `pg_node_tree` 的集群局部指纹；它必须通过这一步在目标集群重算，不能跳过迁移直接启动 `schemaMode: validate`：

```powershell
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = '<由秘密管理注入的目标 registry_migrator URL>'
node --import tsx/esm deploy/registry/migrate-postgres-schemas.mjs `
  --schema registry_saas --execute --confirm-runtime-stopped
Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL
```

archive 保留源 ACL；`--no-owner` 让所有对象由执行恢复的 `registry_migrator` 持有。离线迁移完成后，仍须在停服状态依次运行 `split-registry-runtime-role.sql` 和 `provision-registry-backup-role.sql`，重新固化并验证 app/backup exact ACL。

权限重新固化后、启动 Registry 前，临时注入这个隔离目标的 migrator 与 backup URL，执行计费恢复完整性门禁。该命令会先重做全部离线备份验证，再由 migrator 锁住目标表，由 `registry_backup` 在只读一致快照中重新计算两张计费表的行数和摘要；任何缺表、内容变化、URL 指向不同数据库或权限漂移都会失败关闭，输出只含行数与摘要：

```powershell
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = '<隔离目标 registry_migrator URL>'
$env:DSH_REGISTRY_POSTGRES_BACKUP_URL = '<同一隔离目标 registry_backup URL>'
node deploy/registry/backup-postgres-saas-state.mjs verify-restored D:\secure-backups\registry-20260917
if ($LASTEXITCODE -ne 0) { throw '计费表恢复完整性验证失败；禁止启动 Registry' }
Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL,Env:\DSH_REGISTRY_POSTGRES_BACKUP_URL
```

该门禁只比对两张 schema v3 计费表，不能替代后续逐组织业务语义验证；当前仓库尚未用真实 schema v3 支付数据跑过一次完整隔离恢复。

把两个 SQLite 文件复制到事先确认不存在的新路径，绝不能覆盖旧介质：

```powershell
$restoreRoot = 'D:\registry-restore'
New-Item -ItemType Directory -Path $restoreRoot -Force | Out-Null
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls.exe $restoreRoot /inheritance:r /grant:r "*$($identity):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw '无法限制恢复目录 ACL' }
$admission = Join-Path $restoreRoot 'admission.sqlite'
$outbox = Join-Path $restoreRoot 'alert-outbox.sqlite'
if ((Test-Path $admission) -or (Test-Path $outbox)) { throw '恢复 sidecar 路径必须为空' }
Copy-Item D:\secure-backups\registry-20260917\admission.sqlite $admission
Copy-Item D:\secure-backups\registry-20260917\alert-outbox.sqlite $outbox
```

最后只在隔离端口启动使用 `registry_app`、`schemaMode: validate` 和新 sidecar 路径的单实例 Registry；启动环境不得含 migrator/backup URL 或 `REGISTRY_BACKUP_PASSWORD`。就绪后逐组织运行下方 `verify`，全部通过后才能规划切流。

`registry/verify-registry-restore.mjs` 用于恢复后的语义检查：SaaS 恢复校验必须逐组织执行；捕获文件会固定组织 ID，验证时不能换租户：

```text
node deploy/registry/verify-registry-restore.mjs capture https://registry.example.com org-123 /secure/restore/org-123.json
node deploy/registry/verify-registry-restore.mjs verify  https://restored-registry.example.com org-123 /secure/restore/org-123.json
```

认证会话仅通过进程环境变量 `DSH_REGISTRY_RESTORE_COOKIE` 临时注入；不要把 Cookie 写入命令行、捕获文件或仓库。公网 origin 必须使用 HTTPS，本地隔离演练仅允许 HTTP loopback。

告警恢复演练工具 `verify-operational-alert-recovery.mjs` 需用 `node --import tsx/esm` 运行，并将 `REGISTRY_DRILL_TLS_DIR` 设为独立测试证书目录，包含 `ca.pem`、`server.pem`、`server-key.pem`，服务端证书必须包含 IP SAN `127.0.0.1`。本仓库不提交任何私钥；不要使用生产证书进行此演练。

## 上线前需要部署者提供

| 类别 | 必需输入 | 当前缺少时的行为 |
| --- | --- | --- |
| 账号、组织与身份 | 正式 OIDC issuer、client ID、client secret、允许的回调地址、可即时反映用户停用的 Token Introspection，以及能稳定映射到成员 ID 的不可变 claim；旧单组织迁移时还需明确旧组织 ID、初始 Owner 主体和显示名称 | 保持身份未配置；缺少或无法验证 introspection 时受保护请求失败关闭；本地 Keycloak 只能用于本机验收；不会自动认领旧组织 |
| Harness | 每台实例的独立设备私钥、独立设备 secret、确认后的 `dsh1` token；仅授予需要的 `disclosure.sync`／`a2a.receive` scope；公网 WSS 地址与设备公钥登记 | 不能连接生产 Registry；不会退化为人工配对码、网页账号或共享测试密钥 |
| 密钥管理 | 选定的生产 KMS／秘密管理服务、披露数据密钥的生成、作用域授权、轮换、恢复和销毁流程 | 不发布生产披露；不从仓库或普通 `.env` 读取披露私钥 |
| 公网部署 | 正式域名、DNS 控制权、ACME 邮箱、HTTPS 告警接收地址、异机备份位置、Linux 服务账号和 PostgreSQL 生产连接信息 | 只允许回环本地运行；不宣称已公网可用 |
| 支付（可选） | 是否首发收费；若收费，选择 Stripe／支付宝并提供商户账号、产品/Price、Webhook 验签资料、退款/税务/发票规则 | 支付 provider 保持关闭，方案和结账接口返回未配置，不产生交易 |

秘密只写入部署平台的 secret store 或受限的主机文件，不要通过聊天发送，也不要提交到 Git。准备好非秘密项后，先填写 `registry.env.example`、`harness.env.example` 和 `edge.env.example` 的副本，再运行对应范围的 `check-production-environment.mjs`。
