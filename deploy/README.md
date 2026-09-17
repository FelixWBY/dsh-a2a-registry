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

`registry/registry-single-host.example.patch.yml` 是生产基础模板；继续叠加 `registry/registry-postgres.example.patch.yml` 才启用多组织 SaaS 控制面、组织运行时路由和 PostgreSQL RLS。`registry/registry.env.example` 列出所需环境变量。SaaS 的设备认证和按租户持久导入队列均由 Registry 内建提供。该模板尚未配置披露解密和提问提供方，相应接口返回 501；P-KMS 仍未完成，但 KMS 缺失本身不会阻止 Registry 启动。

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

`registry/backup-registry-state.mjs` 和 `registry/backup-sqlite.mjs` 只覆盖纯 SQLite 部署。PostgreSQL SaaS 使用 `registry/backup-postgres-saas-state.mjs`：它把一个 PostgreSQL custom archive、admission SQLite、alert-outbox SQLite 和 exact v1 manifest 发布为一个不可拆分的停服备份集合。

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

迁移账号持有同一事务内的 schema advisory lock 和所有目标表 `SHARE` 锁，备份账号执行 `pg_dump`；两个 SQLite 文件使用 SQLite backup API。工具还比较 SQLite 主文件和非空 WAL 的前后文件状态与摘要，以及 PostgreSQL 序列状态。任一步失败、发现活跃 Registry 连接或检测到源变化时只删除临时目录，不发布目标目录。可用 `DSH_REGISTRY_PG_DUMP_PATH`／`DSH_REGISTRY_PG_RESTORE_PATH` 指定名称严格匹配的绝对工具路径；否则从 `PATH` 查找。离线验证不需要数据库凭据：

```powershell
node deploy/registry/backup-postgres-saas-state.mjs verify D:\secure-backups\registry-20260917
```

验证会核对 manifest exact shape、每个文件的 SHA-256／大小、两个 SQLite `quick_check`，并用受限的 `pg_restore --list` 确认 archive 可读。把整个目录复制到异机受限介质；凭据不在 manifest 内，必须单独备份。

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

archive 保留源 ACL；`--no-owner` 让所有对象由执行恢复的 `registry_migrator` 持有。恢复后仍须在停服状态依次运行 `split-registry-runtime-role.sql` 和 `provision-registry-backup-role.sql`，重新固化并验证 app/backup exact ACL。把两个 SQLite 文件复制到事先确认不存在的新路径，绝不能覆盖旧介质：

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
| 账号、组织与身份 | 正式 OIDC issuer、client ID、client secret、允许的回调地址，以及能稳定映射到成员 ID 的不可变 claim；旧单组织迁移时还需明确旧组织 ID、初始 Owner 主体和显示名称 | 保持身份未配置；本地 Keycloak 只能用于本机验收；不会自动认领旧组织 |
| Harness | 每台实例的独立设备私钥、独立设备 secret、确认后的 `dsh1` token；仅授予需要的 `disclosure.sync`／`a2a.receive` scope；公网 WSS 地址与设备公钥登记 | 不能连接生产 Registry；不会退化为人工配对码、网页账号或共享测试密钥 |
| 密钥管理 | 选定的生产 KMS／秘密管理服务、披露数据密钥的生成、作用域授权、轮换、恢复和销毁流程 | 不发布生产披露；不从仓库或普通 `.env` 读取披露私钥 |
| 公网部署 | 正式域名、DNS 控制权、ACME 邮箱、HTTPS 告警接收地址、异机备份位置、Linux 服务账号和 PostgreSQL 生产连接信息 | 只允许回环本地运行；不宣称已公网可用 |
| 支付（可选） | 是否首发收费；若收费，选择 Stripe／支付宝并提供商户账号、产品/Price、Webhook 验签资料、退款/税务/发票规则 | 支付 provider 保持关闭，方案和结账接口返回未配置，不产生交易 |

秘密只写入部署平台的 secret store 或受限的主机文件，不要通过聊天发送，也不要提交到 Git。准备好非秘密项后，先填写 `registry.env.example`、`harness.env.example` 和 `edge.env.example` 的副本，再运行对应范围的 `check-production-environment.mjs`。
