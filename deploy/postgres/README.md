# 本地 PostgreSQL（Docker）

Windows 使用 Docker Desktop 的 WSL 2 / Linux 容器引擎，不安装 Windows 原生 PostgreSQL。固定 `postgres:18.6-bookworm`，数据库 `registry`，只监听 `127.0.0.1:5432`。`registry_migrator` 只供停服后的结构迁移，`registry_app` 只供在线业务读写；两者不互相继承。注册站已提供 PostgreSQL KV 后端与显式迁移工具；切换仍必须由部署者停写、备份并执行迁移，不能只修改配置。

## 启停

安装并启动 Docker Desktop；首次启用 WSL 2 后若 Windows 要求重启，先保存工作再重启。无需单独安装 Ubuntu。

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Start
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Status
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Stop
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Backup
```

`Prepare` 可在 Docker 未启动时准备首次本地凭据。密码随机生成，仅存于忽略目录 `.artifacts/postgres/private`；`connection.env` 分别保存在线和离线连接串，但不会自动覆盖根目录环境文件。不要把此目录、连接串或数据库备份发到 GitHub。Registry 服务环境只能注入 `DSH_REGISTRY_POSTGRES_URL`，不能包含 `DSH_REGISTRY_POSTGRES_MIGRATOR_URL`。

两个账号都不是超级管理员，也没有 `BYPASSRLS`。迁移账号持有 schema 和表，并仅额外继承 PostgreSQL 内置只读角色 `pg_read_all_stats`，以便离线工具能完整确认在线会话已经停止；在线账号被明确禁止继承该角色。在线账号没有数据库临时对象权限、schema `CREATE`、对象所有权或迁移角色成员关系，只获得 schema `USAGE`、元数据只读和已知业务表 DML，未知表及未来表默认无权。PostgreSQL KV schema v2 在三张领域表上保存 `tenant_id`，并使用强制 RLS 和复合主外键隔离租户。上层仍必须给每个组织传入正确的 `tenantId`；未传时只会进入保留的空字符串全局作用域，不能把这个兼容作用域当作组织路由。

当前数据面仍由单个 Registry 进程持有内存快照和排他写入队列。同一生产 schema 只能由一个业务副本使用；不能双实例滚动发布或水平扩容。任一 schema 的离线升级会拒绝当前数据库中的全部 `registry_app` 会话，因此共库的其他 Registry 也必须先停止。升级后只启动一个新实例并完成探针验证。

## 离线结构迁移与在线校验

空卷首次初始化会创建两个角色，并让 `registry_migrator` 持有 `registry` schema。已有卷在运行新版 `Start` 后会幂等核对两个角色、密码、基础权限和空的基础 schema，但不会在业务进程运行时自动改已有对象所有权。停止相关 Registry 后，对每个实际 schema 依次执行：

```powershell
$schema = 'registry_saas_local'
$split = Get-Content -Raw deploy/postgres/split-registry-runtime-role.sql
$split | docker.exe --context desktop-linux compose -f deploy/postgres/compose.yaml exec -T postgres `
  psql -U postgres -d registry -v ON_ERROR_STOP=1 "--set=target_schema=$schema"
if ($LASTEXITCODE -ne 0) { throw '第一次权限拆分失败，已停止后续步骤' }

$line = Get-Content .artifacts/postgres/private/connection.env | `
  Where-Object { $_.StartsWith('DSH_REGISTRY_POSTGRES_MIGRATOR_URL=') } | Select-Object -First 1
if ($null -eq $line) { throw '缺少离线迁移连接串' }
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = $line.Substring('DSH_REGISTRY_POSTGRES_MIGRATOR_URL='.Length)
try {
  node --import tsx/esm deploy/registry/migrate-postgres-schemas.mjs `
    --schema $schema --execute --confirm-runtime-stopped
  if ($LASTEXITCODE -ne 0) { throw '离线 schema 迁移失败，不能执行最终授权' }
} finally {
  Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL -ErrorAction SilentlyContinue
}

$split | docker.exe --context desktop-linux compose -f deploy/postgres/compose.yaml exec -T postgres `
  psql -U postgres -d registry -v ON_ERROR_STOP=1 "--set=target_schema=$schema"
if ($LASTEXITCODE -ne 0) { throw '最终最小权限固化失败，不能启动 Registry' }
```

第一次权限拆分让迁移角色接管已有对象；离线命令只建表、升级并重装策略，执行后立即关闭连接；第二次权限拆分给新增业务表补齐最小授权并移除两张元数据表的写权限。三步使用同一个 schema 级快速失败锁，并按数据库账号而非仅按可伪装的 `application_name` 检查在线会话。在线配置必须显式使用 `schemaMode: validate`，启动时只在只读事务中核验角色、版本、表、表权限和 RLS 策略；在线账号能 DDL、元数据写入、危险表权限或缺少业务 DML 时均拒绝启动。

已有卷第一次落地该角色模型时，顺序固定为：停止 3081 和 3181，运行新版 `scripts/local-postgres.ps1 Start` 补齐角色与秘密，再显式运行：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/registry/start-local-keycloak.ps1 -UpgradeDatabase
```

之后的日常启动不带 `-UpgradeDatabase`，不会自动代执行任何迁移确认：

```powershell
powershell -ExecutionPolicy Bypass -File deploy/registry/start-local-keycloak.ps1
```

本地 Keycloak patch 暂时显式启用 `allowUnsafeSharedDatabase`，仅用于 `registry_mvp` 等 legacy schema 尚未完成 P-MIGRATE、但与 `registry_saas_local` 共用一个开发数据库的阶段。生产模板没有也不得启用该开关；旧 schema 完成角色拆分后立即从本地 patch 删除。

## schema v1 升级到 v2

先停止全部 Registry 进程并运行 `Backup`，在隔离数据库验证备份可恢复。已有 v1 数据不能靠 JSON 猜组织：第一次用新版后端启动时，必须在 PostgreSQL 插件配置中显式设置 `legacyTenantId`，而且它必须与旧站运行时的 `ingest.organizationId`（部署变量 `DSH_REGISTRY_ORGANIZATION_ID`）逐字一致。首次迁移只启动一个新版进程；不要生成新 ID，也不要让两个实例并发迁移。迁移在一个事务内增加租户列、回填旧行、替换复合主外键、启用并强制 RLS，最后才把 schema 版本写成 2；失败会回滚到 v1。

需要运维人员离线执行时，只使用带显式 schema、预期计数、停写检查和前后摘要验证的 [Registry v1 到 v2 迁移工具](../registry/migrate-postgres-storage-v1-to-v2.md)。原来硬编码 `registry` 的 `002-tenant-scope-rls.sql` 已移除，不能用历史副本代替这个工具。

```powershell
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = '<从秘密管理注入>'
node deploy/registry/migrate-postgres-storage-v1-to-v2.mjs --schema <实际schema> `
  --legacy-tenant-id <旧组织ID> --expect-units <数量> --expect-globals <数量> --expect-records <数量>
```

确认只读计划、备份恢复和停写状态后，使用相同参数追加 `--execute --confirm-quiesced --confirm-backup-verified`。

脚本和应用内迁移二选一，不能并发执行。首次启动后至少确认：`storage_meta.schema_version = 2`；三张领域表都同时启用 `relrowsecurity` 与 `relforcerowsecurity`；`units` 中只有预期的旧组织 ID；应用账号既不是超级管理员也没有 `BYPASSRLS`；旧组织页面仍能读到原数据，并且新建第二个组织后双方数据互不可见。确认无误后可删除临时 `legacyTenantId` 配置。回滚必须停止新版进程并恢复升级前备份；不要手工删除租户列或降低 `storage_meta` 版本。

```sql
\set target_schema registry_mvp
select schema_version from :"target_schema".storage_meta where singleton = true;
select tenant_id, count(*) from :"target_schema".units group by tenant_id order by tenant_id;
select relation.relname, relation.relrowsecurity, relation.relforcerowsecurity
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
where namespace.nspname = :'target_schema'
  and relation.relname in ('units', 'unit_globals', 'unit_records')
order by relation.relname;
select rolname, rolsuper, rolbypassrls from pg_roles where rolname = 'registry_app';
```

上例的 `registry_mvp` 是当前旧站实际 schema；迁移其他部署时必须先改成该部署的真实值，不能用 `registry` 代替。

## 注册站接入与迁移

先读取本机忽略文件 `.artifacts/postgres/private/connection.env`，把其中连接串仅注入当前 Registry 进程的 `DSH_REGISTRY_POSTGRES_URL`，再在单机部署 patch 后追加：

```powershell
npm start -- --patch deploy/registry/registry-single-host.example.patch.yml --patch deploy/registry/registry-postgres.example.patch.yml
```

已有 SQLite 介质必须先停 Registry 并完成 SQLite 与 PostgreSQL 备份。该兼容工具只导入保留的全局租户，适用于独立单组织部署；不得把它直接导入已有组织数据的共享 SaaS schema。先用迁移账号对一个专用空 schema 执行上面的 `split → migrate → split`，清除迁移连接串，再用在线账号复制：

```powershell
$env:DSH_REGISTRY_POSTGRES_URL = '<从本机私密 connection.env 读取，不要提交>'
node --import tsx/esm deploy/registry/migrate-sqlite-storage-to-postgres.mjs `
  --sqlite <源数据库绝对路径> --schema <专用空schema> --confirm-empty-target
```

迁移工具以 `schemaMode: validate` 使用受限在线账号，不执行 DDL；它要求源库 `quick_check=ok`、目标 schema 已离线初始化且全局租户没有任何单元，按单事务批次写入每个领域，不会覆盖已有全局数据。空检查和复制之间仍要求保持停写。完成后先用隔离 Registry 验证，再切换正式进程。回滚方式是停止新进程并恢复切换前 SQLite 介质；切换后产生的新写入不会自动反向同步。

## 数据与备份

- 数据位于命名卷 `dsh-registry-postgres-data`；PostgreSQL 18 的挂载点为 `/var/lib/postgresql`。停止或重建容器不会主动删除该卷。
- **禁止运行 `docker compose down -v` 或清理该卷。** 重装／重置 Docker Desktop 仍可能丢数据，持久卷不是备份。
- `Backup` 生成自定义格式 `pg_dump`，保存在 `.artifacts/postgres-backups`；需要另行复制到安全的异机位置。此命令不备份角色密码。切换前的 JSON／SQLite 介质仍须单独保留，凭据也要单独安全保管。
- 恢复时先创建隔离的新数据库，使用匹配版本的 `pg_restore` 验证；不要直接覆盖正在使用的库。大版本升级必须显式迁移和验证，不能直接把镜像改成下一代版本。
- 初始化脚本只在空卷第一次运行并使用单事务。每次 `Start` 会从本机秘密文件幂等核对两个角色、密码、数据库基础权限和空的基础 schema，但不会在线迁移已有对象所有权；不要手改秘密文件。凭据丢失先恢复，不要删卷或生成新密码来“修复”。

## 后续上线

Linux 服务器使用 Docker Engine + Compose，无需 Windows 或 Docker Desktop。复用 Compose 和初始化文件，在服务器重新生成秘密并完成备份恢复；如果应用也容器化，连接主机名改为 `postgres`，不是 `127.0.0.1`。公网只暴露 HTTPS 应用入口，数据库端口不对外开放。此配置是单机起步方案，不包含高可用、自动备份、生产 TLS 或跨进程写入协调。

官方依据：[Docker Desktop Windows 安装](https://docs.docker.com/desktop/setup/install/windows-install/)、[PostgreSQL 官方镜像](https://hub.docker.com/_/postgres)。
