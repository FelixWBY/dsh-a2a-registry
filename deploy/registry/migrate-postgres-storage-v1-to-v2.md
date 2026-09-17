# 单组织 PostgreSQL 数据迁移

这个工具把指定 schema 中的 Registry PostgreSQL storage 从 v1 原地升级到带租户边界和强制 RLS 的 v2。它不猜 schema 或组织 ID，不复制到另一个 schema，也不修改账号、OIDC 或目录成员。默认命令只做只读计划并回滚；只有显式 `--execute` 才会提交。

## 迁移前

1. 从旧部署配置确认唯一的 `ingest.organizationId`，不要生成新 ID。
2. 停止所有连接同一数据库的 Registry 实例。工具执行时按 `registry_app` 数据库账号并辅以应用名检查 `pg_stat_activity`，发现 Registry 连接就拒绝提交；URL 中覆盖应用名不能绕过账号检查。空闲进程可能暂时没有数据库会话，因此这个检查只是附加保护，不能替代停服务。
3. 对数据库执行 `pg_dump`，恢复到隔离数据库并验证可读。恢复时保留原对象所有者，或显式把目标 schema 和表交给迁移角色；不要用 `--no-owner` 意外改成超级用户所有。持久卷不是备份。
4. 从备份或只读查询记录 v1 的 `units`、`unit_globals`、`unit_records` 精确行数。执行命令必须提供这三个预期值。
5. 先完成数据库角色拆分，再把离线账号连接串只注入当前进程的 `DSH_REGISTRY_POSTGRES_MIGRATOR_URL`。工具会拒绝在线账号；不要把连接串写进命令参数、文档、聊天或 Git。

工具要求非超级用户、没有 `BYPASSRLS`、拥有目标 schema 迁移权限，并继承只读内置角色 `pg_read_all_stats`；缺少完整会话可见性会直接拒绝执行。它只接受小写字母、数字和下划线组成的显式 schema 名。历史版本中硬编码 `registry` 的 `002-tenant-scope-rls.sql` 已移除，不得从旧副本继续使用。

## 先运行计划

```powershell
$env:DSH_REGISTRY_POSTGRES_MIGRATOR_URL = '<从秘密管理注入>'
node deploy/registry/migrate-postgres-storage-v1-to-v2.mjs `
  --schema <旧数据实际 schema> `
  --legacy-tenant-id <旧组织 ID> `
  --expect-units <单元数> `
  --expect-globals <全局记录数> `
  --expect-records <领域记录数>
```

计划在可重复读事务中验证版本、表布局、主外键、三个预期计数、持久化组织 ID，并生成不含原文的 SHA-256 摘要，最后回滚。输出只记录检测瞬间观察到的 Registry 数据库连接数，并始终保留 `operatorQuiescenceStillRequired: true`；计划成功不代表 Registry 进程已经停止，也不等于已经迁移。

## 执行

确认 Registry 已停、备份已通过隔离恢复、计划输出和人工记录一致后，在同一主机执行：

```powershell
node deploy/registry/migrate-postgres-storage-v1-to-v2.mjs `
  --schema <旧数据实际 schema> `
  --legacy-tenant-id <旧组织 ID> `
  --expect-units <单元数> `
  --expect-globals <全局记录数> `
  --expect-records <领域记录数> `
  --execute --confirm-quiesced --confirm-backup-verified
```

执行过程取得与权限拆分及其他结构迁移共用的 schema 级快速失败锁，以固定顺序独占锁定四张存储表，在一个事务内增加并回填 `tenant_id`、替换复合主外键、启用并强制 RLS、安装 `tenant_isolation` 策略，最后才把版本写为 2。提交前再次核对计数、约束、RLS 和前后摘要；任一步失败都会回滚整个事务。

storage v2 提交后仍不要启动在线服务。继续用同一离线连接补齐 SaaS 控制面和策略指纹，再重新执行权限拆分脚本，让新增表获得最小业务授权并把两张元数据表恢复为只读：

```powershell
node --import tsx/esm deploy/registry/migrate-postgres-schemas.mjs `
  --schema <旧数据实际 schema> --execute --confirm-runtime-stopped

$split = Get-Content -Raw deploy/postgres/split-registry-runtime-role.sql
$split | psql '<DBA 连接由秘密管理注入>' -v ON_ERROR_STOP=1 `
  --set=target_schema=<旧数据实际 schema>
Remove-Item Env:\DSH_REGISTRY_POSTGRES_MIGRATOR_URL
```

不要把示例中的 DBA 连接写入脚本或 Shell 历史；实际部署应由数据库管理员通过受控会话执行。

## 提交后验收与回滚

- 只启动一个新版 Registry 实例，并把同一个组织 ID 配置为旧组织。
- 使用已确认的 Owner 身份登录，核对目录、披露、请求状态和审计摘要。
- 创建第二个测试组织，确认两个组织互相看不到数据。
- 完成业务验收前保留旧版本程序和迁移前备份，不启动第二个业务副本。

若工具在 `COMMIT` 前失败，数据库仍是 v1，可修复原因后重新运行计划。若终端在提交确认期间断开，先只读检查 `storage_meta.schema_version`，不要盲目重试。若已提交但业务验收失败，停止新版 Registry，从迁移前备份恢复到隔离数据库并验证后再切回；不要手工删除租户列、策略或降低版本号。
