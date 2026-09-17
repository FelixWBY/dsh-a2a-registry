# PostgreSQL 存储

这个后端把每个 KV 单元写入 PostgreSQL，并从 schema v2 开始把 `tenant_id` 纳入所有物理主键和外键。`KvUnitDescriptor.tenantId` 是显式租户边界；未提供时使用保留的空字符串全局作用域。JSON 和 SQLite 后端保持原行为并忽略该字段。

每一次打开、读取或写入都会独占一个池连接并执行：

1. `BEGIN`；
2. `set_config('app.tenant_id', tenantId, true)`；
3. 带显式 `tenant_id` 条件的 SQL；
4. `COMMIT`，失败则 `ROLLBACK`。

`true` 表示事务局部设置，连接归还池后不会把一个非空租户的上下文带给下一个租户。`units`、`unit_globals`、`unit_records` 均启用并强制 RLS；策略同时约束读取和写入，直接比较行的 `tenant_id` 与当前事务设置。后端不会在该事务边界外访问这三张表；部署代码也不能绕过后端直接查询它们。

初始化会先取得由 schema 名经 SHA-256 派生的事务级 advisory lock，再检查 `current_user`。超级管理员或带 `BYPASSRLS` 的角色会在任何建表或迁移前被拒绝；同一 schema 的并发首启则串行检查版本，避免重复执行 v1 DDL。

## v1 升级

schema v1 没有租户列。后端发现 v1 时会在单一事务内升级；任何步骤失败都会完整回滚。若 v1 的 `units` 已有行，配置必须显式提供 `legacyTenantId`，所有旧行都会归入该租户。后端不会检查或猜测 JSON 内的组织字段。

```yaml
config:
  connectionString: !!js process.env.DSH_REGISTRY_POSTGRES_URL
  schema: registry
  legacyTenantId: !!js process.env.DSH_REGISTRY_LEGACY_TENANT_ID
```

先停止旧 Registry 并验证 `pg_dump` 可以恢复，再启动新版本。升级确认完成后可以删除 `legacyTenantId` 配置；它不会参与 v2 的正常读写。需要离线迁移时，只能使用 `deploy/registry/migrate-postgres-storage-v1-to-v2.mjs` 的默认只读计划和显式执行流程；不能同时运行工具和应用内迁移。

空 v1 数据库无需配置，会迁入保留的全局作用域。未知 schema 版本、填充过但未指定旧租户的 v1 数据库，以及部分手工修改的表结构都会拒绝启动。
