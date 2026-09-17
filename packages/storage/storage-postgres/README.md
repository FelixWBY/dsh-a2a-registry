# PostgreSQL 存储

这个后端把每个 KV 单元写入 PostgreSQL，并从 schema v2 开始把 `tenant_id` 纳入所有物理主键和外键。`KvUnitDescriptor.tenantId` 是显式租户边界；未提供时使用保留的空字符串全局作用域。JSON 和 SQLite 后端保持原行为并忽略该字段。

每一次打开、读取或写入都会独占一个池连接并执行：

1. `BEGIN`；
2. `set_config('app.tenant_id', tenantId, true)`；
3. 带显式 `tenant_id` 条件的 SQL；
4. `COMMIT`，失败则 `ROLLBACK`。

`true` 表示事务局部设置，连接归还池后不会把一个非空租户的上下文带给下一个租户。`units`、`unit_globals`、`unit_records` 均启用并强制 RLS；策略同时约束读取和写入，直接比较行的 `tenant_id` 与当前事务设置。后端不会在该事务边界外访问这三张表；部署代码也不能绕过后端直接查询它们。

## 在线角色与只读校验

公网 Registry 必须显式配置 `schemaMode: validate`：

```yaml
config:
  connectionString: !!js process.env.DSH_REGISTRY_POSTGRES_URL
  schema: registry
  schemaMode: validate
```

该模式只开启 `REPEATABLE READ READ ONLY` 事务并读取 PostgreSQL catalog 和 `storage_meta`，不会执行 `CREATE`、`ALTER`、`DROP` 或数据写入。启动时会拒绝以下角色：

- 自身或任一可承担角色是超级管理员或带 `BYPASSRLS`；
- 连接身份不是固定在线账号 `registry_app`，或该账号可继承／切换到任一其他组角色；
- 自身或任一可承担角色对当前数据库拥有 `CREATE` 或 `TEMP`；
- 自身或任一可承担角色对任一 schema 拥有 `CREATE` 权限；
- 没有存储 schema 的 `USAGE` 权限；
- 拥有任一存储表，或可通过角色成员关系切换为表所有者。

校验同时要求 schema v2 的四张表存在，三个租户表均具有非空 `text tenant_id`、启用并强制 RLS，而且只存在精确的 `tenant_isolation` 全命令策略。部署时应让独立迁移角色持有 schema/表；在线角色只获得 schema `USAGE`、`storage_meta` 的 `SELECT`，以及三个租户表所需的 `SELECT`、`INSERT`、`UPDATE`、`DELETE`，不得拥有 `TRUNCATE`、`REFERENCES`、`TRIGGER` 或 PostgreSQL 18 的 `MAINTAIN`。

`allowUnsafeSharedDatabase: true` 只为本仓库当前本地旧站与 SaaS 共库的迁移过渡保留：它仍检查固定账号、目标 schema、角色链、数据库权限和表权限，只暂时忽略其他 legacy schema 的 `CREATE`。公网配置必须保持默认 `false`，完成 P-MIGRATE 后本地配置也必须删除该例外。

`schemaMode` 缺省仍是 `migrate`，仅用于兼容现有本地配置。生产配置不能依赖这个缺省值。

## v1 升级

schema v1 没有租户列。离线迁移会先取得与权限拆分、控制面迁移共用的 schema 级事务锁；锁已占用时快速失败，不会无限等待。之后在单一事务内升级，任何步骤失败都会完整回滚。超级管理员或带 `BYPASSRLS` 的迁移连接也会被拒绝。若 v1 的 `units` 已有行，必须显式提供 `legacyTenantId`，所有旧行都会归入该租户。迁移不会检查或猜测 JSON 内的组织字段。

```yaml
config:
  connectionString: !!js process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL
  schema: registry
  schemaMode: migrate
  legacyTenantId: !!js process.env.DSH_REGISTRY_LEGACY_TENANT_ID
```

离线工具可以直接调用专用导出，函数结束前会关闭自己的单连接池：

```ts
import { migratePostgresStorageSchema } from '@deepseek-ai/dsh-storage-postgres'

await migratePostgresStorageSchema({
  connectionString: process.env.DSH_REGISTRY_POSTGRES_MIGRATOR_URL!,
  schema: 'registry',
  legacyTenantId: process.env.DSH_REGISTRY_LEGACY_TENANT_ID,
})
```

先停止旧 Registry 并验证 `pg_dump` 可以恢复，再运行离线迁移。升级完成后，业务进程应改用权限受限的在线连接与 `schemaMode: validate`；不能同时运行迁移工具和应用内兼容迁移路径。仓库的离线 CLI 应使用上述导出，不应通过启动业务后端来取得迁移能力。

已有数据的 v1 schema 必须经仓库的 [`deploy/registry/migrate-postgres-storage-v1-to-v2.mjs`](../../../deploy/registry/migrate-postgres-storage-v1-to-v2.mjs) 防护流程执行，不能直接调用裸导出来绕过停写确认、备份恢复、预期计数和摘要核验。该导出是离线 CLI 的底层能力，不是线上进程或运维人员跳过防护的捷径。

空 v1 数据库无需配置，会迁入保留的全局作用域。未知 schema 版本、填充过但未指定旧租户的 v1 数据库，以及部分手工修改的表结构都会拒绝启动。
