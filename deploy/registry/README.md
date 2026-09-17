# Registry 部署模板

请按[独立部署说明](../README.md)操作。本目录提供独立 Registry、外部 Harness、OIDC 和多租户 PostgreSQL 所需的配置模板及本地运维工具，不再使用原单体仓库的启动命令。

生产基础配置叠加 `registry-postgres.example.patch.yml` 后启用 SaaS 模式、自助组织创建／切换、按组织延迟加载运行时和 PostgreSQL RLS。所有 `.example` 文件均需替换为自己的环境配置，不包含真实凭据。

PostgreSQL 必须在停服后按 `deploy/postgres/split-registry-runtime-role.sql`、独立 `registry_migrator` 的 `migrate-postgres-schemas.mjs`、同一权限脚本的顺序执行完整 `split → migrate → split`。在线 Registry 只注入 `registry_app` URL，并以 `schemaMode: validate` 做只读启动校验；迁移 URL 不得进入服务环境。

本地开发先启动仓库提供的 PostgreSQL 容器。首次初始化或结构升级时，先停止 3081／3181 两个 Registry，再显式运行 `start-local-keycloak.ps1 -UpgradeDatabase`；它执行一次 `split → migrate → split` 后启动站点。日常运行只执行 `start-local-keycloak.ps1`，不会改数据库结构，只由在线进程做只读校验。脚本启动固定版本 Keycloak、打开用户自助注册并启动 Registry；生成的凭据只写入 Git 忽略的本地文件。该 Keycloak 配置不得用于生产。

已有单组织 PostgreSQL storage v1 上线前必须停写、备份并迁移。使用默认只读计划、显式 schema 和预期计数的 [v1 到 v2 迁移工具](migrate-postgres-storage-v1-to-v2.md)；不要把硬编码 `registry` 的旧 SQL 用到其他 schema。
