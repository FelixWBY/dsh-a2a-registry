# Registry 部署模板

请按[独立部署说明](../README.md)操作。本目录提供独立 Registry、外部 Harness、OIDC 和多租户 PostgreSQL 所需的配置模板及本地运维工具，不再使用原单体仓库的启动命令。

生产基础配置叠加 `registry-postgres.example.patch.yml` 后启用 SaaS 模式、自助组织创建／切换、按组织延迟加载运行时和 PostgreSQL RLS。所有 `.example` 文件均需替换为自己的环境配置，不包含真实凭据。

本地开发先启动仓库提供的 PostgreSQL 容器，再运行 `start-local-keycloak.ps1`。脚本会创建隔离的本地 SaaS schema、启动固定版本 Keycloak、打开用户自助注册并启动 Registry；生成的凭据只写入 Git 忽略的本地文件。该 Keycloak 配置不得用于生产。
