# 本地 PostgreSQL（Docker）

Windows 使用 Docker Desktop 的 WSL 2 / Linux 容器引擎，不安装 Windows 原生 PostgreSQL。固定 `postgres:18.6-bookworm`，数据库 `registry`，应用账号 `registry_app`，只监听 `127.0.0.1:5432`。注册站已提供 PostgreSQL KV 后端与显式 SQLite 迁移工具；切换仍必须由部署者停写、备份并执行迁移，不能只修改配置。

## 启停

安装并启动 Docker Desktop；首次启用 WSL 2 后若 Windows 要求重启，先保存工作再重启。无需单独安装 Ubuntu。

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Start
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Status
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Stop
powershell -ExecutionPolicy Bypass -File scripts/local-postgres.ps1 Backup
```

`Prepare` 可在 Docker 未启动时准备首次本地凭据。密码随机生成，仅存于忽略目录 `.artifacts/postgres/private`；`connection.env` 保存应用连接串，但不会自动覆盖根目录环境文件。不要把此目录、连接串或数据库备份发到 GitHub。

应用账号不是超级管理员，不能创建其他数据库／角色，只能连接 `registry` 并在自己的 `registry` schema 内建表和读写。当前 Registry 领域表是通用 KV 行，组织隔离仍由单组织进程和应用授权负责；不能把 PostgreSQL 接入视为多租户 RLS 已完成。

## 注册站接入与迁移

先读取本机忽略文件 `.artifacts/postgres/private/connection.env`，把其中连接串仅注入当前 Registry 进程的 `DSH_REGISTRY_POSTGRES_URL`，再在单机部署 patch 后追加：

```powershell
npm start -- --patch deploy/registry/registry-single-host.example.patch.yml --patch deploy/registry/registry-postgres.example.patch.yml
```

已有 SQLite 介质必须先停 Registry 并完成 SQLite 与 PostgreSQL 备份，然后迁移到空目标：

```powershell
$env:DSH_REGISTRY_POSTGRES_URL = '<从本机私密 connection.env 读取，不要提交>'
node --import tsx/esm deploy/registry/migrate-sqlite-storage-to-postgres.mjs --sqlite <源数据库绝对路径> --confirm-empty-target
```

迁移工具要求源库 `quick_check=ok`、目标 `units` 为空，按单事务批次写入每个领域；不会覆盖已有目标数据。完成后先用隔离 Registry 验证，再切换正式进程。回滚方式是停止新进程并恢复切换前 SQLite 介质；切换后产生的新写入不会自动反向同步。

## 数据与备份

- 数据位于命名卷 `dsh-registry-postgres-data`；PostgreSQL 18 的挂载点为 `/var/lib/postgresql`。停止或重建容器不会主动删除该卷。
- **禁止运行 `docker compose down -v` 或清理该卷。** 重装／重置 Docker Desktop 仍可能丢数据，持久卷不是备份。
- `Backup` 生成自定义格式 `pg_dump`，保存在 `.artifacts/postgres-backups`；需要另行复制到安全的异机位置。此命令不备份角色密码。切换前的 JSON／SQLite 介质仍须单独保留，凭据也要单独安全保管。
- 恢复时先创建隔离的新数据库，使用匹配版本的 `pg_restore` 验证；不要直接覆盖正在使用的库。大版本升级必须显式迁移和验证，不能直接把镜像改成下一代版本。
- 初始化脚本只在空卷第一次运行；修改本地密码文件不会更改已有数据库密码。凭据丢失先恢复，不要删卷或生成新密码来“修复”。

## 后续上线

Linux 服务器使用 Docker Engine + Compose，无需 Windows 或 Docker Desktop。复用 Compose 和初始化文件，在服务器重新生成秘密并完成备份恢复；如果应用也容器化，连接主机名改为 `postgres`，不是 `127.0.0.1`。公网只暴露 HTTPS 应用入口，数据库端口不对外开放。此配置是单机起步方案，不包含高可用、自动备份、生产 TLS 或跨进程写入协调。

官方依据：[Docker Desktop Windows 安装](https://docs.docker.com/desktop/setup/install/windows-install/)、[PostgreSQL 官方镜像](https://hub.docker.com/_/postgres)。
