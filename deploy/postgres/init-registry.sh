#!/usr/bin/env bash
set -e

export REGISTRY_APP_PASSWORD="$(cat /run/secrets/postgres_app_password)"
export REGISTRY_MIGRATOR_PASSWORD="$(cat /run/secrets/postgres_migrator_password)"
export REGISTRY_BACKUP_PASSWORD="$(cat /run/secrets/postgres_backup_password)"
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv app_password REGISTRY_APP_PASSWORD
\getenv migrator_password REGISTRY_MIGRATOR_PASSWORD
\getenv backup_password REGISTRY_BACKUP_PASSWORD
BEGIN;
CREATE ROLE registry_migrator LOGIN PASSWORD :'migrator_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE registry_app LOGIN PASSWORD :'app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE registry_backup LOGIN NOINHERIT CONNECTION LIMIT 2 PASSWORD :'backup_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_database
    WHERE datname <> current_database() AND datname <> 'postgres' AND NOT datistemplate
  ) THEN
    RAISE EXCEPTION 'Registry PostgreSQL must be a dedicated cluster';
  END IF;
END
$$;
REVOKE ALL ON DATABASE registry FROM PUBLIC;
GRANT CONNECT ON DATABASE registry TO registry_migrator, registry_app, registry_backup;
SELECT format('REVOKE CONNECT ON DATABASE %I FROM PUBLIC, registry_backup', datname)
FROM pg_database WHERE datname <> current_database() ORDER BY datname
\gexec
GRANT pg_read_all_stats TO registry_migrator;
REVOKE pg_read_all_stats FROM registry_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA registry AUTHORIZATION registry_migrator;
GRANT USAGE ON SCHEMA registry TO registry_app;
ALTER DEFAULT PRIVILEGES FOR ROLE registry_migrator IN SCHEMA registry
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, registry_app;
ALTER DEFAULT PRIVILEGES FOR ROLE registry_migrator IN SCHEMA registry
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, registry_app;
ALTER ROLE registry_migrator IN DATABASE registry SET search_path = registry;
ALTER ROLE registry_app IN DATABASE registry SET search_path = registry;
COMMIT;
SQL
unset REGISTRY_APP_PASSWORD
unset REGISTRY_MIGRATOR_PASSWORD
unset REGISTRY_BACKUP_PASSWORD
