#!/usr/bin/env bash
set -e

export REGISTRY_APP_PASSWORD="$(cat /run/secrets/postgres_app_password)"
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv app_password REGISTRY_APP_PASSWORD
CREATE ROLE registry_app LOGIN PASSWORD :'app_password'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON DATABASE registry FROM PUBLIC;
GRANT CONNECT ON DATABASE registry TO registry_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA registry AUTHORIZATION registry_app;
ALTER ROLE registry_app IN DATABASE registry SET search_path = registry;
SQL
unset REGISTRY_APP_PASSWORD
