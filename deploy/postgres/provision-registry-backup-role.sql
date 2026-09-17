\set ON_ERROR_STOP on

-- Run as the database administrator while every Registry process using this
-- database is stopped. Required psql variable: target_schema.
-- The password is read from REGISTRY_BACKUP_PASSWORD, never from argv.
\if :{?target_schema}
\else
  \echo 'target_schema is required'
  \quit 3
\endif
\getenv backup_password REGISTRY_BACKUP_PASSWORD

begin;
set local lock_timeout = '2s';
select set_config('app.backup_schema', :'target_schema', true);
select set_config('app.backup_password', :'backup_password', true);

do $guard$
declare
  target_schema text := current_setting('app.backup_schema');
  backup_password text := current_setting('app.backup_password');
begin
  if target_schema !~ '^[a-z][a-z0-9_]*$' then
    raise exception 'invalid target schema';
  end if;
  if length(backup_password) < 24 then
    raise exception 'REGISTRY_BACKUP_PASSWORD must contain at least 24 characters';
  end if;
  if not exists (
    select 1 from pg_namespace where nspname = target_schema
      and pg_get_userbyid(nspowner) = 'registry_migrator'
  ) then
    raise exception 'target schema must exist and be owned by registry_migrator';
  end if;
  if not pg_try_advisory_xact_lock(hashtextextended('dsh-registry-schema:' || target_schema, 0)) then
    raise exception 'another offline operation is using the target schema';
  end if;
  if exists (
    select 1 from pg_stat_activity
    where datname = current_database() and pid <> pg_backend_pid()
      and backend_type = 'client backend'
      and (usename in ('registry_app', 'registry_backup', 'registry_migrator')
        or application_name in ('dsh-a2a-registry', 'dsh-a2a-registry-tenancy'))
  ) then
    raise exception 'Registry or backup database connections are still active';
  end if;
  if exists (
    select 1 from pg_database
    where datname <> current_database() and datname <> 'postgres' and not datistemplate
  ) then
    raise exception 'backup provisioning requires a dedicated PostgreSQL cluster with no other user database';
  end if;
end
$guard$;

select format(
  'create role registry_backup login noinherit connection limit 2 password %L nosuperuser nocreatedb nocreaterole noreplication bypassrls',
  current_setting('app.backup_password')
)
where not exists (select 1 from pg_roles where rolname = 'registry_backup')
\gexec

select format(
  'alter role registry_backup login noinherit connection limit 2 password %L nosuperuser nocreatedb nocreaterole noreplication bypassrls',
  current_setting('app.backup_password')
)
\gexec

select format('revoke %I from registry_backup', parent.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where member.rolname = 'registry_backup'
order by parent.rolname
\gexec

select format('revoke registry_backup from %I', member.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where parent.rolname = 'registry_backup'
order by member.rolname
\gexec

select format('revoke connect on database %I from public, registry_backup', datname)
from pg_database where datname <> current_database() order by datname
\gexec
select format('revoke all privileges on database %I from public, registry_backup', current_database()) \gexec
select format('grant connect on database %I to registry_app, registry_migrator, registry_backup', current_database()) \gexec

select format('revoke all privileges on all tables in schema %I from public, registry_backup', namespace.nspname)
from pg_namespace as namespace
where namespace.nspname <> :'target_schema'
  and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
order by namespace.nspname
\gexec
select format('revoke all privileges on all sequences in schema %I from public, registry_backup', namespace.nspname)
from pg_namespace as namespace
where namespace.nspname <> :'target_schema'
  and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
order by namespace.nspname
\gexec
select format('revoke all privileges on schema %I from public, registry_backup', namespace.nspname)
from pg_namespace as namespace
where namespace.nspname <> :'target_schema'
  and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
order by namespace.nspname
\gexec
-- Revoke every supported default ACL entry for registry_backup before installing
-- the two exact target-schema grants below. defaclnamespace = 0 is a global
-- default and therefore has no pg_namespace row; keep the LEFT JOIN and omit
-- IN SCHEMA for those entries.
select distinct case when defaults.defaclnamespace = 0 then format(
  'alter default privileges for role %I revoke all privileges on %s from registry_backup',
  owner.rolname, case defaults.defaclobjtype
    when 'r' then 'tables'
    when 'S' then 'sequences'
    when 'f' then 'functions'
    when 'T' then 'types'
    when 'n' then 'schemas'
    when 'L' then 'large objects'
  end)
else format(
  'alter default privileges for role %I in schema %I revoke all privileges on %s from registry_backup',
  owner.rolname, namespace.nspname,
  case defaults.defaclobjtype
    when 'r' then 'tables'
    when 'S' then 'sequences'
    when 'f' then 'functions'
    when 'T' then 'types'
  end)
end
from pg_default_acl as defaults
join pg_roles as owner on owner.oid = defaults.defaclrole
left join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
cross join lateral aclexplode(defaults.defaclacl) as acl
where defaults.defaclobjtype in ('r', 'S', 'f', 'T', 'n', 'L')
  and acl.grantee = (select oid from pg_roles where rolname = 'registry_backup')
  and (defaults.defaclnamespace = 0 or defaults.defaclobjtype not in ('n', 'L'))
order by 1
\gexec

select format('revoke %s (%s) on table %I.%I from registry_backup',
  lower(acl.privilege_type), string_agg(quote_ident(attribute.attname), ', ' order by attribute.attnum),
  namespace.nspname, relation.relname)
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
join pg_attribute as attribute on attribute.attrelid = relation.oid
  and attribute.attnum > 0 and not attribute.attisdropped
cross join lateral aclexplode(attribute.attacl) as acl
where namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
  and relation.relkind in ('r', 'p', 'v', 'm', 'f')
  and acl.grantee = (select oid from pg_roles where rolname = 'registry_backup')
group by acl.privilege_type, namespace.nspname, relation.relname
order by namespace.nspname, relation.relname, acl.privilege_type
\gexec

revoke all privileges on schema :"target_schema" from public, registry_backup;
grant usage on schema :"target_schema" to registry_backup;
revoke all privileges on all tables in schema :"target_schema" from public, registry_backup;
grant select on all tables in schema :"target_schema" to registry_backup;
revoke all privileges on all sequences in schema :"target_schema" from public, registry_backup;
grant select on all sequences in schema :"target_schema" to registry_backup;

alter default privileges for role registry_migrator in schema :"target_schema"
  revoke all privileges on tables from registry_backup;
alter default privileges for role registry_migrator in schema :"target_schema"
  grant select on tables to registry_backup;
alter default privileges for role registry_migrator in schema :"target_schema"
  revoke all privileges on sequences from registry_backup;
alter default privileges for role registry_migrator in schema :"target_schema"
  grant select on sequences to registry_backup;

do $verify$
declare
  target_schema text := current_setting('app.backup_schema');
  backup_oid oid;
  default_acl_count bigint;
  allowed_default_acl_count bigint;
  allowed_default_acl_types bigint;
begin
  select oid into backup_oid from pg_roles
  where rolname = 'registry_backup' and rolcanlogin and not rolinherit and rolconnlimit = 2
    and rolbypassrls and not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication;
  if backup_oid is null then
    raise exception 'registry_backup role attributes are invalid';
  end if;
  if exists (select 1 from pg_auth_members where member = backup_oid or roleid = backup_oid) then
    raise exception 'registry_backup must have no inbound or outbound role memberships';
  end if;
  if not has_database_privilege(backup_oid, current_database(), 'CONNECT')
    or has_database_privilege(backup_oid, current_database(), 'CREATE')
    or has_database_privilege(backup_oid, current_database(), 'TEMP')
    or exists (
      select 1 from pg_database
      where datname <> current_database() and has_database_privilege(backup_oid, oid, 'CONNECT')
    )
    or exists (
      select 1 from pg_database
      where datname <> current_database() and datname <> 'postgres' and not datistemplate
    ) then
    raise exception 'registry_backup database privileges are invalid';
  end if;
  if not exists (
    select 1 from pg_database as database
    cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) as acl
    where database.datname = current_database() and acl.grantee = backup_oid
      and acl.privilege_type = 'CONNECT' and not acl.is_grantable
  ) or exists (
    select 1 from pg_database as database
    cross join lateral aclexplode(coalesce(database.datacl, acldefault('d', database.datdba))) as acl
    where database.datname = current_database() and acl.grantee = backup_oid
      and (acl.privilege_type <> 'CONNECT' or acl.is_grantable)
  ) then
    raise exception 'registry_backup database ACL is invalid';
  end if;
  if not has_schema_privilege(backup_oid, target_schema, 'USAGE')
    or has_schema_privilege(backup_oid, target_schema, 'CREATE')
    or not exists (
      select 1 from pg_namespace as namespace
      cross join lateral aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) as acl
      where namespace.nspname = target_schema and acl.grantee = backup_oid
        and acl.privilege_type = 'USAGE' and not acl.is_grantable
    ) or exists (
      select 1 from pg_namespace as namespace
      cross join lateral aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) as acl
      where namespace.nspname = target_schema and acl.grantee = backup_oid
        and (acl.privilege_type <> 'USAGE' or acl.is_grantable)
    ) then
    raise exception 'registry_backup target schema privileges are invalid';
  end if;
  if exists (
    select 1 from pg_namespace as namespace
    where namespace.nspname <> target_schema
      and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
      and (has_schema_privilege(backup_oid, namespace.oid, 'USAGE')
        or has_schema_privilege(backup_oid, namespace.oid, 'CREATE'))
  ) then
    raise exception 'registry_backup can access a non-target schema';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p', 'v', 'm', 'f')
      and (not has_table_privilege(backup_oid, relation.oid, 'SELECT')
        or not exists (
          select 1 from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) as acl
          where acl.grantee = backup_oid and acl.privilege_type = 'SELECT' and not acl.is_grantable
        )
        or exists (
          select 1 from aclexplode(coalesce(relation.relacl, acldefault('r', relation.relowner))) as acl
          where acl.grantee = backup_oid and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
        )
        or has_table_privilege(backup_oid, relation.oid, 'INSERT')
        or has_table_privilege(backup_oid, relation.oid, 'UPDATE')
        or has_table_privilege(backup_oid, relation.oid, 'DELETE')
        or has_table_privilege(backup_oid, relation.oid, 'TRUNCATE')
        or has_table_privilege(backup_oid, relation.oid, 'REFERENCES')
        or has_table_privilege(backup_oid, relation.oid, 'TRIGGER')
        or has_table_privilege(backup_oid, relation.oid, 'MAINTAIN'))
  ) or exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname <> target_schema
      and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
      and relation.relkind in ('r', 'p', 'v', 'm', 'f')
      and (has_table_privilege(backup_oid, relation.oid, 'SELECT')
        or has_table_privilege(backup_oid, relation.oid, 'INSERT')
        or has_table_privilege(backup_oid, relation.oid, 'UPDATE')
        or has_table_privilege(backup_oid, relation.oid, 'DELETE')
        or has_table_privilege(backup_oid, relation.oid, 'TRUNCATE')
        or has_table_privilege(backup_oid, relation.oid, 'REFERENCES')
        or has_table_privilege(backup_oid, relation.oid, 'TRIGGER')
        or has_table_privilege(backup_oid, relation.oid, 'MAINTAIN')
        or has_any_column_privilege(backup_oid, relation.oid, 'SELECT')
        or has_any_column_privilege(backup_oid, relation.oid, 'INSERT')
        or has_any_column_privilege(backup_oid, relation.oid, 'UPDATE')
        or has_any_column_privilege(backup_oid, relation.oid, 'REFERENCES'))
  ) then
    raise exception 'registry_backup relation privileges are not target-only SELECT';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    join pg_attribute as attribute on attribute.attrelid = relation.oid
      and attribute.attnum > 0 and not attribute.attisdropped
    cross join lateral aclexplode(attribute.attacl) as acl
    where namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
      and acl.grantee = backup_oid
  ) then
    raise exception 'registry_backup must not have column ACLs';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind = 'S'
      and (not has_sequence_privilege(backup_oid, relation.oid, 'SELECT')
        or not exists (
          select 1 from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) as acl
          where acl.grantee = backup_oid and acl.privilege_type = 'SELECT' and not acl.is_grantable
        )
        or exists (
          select 1 from aclexplode(coalesce(relation.relacl, acldefault('S', relation.relowner))) as acl
          where acl.grantee = backup_oid and (acl.privilege_type <> 'SELECT' or acl.is_grantable)
        )
        or has_sequence_privilege(backup_oid, relation.oid, 'USAGE')
        or has_sequence_privilege(backup_oid, relation.oid, 'UPDATE'))
  ) or exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname <> target_schema
      and namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
      and relation.relkind = 'S'
      and (has_sequence_privilege(backup_oid, relation.oid, 'SELECT')
        or has_sequence_privilege(backup_oid, relation.oid, 'USAGE')
        or has_sequence_privilege(backup_oid, relation.oid, 'UPDATE'))
  ) then
    raise exception 'registry_backup sequence privileges are not target-only SELECT';
  end if;
  -- LEFT JOIN is required: global defaults use defaclnamespace = 0 and must be
  -- counted as invalid instead of disappearing from the verification query.
  select count(*),
    count(*) filter (where defaults.defaclnamespace <> 0
      and owner.rolname = 'registry_migrator'
      and namespace.nspname = target_schema
      and defaults.defaclobjtype in ('r', 'S')
      and acl.privilege_type = 'SELECT' and not acl.is_grantable),
    count(distinct defaults.defaclobjtype) filter (where defaults.defaclnamespace <> 0
      and owner.rolname = 'registry_migrator'
      and namespace.nspname = target_schema
      and defaults.defaclobjtype in ('r', 'S')
      and acl.privilege_type = 'SELECT' and not acl.is_grantable)
  into default_acl_count, allowed_default_acl_count, allowed_default_acl_types
  from pg_default_acl as defaults
  left join pg_roles as owner on owner.oid = defaults.defaclrole
  left join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
  cross join lateral aclexplode(defaults.defaclacl) as acl
  where acl.grantee = backup_oid;
  if default_acl_count <> 2 or allowed_default_acl_count <> 2
    or allowed_default_acl_types <> 2 then
    raise exception 'registry_backup default privileges are not target-only SELECT';
  end if;
end
$verify$;

commit;
