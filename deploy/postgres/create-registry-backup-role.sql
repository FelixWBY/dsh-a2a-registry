\set ON_ERROR_STOP on

-- Restore bootstrap for a brand-new empty database on a dedicated Registry
-- PostgreSQL cluster. Run as its administrator. Passwords come from the
-- environment, never argv.
\getenv app_password REGISTRY_APP_PASSWORD
\getenv migrator_password REGISTRY_MIGRATOR_PASSWORD
\getenv backup_password REGISTRY_BACKUP_PASSWORD

begin;
select set_config('app.app_password', :'app_password', true);
select set_config('app.migrator_password', :'migrator_password', true);
select set_config('app.backup_password', :'backup_password', true);
do $guard$
begin
  if length(current_setting('app.app_password')) < 24
    or length(current_setting('app.migrator_password')) < 24
    or length(current_setting('app.backup_password')) < 24 then
    raise exception 'Registry restore passwords must each contain at least 24 characters';
  end if;
  if exists (
    select 1 from pg_stat_activity
    where datname = current_database() and pid <> pg_backend_pid()
      and backend_type = 'client backend'
      and usename in ('registry_app', 'registry_backup', 'registry_migrator')
  ) then
    raise exception 'Registry or backup database connections are still active';
  end if;
  if exists (
    select 1 from pg_database
    where datname <> current_database() and datname <> 'postgres' and not datistemplate
  ) then
    raise exception 'restore bootstrap requires a dedicated PostgreSQL cluster with no other user database';
  end if;
  if exists (
    select 1 from pg_namespace
    where nspname <> 'public' and nspname <> 'information_schema' and nspname !~ '^pg_'
  ) or exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname <> 'information_schema' and namespace.nspname !~ '^pg_'
      and relation.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
  ) then
    raise exception 'backup role bootstrap requires a new empty isolated database';
  end if;
end
$guard$;

select format(
  'create role registry_app login password %L nosuperuser nocreatedb nocreaterole noreplication nobypassrls',
  current_setting('app.app_password')
)
where not exists (select 1 from pg_roles where rolname = 'registry_app')
\gexec
select format(
  'alter role registry_app login password %L nosuperuser nocreatedb nocreaterole noreplication nobypassrls',
  current_setting('app.app_password')
)
\gexec
select format(
  'create role registry_migrator login password %L nosuperuser nocreatedb nocreaterole noreplication nobypassrls',
  current_setting('app.migrator_password')
)
where not exists (select 1 from pg_roles where rolname = 'registry_migrator')
\gexec
select format(
  'alter role registry_migrator login password %L nosuperuser nocreatedb nocreaterole noreplication nobypassrls',
  current_setting('app.migrator_password')
)
\gexec
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

select format('revoke %I from registry_app', parent.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where member.rolname = 'registry_app'
order by parent.rolname
\gexec
select format('revoke registry_app from %I', member.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where parent.rolname = 'registry_app'
order by member.rolname
\gexec
select format('revoke %I from registry_migrator', parent.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where member.rolname = 'registry_migrator' and parent.rolname <> 'pg_read_all_stats'
order by parent.rolname
\gexec
select format('revoke registry_migrator from %I', member.rolname)
from pg_auth_members as membership
join pg_roles as parent on parent.oid = membership.roleid
join pg_roles as member on member.oid = membership.member
where parent.rolname = 'registry_migrator'
order by member.rolname
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

select distinct case when defaults.defaclnamespace = 0 then format(
  'alter default privileges for role %I revoke all privileges on %s from registry_backup',
  owner.rolname, case defaults.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences' end)
else format(
  'alter default privileges for role %I in schema %I revoke all privileges on %s from registry_backup',
  owner.rolname, namespace.nspname,
  case defaults.defaclobjtype when 'r' then 'tables' when 'S' then 'sequences' end)
end
from pg_default_acl as defaults
join pg_roles as owner on owner.oid = defaults.defaclrole
left join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
cross join lateral aclexplode(defaults.defaclacl) as acl
where defaults.defaclobjtype in ('r', 'S')
  and acl.grantee = (select oid from pg_roles where rolname = 'registry_backup')
order by 1
\gexec

grant pg_read_all_stats to registry_migrator;
select format('revoke connect on database %I from public, registry_app, registry_migrator, registry_backup', datname)
from pg_database where datname <> current_database() order by datname
\gexec
select format('revoke all privileges on database %I from public, registry_app, registry_migrator, registry_backup', current_database()) \gexec
select format('grant connect on database %I to registry_app, registry_migrator, registry_backup', current_database()) \gexec

do $verify$
declare
  app_oid oid;
  backup_oid oid;
  migrator_oid oid;
begin
  select oid into app_oid from pg_roles
  where rolname = 'registry_app' and rolcanlogin and not rolsuper and not rolbypassrls
    and not rolcreatedb and not rolcreaterole and not rolreplication;
  select oid into migrator_oid from pg_roles
  where rolname = 'registry_migrator' and rolcanlogin and not rolsuper and not rolbypassrls
    and not rolcreatedb and not rolcreaterole and not rolreplication;
  select oid into backup_oid from pg_roles
  where rolname = 'registry_backup' and rolcanlogin and not rolinherit and rolconnlimit = 2
    and rolbypassrls and not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication;
  if app_oid is null or migrator_oid is null or backup_oid is null
    or exists (
      select 1 from pg_auth_members
      where member in (app_oid, backup_oid) or roleid in (app_oid, migrator_oid, backup_oid)
        or (member = migrator_oid and roleid <> (select oid from pg_roles where rolname = 'pg_read_all_stats'))
    )
    or not pg_has_role(migrator_oid, 'pg_read_all_stats', 'MEMBER')
    or not has_database_privilege(app_oid, current_database(), 'CONNECT')
    or not has_database_privilege(migrator_oid, current_database(), 'CONNECT')
    or not has_database_privilege(backup_oid, current_database(), 'CONNECT')
    or has_database_privilege(backup_oid, current_database(), 'CREATE')
    or has_database_privilege(backup_oid, current_database(), 'TEMP')
    or exists (
      select 1 from pg_database
      where datname <> current_database() and has_database_privilege(backup_oid, oid, 'CONNECT')
    )
    or exists (
      select 1 from pg_database
      where datname <> current_database() and datname <> 'postgres' and not datistemplate
    )
    or exists (
      select 1 from pg_default_acl as defaults
      cross join lateral aclexplode(defaults.defaclacl) as acl
      where acl.grantee = backup_oid
    ) then
    raise exception 'registry_backup role or database privileges are invalid';
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
end
$verify$;
commit;
