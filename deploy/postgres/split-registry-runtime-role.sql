\set ON_ERROR_STOP on

-- Run only while every Registry process using this database is stopped.
-- Required psql variable: target_schema (for example registry_saas_local).
\if :{?target_schema}
\else
  \echo 'target_schema is required'
  \quit 3
\endif

begin;
set local lock_timeout = '2s';
select set_config('app.role_split_schema', :'target_schema', true);

do $guard$
declare
  target_schema text := current_setting('app.role_split_schema');
begin
  if target_schema !~ '^[a-z][a-z0-9_]*$' then
    raise exception 'invalid target schema';
  end if;
  if not exists (select 1 from pg_namespace where nspname = target_schema) then
    raise exception 'target schema does not exist';
  end if;
  if not pg_try_advisory_xact_lock(hashtextextended('dsh-registry-schema:' || target_schema, 0)) then
    raise exception 'another offline operation is changing the target schema';
  end if;
  if not exists (select 1 from pg_roles where rolname = 'registry_migrator')
    or not exists (select 1 from pg_roles where rolname = 'registry_app')
    or not exists (
      select 1 from pg_roles
      where rolname = 'registry_backup' and rolcanlogin and not rolinherit and rolconnlimit = 2
        and rolbypassrls and not rolsuper and not rolcreatedb and not rolcreaterole and not rolreplication
    ) then
    raise exception 'exact registry_migrator, registry_app, and registry_backup roles are required';
  end if;
  if exists (
    select 1
    from pg_roles as base_role
    join pg_roles as reachable_role on reachable_role.rolname = base_role.rolname
      or pg_has_role(base_role.oid, reachable_role.oid, 'MEMBER')
      or pg_has_role(base_role.oid, reachable_role.oid, 'SET')
    where base_role.rolname in ('registry_migrator', 'registry_app')
      and (reachable_role.rolsuper or reachable_role.rolbypassrls or reachable_role.rolcreatedb
        or reachable_role.rolcreaterole or reachable_role.rolreplication
        or (reachable_role.rolname <> base_role.rolname
          and not (base_role.rolname = 'registry_migrator'
            and reachable_role.rolname = 'pg_read_all_stats')))
  ) then
    raise exception 'Registry database roles must not have cluster administration, replication, or BYPASSRLS';
  end if;
  if exists (
    select 1 from pg_auth_members as membership
    join pg_roles as backup on backup.rolname = 'registry_backup'
    where membership.member = backup.oid or membership.roleid = backup.oid
  ) or has_database_privilege('registry_backup', current_database(), 'CREATE')
    or has_database_privilege('registry_backup', current_database(), 'TEMP') then
    raise exception 'registry_backup must have no role memberships, CREATE, or TEMP privilege';
  end if;
  if exists (
    select 1 from pg_stat_activity
    where datname = current_database() and pid <> pg_backend_pid()
      and backend_type = 'client backend'
      and (usename in ('registry_app', 'registry_backup', 'registry_migrator')
        or application_name in ('dsh-a2a-registry', 'dsh-a2a-registry-tenancy'))
  ) then
    raise exception 'Registry database connections are still active';
  end if;
end
$guard$;

select format('alter schema %I owner to registry_migrator', :'target_schema') \gexec
select format('alter table %I.%I owner to registry_migrator', namespace.nspname, relation.relname)
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
where namespace.nspname = :'target_schema' and relation.relkind in ('r', 'p')
order by relation.relname
\gexec
select format('alter sequence %I.%I owner to registry_migrator', namespace.nspname, relation.relname)
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
where namespace.nspname = :'target_schema' and relation.relkind = 'S'
order by relation.relname
\gexec

revoke registry_migrator from registry_app;
revoke registry_app from registry_migrator;
revoke registry_backup from registry_app, registry_migrator;
revoke registry_app, registry_migrator from registry_backup;
grant pg_read_all_stats to registry_migrator;
revoke pg_read_all_stats from registry_app;
select format(
  'revoke create, temporary on database %I from public, registry_app, registry_migrator, registry_backup',
  current_database())
\gexec
revoke all on schema :"target_schema" from public, registry_app;
grant usage on schema :"target_schema" to registry_app;
revoke all privileges on all tables in schema :"target_schema" from public, registry_app;
revoke all privileges on all sequences in schema :"target_schema" from public, registry_app;

select format(
  'grant select on table %I.%I to registry_app',
  namespace.nspname, relation.relname
)
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
where namespace.nspname = :'target_schema' and relation.relkind in ('r', 'p')
  and relation.relname in ('storage_meta', 'tenancy_meta')
order by relation.relname
\gexec

select format(
  'grant select, insert, update, delete on table %I.%I to registry_app',
  namespace.nspname, relation.relname
)
from pg_class as relation
join pg_namespace as namespace on namespace.oid = relation.relnamespace
where namespace.nspname = :'target_schema' and relation.relkind in ('r', 'p')
  and relation.relname in (
    'units', 'unit_globals', 'unit_records',
    'accounts', 'account_identities', 'organizations', 'organization_memberships',
    'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events'
  )
order by relation.relname
\gexec

do $columns$
declare
  relation record;
  columns text;
begin
  for relation in
    select namespace.nspname, class.relname, class.oid
    from pg_class as class
    join pg_namespace as namespace on namespace.oid = class.relnamespace
    where namespace.nspname = current_setting('app.role_split_schema')
      and class.relkind in ('r', 'p')
  loop
    select string_agg(format('%I', attribute.attname), ', ' order by attribute.attnum)
      into columns
    from pg_attribute as attribute
    where attribute.attrelid = relation.oid and attribute.attnum > 0 and not attribute.attisdropped;
    if columns is not null then
      execute format('revoke select (%s) on table %I.%I from registry_app',
        columns, relation.nspname, relation.relname);
      execute format('revoke insert (%s) on table %I.%I from registry_app',
        columns, relation.nspname, relation.relname);
      execute format('revoke update (%s) on table %I.%I from registry_app',
        columns, relation.nspname, relation.relname);
      execute format('revoke references (%s) on table %I.%I from registry_app',
        columns, relation.nspname, relation.relname);
    end if;
  end loop;
end
$columns$;

alter default privileges for role registry_migrator in schema :"target_schema"
  revoke all privileges on tables from public, registry_app;
alter default privileges for role registry_migrator in schema :"target_schema"
  revoke all privileges on sequences from public, registry_app;

do $verify$
declare
  target_schema text := current_setting('app.role_split_schema');
  app_oid oid;
  backup_oid oid;
  backup_enabled boolean;
  migrator_oid oid;
begin
  select oid into app_oid from pg_roles where rolname = 'registry_app';
  select oid into backup_oid from pg_roles where rolname = 'registry_backup';
  select oid into migrator_oid from pg_roles where rolname = 'registry_migrator';
  select exists (
    select 1 from pg_namespace as namespace
    cross join lateral aclexplode(coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))) as acl
    where namespace.nspname = target_schema and acl.grantee = backup_oid
      and acl.privilege_type = 'USAGE' and not acl.is_grantable
  ) into backup_enabled;
  if exists (
    select 1 from pg_roles as role
    where (pg_has_role('registry_app', role.oid, 'MEMBER') or pg_has_role('registry_app', role.oid, 'SET'))
      and (role.rolname <> 'registry_app'
        or role.rolsuper or role.rolbypassrls or role.rolcreatedb or role.rolcreaterole
        or role.rolreplication or role.rolname = 'pg_read_all_stats'
        or has_database_privilege(role.oid, current_database(), 'CREATE')
        or has_database_privilege(role.oid, current_database(), 'TEMP')
        or has_schema_privilege(role.oid, target_schema, 'CREATE'))
  ) then
    raise exception 'registry_app or a reachable role still has unsafe runtime privileges';
  end if;
  if not exists (
    select 1 from pg_namespace as namespace
    where namespace.nspname = target_schema and namespace.nspowner = migrator_oid
  ) then
    raise exception 'Target schema must be owned by registry_migrator';
  end if;
  if exists (
    select 1
    from pg_namespace as namespace
    cross join lateral aclexplode(
      coalesce(namespace.nspacl, acldefault('n', namespace.nspowner))
    ) as acl
    where namespace.nspname = target_schema
      and (acl.grantee not in (migrator_oid, app_oid, backup_oid)
        or (acl.grantee = app_oid
          and (acl.privilege_type <> 'USAGE' or acl.is_grantable))
        or (acl.grantee = backup_oid
          and (not backup_enabled or acl.privilege_type <> 'USAGE' or acl.is_grantable)))
  ) then
    raise exception 'Target schema ACL contains an unknown or inexact Registry grant';
  end if;
  if (backup_enabled and (not has_schema_privilege(backup_oid, target_schema, 'USAGE')
      or has_schema_privilege(backup_oid, target_schema, 'CREATE')))
    or (not backup_enabled and (has_schema_privilege(backup_oid, target_schema, 'USAGE')
      or has_schema_privilege(backup_oid, target_schema, 'CREATE'))) then
    raise exception 'registry_backup schema access is partial or unsafe';
  end if;
  if exists (
    select 1
    from pg_default_acl as defaults
    join pg_roles as owner on owner.oid = defaults.defaclrole
    left join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
    cross join lateral aclexplode(defaults.defaclacl) as acl
    where acl.grantee = backup_oid
      and (defaults.defaclnamespace = 0
        or owner.rolname <> 'registry_migrator'
        or defaults.defaclobjtype not in ('r', 'S')
        or acl.privilege_type <> 'SELECT' or acl.is_grantable
        or ((namespace.nspname is not distinct from target_schema) <> backup_enabled))
  ) or (backup_enabled and (
    select count(distinct defaults.defaclobjtype)
    from pg_default_acl as defaults
    join pg_roles as owner on owner.oid = defaults.defaclrole
    join pg_namespace as namespace on namespace.oid = defaults.defaclnamespace
    cross join lateral aclexplode(defaults.defaclacl) as acl
    where owner.rolname = 'registry_migrator' and namespace.nspname = target_schema
      and defaults.defaclobjtype in ('r', 'S') and acl.grantee = backup_oid
      and acl.privilege_type = 'SELECT' and not acl.is_grantable
  ) <> 2) then
    raise exception 'registry_backup default privileges are partial or unsafe';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p', 'v', 'm', 'f', 'S')
      and relation.relowner <> migrator_oid
  ) then
    raise exception 'Every target table and sequence must be owned by registry_migrator';
  end if;
  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    cross join lateral aclexplode(
      coalesce(relation.relacl, acldefault('r', relation.relowner))
    ) as acl
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p', 'v', 'm', 'f')
      and (acl.grantee not in (migrator_oid, app_oid, backup_oid)
        or (acl.grantee = app_oid and (
          acl.is_grantable
          or case
            when relation.relname in ('storage_meta', 'tenancy_meta')
              then acl.privilege_type <> 'SELECT'
            when relation.relname in (
              'units', 'unit_globals', 'unit_records',
              'accounts', 'account_identities', 'organizations', 'organization_memberships',
              'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events'
            ) then acl.privilege_type not in ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
            else true
          end
        ))
        or (acl.grantee = backup_oid and (
          not backup_enabled or acl.is_grantable or acl.privilege_type <> 'SELECT'
        )))
  ) then
    raise exception 'Target table ACL contains an unknown or inexact Registry grant';
  end if;
  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p', 'v', 'm', 'f')
      and case when backup_enabled then
        not has_table_privilege(backup_oid, relation.oid, 'SELECT')
        or has_table_privilege(backup_oid, relation.oid, 'INSERT')
        or has_table_privilege(backup_oid, relation.oid, 'UPDATE')
        or has_table_privilege(backup_oid, relation.oid, 'DELETE')
        or has_table_privilege(backup_oid, relation.oid, 'TRUNCATE')
        or has_table_privilege(backup_oid, relation.oid, 'REFERENCES')
        or has_table_privilege(backup_oid, relation.oid, 'TRIGGER')
        or has_table_privilege(backup_oid, relation.oid, 'MAINTAIN')
      else
        has_table_privilege(backup_oid, relation.oid, 'SELECT')
        or has_table_privilege(backup_oid, relation.oid, 'INSERT')
        or has_table_privilege(backup_oid, relation.oid, 'UPDATE')
        or has_table_privilege(backup_oid, relation.oid, 'DELETE')
        or has_table_privilege(backup_oid, relation.oid, 'TRUNCATE')
        or has_table_privilege(backup_oid, relation.oid, 'REFERENCES')
        or has_table_privilege(backup_oid, relation.oid, 'TRIGGER')
        or has_table_privilege(backup_oid, relation.oid, 'MAINTAIN')
      end
  ) then
    raise exception 'registry_backup table access is partial or unsafe';
  end if;
  if exists (
    select 1
    from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    join pg_attribute as attribute on attribute.attrelid = relation.oid
      and attribute.attnum > 0 and not attribute.attisdropped
    cross join lateral aclexplode(attribute.attacl) as acl
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p', 'v', 'm', 'f')
      and acl.grantee <> migrator_oid
  ) then
    raise exception 'Target column ACL contains a registry_app, PUBLIC, or old-role grant';
  end if;
  if exists (
    select 1
    from pg_sequence as sequence
    join pg_class as relation on relation.oid = sequence.seqrelid
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    cross join lateral aclexplode(
      coalesce(relation.relacl, acldefault('S', relation.relowner))
    ) as acl
    where namespace.nspname = target_schema
      and (acl.grantee not in (migrator_oid, backup_oid)
        or (acl.grantee = backup_oid
          and (not backup_enabled or acl.privilege_type <> 'SELECT' or acl.is_grantable)))
  ) or exists (
    select 1
    from pg_sequence as sequence
    join pg_class as relation on relation.oid = sequence.seqrelid
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema
      and (has_sequence_privilege('registry_app', sequence.seqrelid, 'USAGE, SELECT, UPDATE')
        or (backup_enabled and (
          not has_sequence_privilege(backup_oid, sequence.seqrelid, 'SELECT')
          or has_sequence_privilege(backup_oid, sequence.seqrelid, 'USAGE')
          or has_sequence_privilege(backup_oid, sequence.seqrelid, 'UPDATE')
        ))
        or (not backup_enabled
          and has_sequence_privilege(backup_oid, sequence.seqrelid, 'USAGE, SELECT, UPDATE')))
  ) then
    raise exception 'Target sequence ACL is not exact for Registry roles';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p')
      and relation.relname in ('storage_meta', 'tenancy_meta')
      and (not has_table_privilege('registry_app', relation.oid, 'SELECT')
        or has_table_privilege('registry_app', relation.oid, 'INSERT')
        or has_table_privilege('registry_app', relation.oid, 'UPDATE')
        or has_table_privilege('registry_app', relation.oid, 'DELETE')
        or has_table_privilege('registry_app', relation.oid, 'TRUNCATE')
        or has_table_privilege('registry_app', relation.oid, 'REFERENCES')
        or has_table_privilege('registry_app', relation.oid, 'TRIGGER')
        or has_table_privilege('registry_app', relation.oid, 'MAINTAIN')
        or has_any_column_privilege('registry_app', relation.oid, 'INSERT')
        or has_any_column_privilege('registry_app', relation.oid, 'UPDATE')
        or has_any_column_privilege('registry_app', relation.oid, 'REFERENCES'))
  ) then
    raise exception 'Registry metadata tables are not runtime read-only';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p')
      and relation.relname in (
        'units', 'unit_globals', 'unit_records',
        'accounts', 'account_identities', 'organizations', 'organization_memberships',
        'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events'
      )
      and (not has_table_privilege('registry_app', relation.oid, 'SELECT')
        or not has_table_privilege('registry_app', relation.oid, 'INSERT')
        or not has_table_privilege('registry_app', relation.oid, 'UPDATE')
        or not has_table_privilege('registry_app', relation.oid, 'DELETE')
        or has_table_privilege('registry_app', relation.oid, 'TRUNCATE')
        or has_table_privilege('registry_app', relation.oid, 'REFERENCES')
        or has_table_privilege('registry_app', relation.oid, 'TRIGGER')
        or has_table_privilege('registry_app', relation.oid, 'MAINTAIN')
        or has_any_column_privilege('registry_app', relation.oid, 'REFERENCES'))
  ) then
    raise exception 'Registry business tables do not have the exact runtime privilege set';
  end if;
  if exists (
    select 1 from pg_class as relation
    join pg_namespace as namespace on namespace.oid = relation.relnamespace
    where namespace.nspname = target_schema and relation.relkind in ('r', 'p')
      and relation.relname not in (
        'storage_meta', 'tenancy_meta',
        'units', 'unit_globals', 'unit_records',
        'accounts', 'account_identities', 'organizations', 'organization_memberships',
        'organization_creations', 'organization_invitations', 'billing_orders', 'billing_provider_events'
      )
      and (has_table_privilege('registry_app', relation.oid,
          'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN')
        or has_any_column_privilege('registry_app', relation.oid, 'SELECT')
        or has_any_column_privilege('registry_app', relation.oid, 'INSERT')
        or has_any_column_privilege('registry_app', relation.oid, 'UPDATE')
        or has_any_column_privilege('registry_app', relation.oid, 'REFERENCES'))
  ) then
    raise exception 'Registry runtime role has privileges on an unknown table';
  end if;
end
$verify$;

commit;
