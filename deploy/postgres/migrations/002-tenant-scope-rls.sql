\set ON_ERROR_STOP on

-- Offline recovery/operator migration for a populated schema-v1 database.
-- Invoke with: psql --set=legacy_tenant_id='the-explicit-tenant' --file=...
\if :{?legacy_tenant_id}
\else
  \echo 'legacy_tenant_id is required; refusing to guess from retained JSON'
  \quit 3
\endif

begin;
select set_config('app.migration_legacy_tenant_id', :'legacy_tenant_id', true);

do $migration_check$
begin
  if (select schema_version from registry.storage_meta where singleton = true) is distinct from 1 then
    raise exception 'expected PostgreSQL storage schema version 1';
  end if;
end
$migration_check$;

alter table registry.units add column tenant_id text;
alter table registry.unit_globals add column tenant_id text;
alter table registry.unit_records add column tenant_id text;

update registry.units
set tenant_id = current_setting('app.migration_legacy_tenant_id');
update registry.unit_globals
set tenant_id = current_setting('app.migration_legacy_tenant_id');
update registry.unit_records
set tenant_id = current_setting('app.migration_legacy_tenant_id');

alter table registry.units alter column tenant_id set not null;
alter table registry.unit_globals alter column tenant_id set not null;
alter table registry.unit_records alter column tenant_id set not null;

alter table registry.unit_globals drop constraint unit_globals_unit_fkey;
alter table registry.unit_records drop constraint unit_records_unit_fkey;
alter table registry.unit_globals drop constraint unit_globals_pkey;
alter table registry.unit_records drop constraint unit_records_pkey;
alter table registry.units drop constraint units_pkey;

alter table registry.units
  add constraint units_pkey primary key (tenant_id, name);
alter table registry.unit_globals
  add constraint unit_globals_pkey primary key (tenant_id, unit),
  add constraint unit_globals_unit_fkey foreign key (tenant_id, unit)
    references registry.units (tenant_id, name) on delete cascade;
alter table registry.unit_records
  add constraint unit_records_pkey primary key (tenant_id, unit, table_name, key),
  add constraint unit_records_unit_fkey foreign key (tenant_id, unit)
    references registry.units (tenant_id, name) on delete cascade;

alter table registry.units enable row level security;
alter table registry.units force row level security;
drop policy if exists tenant_isolation on registry.units;
create policy tenant_isolation on registry.units
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

alter table registry.unit_globals enable row level security;
alter table registry.unit_globals force row level security;
drop policy if exists tenant_isolation on registry.unit_globals;
create policy tenant_isolation on registry.unit_globals
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

alter table registry.unit_records enable row level security;
alter table registry.unit_records force row level security;
drop policy if exists tenant_isolation on registry.unit_records;
create policy tenant_isolation on registry.unit_records
  using (tenant_id = current_setting('app.tenant_id', true))
  with check (tenant_id = current_setting('app.tenant_id', true));

update registry.storage_meta set schema_version = 2 where singleton = true;
commit;
