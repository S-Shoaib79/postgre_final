-- Check that Flyway created the current schema. Run after the app's first start:
--   psql -U asset_access -d asset_access -f sql/check_database.sql
-- or, inside psql:
--   \i 'C:/path/to/asset-access-handoff/sql/check_database.sql'

\echo '--- Migrations applied (expect versions 1 to 6, success = t)'
select version, description, success, installed_on
from flyway_schema_history
order by installed_rank;

\echo '--- Tables (expect 11 app_* tables plus flyway_schema_history)'
\dt

\echo '--- Tenant admin usernames: unique per tenant (expect uq_app_tenant_admins_tenant_username)'
select conname, pg_get_constraintdef(oid) as definition
from pg_constraint
where conrelid = 'app_tenant_admins'::regclass and contype = 'u';

\echo '--- Immutability triggers on the role/asset map (expect 15)'
select count(*) as triggers
from pg_trigger
where not tgisinternal
  and tgrelid in ('app_roles'::regclass, 'app_assets'::regclass,
                  'app_roles_assets_map'::regclass, 'app_setup'::regclass);

\echo '--- Users cannot be deleted (expect app_users_no_delete and app_users_no_truncate)'
select tgname from pg_trigger where tgrelid = 'app_users'::regclass and not tgisinternal order by 1;

\echo '--- Asset values: size limit (expect ck_app_tenant_asset_values_size, <= 128 bytes)'
select conname, pg_get_constraintdef(oid) from pg_constraint
where conrelid = 'app_tenant_asset_values'::regclass and contype = 'c';

\echo '--- Platform admins (expect admin, created on first start)'
select id, username, enabled from app_platform_admins;
