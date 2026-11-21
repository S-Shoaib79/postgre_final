-- See the tables the login fills.
--   & 'D:\postgres-dev\install\bin\psql.exe' -U postgres -d erms -f 'D:\postgres-dev\login-server\show_tables.sql'

-- Users: login_status 1 = signed in, 0 = signed out
SELECT t.org_code AS tenant, u.user_id, u.username, u.status, u.login_status
FROM user_accounts u JOIN tenants t USING (tenant_id)
ORDER BY u.user_id;

-- The keys the AM sent (filled at sign-in, emptied at sign-out)
SELECT u.username, k.tenant_id, k.type_id, k.asset_key
FROM user_asset_map k JOIN user_accounts u USING (user_id)
ORDER BY u.user_id, k.type_id;
