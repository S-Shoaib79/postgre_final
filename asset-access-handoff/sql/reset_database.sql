-- Reset the asset_access database to empty, so Flyway can create the
-- current schema from scratch on the app's next start.
--
-- DELETES ALL DATA in asset_access (tenants, users, API keys, admins, the role/asset map).
--
-- Run as the postgres superuser, with the app STOPPED:
--   psql -U postgres -f sql/reset_database.sql
-- or, inside psql:
--   \i 'C:/path/to/asset-access-handoff/sql/reset_database.sql'

\set ON_ERROR_STOP on

-- DROP/CREATE DATABASE cannot run on the database being dropped, so work from "postgres".
\c postgres

-- WITH (FORCE) disconnects any remaining sessions (PostgreSQL 13+).
drop database if exists asset_access with (force);

-- The app's login role. Created only if missing; its password is left unchanged.
select 'create role asset_access login'
where not exists (select 1 from pg_roles where rolname = 'asset_access')
\gexec

create database asset_access owner asset_access;

\echo ''
\echo 'asset_access has been recreated and is empty.'
\echo 'If the asset_access role was just created, set its password:  \\password asset_access'
\echo 'Then start the service again; it creates the tables and the platform admin.'
