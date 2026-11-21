-- Create the database and login role for the Asset Access Service.
--
-- Run once, as the postgres superuser, choosing a password for the app's role:
--   psql -U postgres -v app_password=YOUR-PASSWORD -f sql/create_database.sql
--
-- Put the same password in config/application.yml (spring.datasource.password).
-- The service creates its tables itself (Flyway) on its first start.
-- Safe to run again: an existing role keeps its password, an existing database is kept.

\set ON_ERROR_STOP on

\if :{?app_password}
\else
  \echo 'Missing password. Run: psql -U postgres -v app_password=YOUR-PASSWORD -f sql/create_database.sql'
  \quit
\endif

\c postgres

select format('create role asset_access login password %L', :'app_password')
where not exists (select 1 from pg_roles where rolname = 'asset_access')
\gexec

select 'create database asset_access owner asset_access'
where not exists (select 1 from pg_database where datname = 'asset_access')
\gexec

\echo ''
\echo 'Done: role asset_access and database asset_access exist.'
\echo 'If the role already existed, its password was NOT changed. To change it: \\password asset_access'
\echo 'Next: put the password in config/application.yml and start the service.'
