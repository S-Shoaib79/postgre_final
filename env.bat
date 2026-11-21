@echo off
set "PATH=D:\postgres-dev\install\bin;%PATH%"
set "PGDATA=D:\postgres-dev\data"
set "PGUSER=postgres"
set "PGDATABASE=postgres"
echo PostgreSQL environment variables set!
echo Added D:\postgres-dev\install\bin to PATH.
echo You can now run commands like: psql, pg_ctl, createdb, dropdb, pg_dump, etc.
cmd /k
