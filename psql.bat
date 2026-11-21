@echo off
set "PGBIN=D:\postgres-dev\install\bin"
echo Connecting to PostgreSQL using psql (database: postgres, user: postgres)...
"%PGBIN%\psql.exe" -U postgres -d postgres %*
