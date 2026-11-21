@echo off
set "PGDATA=D:\postgres-dev\data"
set "PGBIN=D:\postgres-dev\install\bin"

echo Stopping PostgreSQL server...
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -m fast stop
