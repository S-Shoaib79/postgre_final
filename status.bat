@echo off
set "PGDATA=D:\postgres-dev\data"
set "PGBIN=D:\postgres-dev\install\bin"

"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" status
