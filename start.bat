@echo off
set "PGDATA=D:\postgres-dev\data"
set "PGBIN=D:\postgres-dev\install\bin"
set "LOGFILE=D:\postgres-dev\data\server.log"

echo Starting PostgreSQL server...
"%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -l "%LOGFILE%" start
if errorlevel 1 (
    echo [ERROR] Failed to start PostgreSQL. Check logs at %LOGFILE%
    exit /b 1
)
echo PostgreSQL started successfully. Log file: %LOGFILE%
