@echo off
rem Create the "erms" database: merged schema, one-time metadata, tenant data.
rem   D:\postgres-dev\merged\setup_merged.bat
rem WARNING: drops and recreates the database "erms" (only that database).
rem The server must be running (D:\postgres-dev\start.bat).
setlocal
set "PGBIN=D:\postgres-dev\install\bin"
cd /d "%~dp0"

"%PGBIN%\psql.exe" -X -q -U postgres -d postgres -c "DROP DATABASE IF EXISTS erms WITH (FORCE)" -c "CREATE DATABASE erms"
if errorlevel 1 (
    echo [ERROR] Could not create the database erms. Is the server running?
    exit /b 1
)
for %%f in (01_schema.sql 02_metadata.sql 03_tenant_data.sql 05_oauth.sql) do (
    echo Loading %%f
    "%PGBIN%\psql.exe" -X -q -v ON_ERROR_STOP=1 -U postgres -d erms -f %%f
    if errorlevel 1 (
        echo [ERROR] %%f failed.
        exit /b 1
    )
)
echo.
echo Database erms is ready. Connect with:  "%PGBIN%\psql.exe" -U postgres -d erms
endlocal
