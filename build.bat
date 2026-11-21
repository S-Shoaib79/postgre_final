@echo off
setlocal
echo ===================================================
echo Building and installing PostgreSQL...
echo ===================================================

call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 (
    echo [ERROR] Failed to load Visual Studio environment.
    exit /b 1
)

rem Perl and win_flex/bison must be on PATH whenever Meson reconfigures (e.g.
rem after a meson.build change, such as adding discreet_hooks.c).
set "PATH=D:\strawberryperl\perl\bin;D:\strawberryperl\c\bin;%LOCALAPPDATA%\Microsoft\WinGet\Packages\WinFlexBison.win_flex_bison_Microsoft.Winget.Source_8wekyb3d8bbwe;%PATH%"

ninja -C "D:\postgres-dev\build" install
if errorlevel 1 (
    echo [ERROR] Build or installation failed.
    exit /b 1
)

rem The build links Strawberry Perl's OpenSSL, zlib, libxml2 and libxslt. Put
rem their DLLs next to postgres.exe and psql.exe, or both fail to start with
rem 0xC0000135 (DLL not found).
for %%D in (libcrypto-3-x64__.dll libssl-3-x64__.dll libxml2-2__.dll libxslt-1__.dll zlib1__.dll libiconv-2__.dll liblzma-5__.dll) do (
    copy /Y "D:\strawberryperl\c\bin\%%D" "D:\postgres-dev\install\bin\" >nul
)

echo ===================================================
echo PostgreSQL built and installed successfully to D:\postgres-dev\install
echo ===================================================
endlocal
