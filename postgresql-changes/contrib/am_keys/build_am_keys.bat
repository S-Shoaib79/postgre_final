@echo off
rem Builds am_keys.dll (the AM keys endpoint inside PostgreSQL) and installs it
rem into D:\postgres-dev\install\lib.  Same compiler flags as the main build
rem (build\build.ninja); no PostgreSQL meson.build is changed.
rem
rem   D:\postgres-dev\postgresql-changes\contrib\am_keys\build_am_keys.bat
rem
rem Then, once: shared_preload_libraries = 'am_keys' in data\postgresql.conf,
rem push_secret = ... in data\am_client.conf, and restart PostgreSQL.
setlocal
set "ROOT=D:\postgres-dev"
set "SRC=%~dp0"
set "OUT=%ROOT%\build\am_keys"

call "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo [ERROR] Failed to load Visual Studio environment.
    exit /b 1
)
if not exist "%OUT%" mkdir "%OUT%"

set "PGINC=/I"%ROOT%\build\src\include" /I"%ROOT%\postgresql\src\include" /I"%ROOT%\postgresql\src\include\port\win32" /I"%ROOT%\postgresql\src\include\port\win32_msvc""
set "DEFS=/DWIN32 /DWINDOWS /D__WINDOWS__ /D__WIN32__ /D_CRT_SECURE_NO_DEPRECATE /D_CRT_NONSTDC_NO_DEPRECATE"

rem The PostgreSQL part (C, with the server headers)
cl /nologo /c /MD /utf-8 /std:c11 /O2 /Z7 /W2 %DEFS% /wd4244 /wd4090 /wd4018 /wd4101 /wd4267 /we4013 ^
   %PGINC% /Fo"%OUT%\am_keys_worker.obj" "%SRC%am_keys_worker.c"
if errorlevel 1 (
    echo [ERROR] Compile of am_keys_worker.c failed.
    exit /b 1
)
rem The C++ part (no PostgreSQL headers, like am_client.cpp)
cl /nologo /c /MD /utf-8 /std:c++17 /Zc:__cplusplus /EHsc /O2 /Z7 /W2 %DEFS% ^
   /Fo"%OUT%\am_keys.obj" "%SRC%am_keys.cpp"
if errorlevel 1 (
    echo [ERROR] Compile of am_keys.cpp failed.
    exit /b 1
)

link /nologo /DLL /DEBUG /INCREMENTAL:NO /OUT:"%OUT%\am_keys.dll" /PDB:"%OUT%\am_keys.pdb" ^
   "%OUT%\am_keys_worker.obj" "%OUT%\am_keys.obj" "%ROOT%\build\src\backend\postgres.lib" ws2_32.lib kernel32.lib advapi32.lib
if errorlevel 1 (
    echo [ERROR] Link failed.
    exit /b 1
)

copy /Y "%OUT%\am_keys.dll" "%ROOT%\install\lib\" >nul
if errorlevel 1 (
    echo [ERROR] Built %OUT%\am_keys.dll but could not copy it to %ROOT%\install\lib:
    echo         PostgreSQL has it loaded. Stop PostgreSQL, run this again, start PostgreSQL.
    exit /b 1
)
echo am_keys.dll built and installed to %ROOT%\install\lib
endlocal
