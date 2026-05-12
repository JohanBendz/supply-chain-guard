@echo off
REM ─────────────────────────────────────────────────────────────────────────────
REM ./npm.cmd shim — supply-chain-guard muscle-memory layer (Windows)
REM
REM Copy this file to the root of your repo as `./npm.cmd` next to the
REM POSIX `./npm` shim. cmd.exe and PowerShell will pick up `npm.cmd`
REM when you run `.\npm install`.
REM
REM THIS IS NOT A SECURITY BOUNDARY. The actual protection is the
REM .scg-lock preinstall guard injected by `scg init`. See ./npm for
REM the full rationale.
REM ─────────────────────────────────────────────────────────────────────────────

setlocal

if "%~1"=="" goto passthrough

if /i "%~1"=="install"   goto route_scg
if /i "%~1"=="i"         goto route_scg
if /i "%~1"=="ci"        goto route_scg
if /i "%~1"=="add"       goto route_scg
if /i "%~1"=="update"    goto route_scg
if /i "%~1"=="uninstall" goto route_scg
if /i "%~1"=="remove"    goto route_scg
if /i "%~1"=="rm"        goto route_scg

if /i "%~1"=="rebuild" (
  echo X .\npm rebuild is blocked by the SCG shim.
  echo   Use: scg rebuild-approved [^<pkg^>]
  echo   This routes through the policy hash-binding check that
  echo   protects against post-approval script tampering.
  exit /b 1
)

if /i "%~1"=="exec" goto block_exec
if /i "%~1"=="x"    goto block_exec

goto passthrough

:route_scg
scg %*
exit /b %errorlevel%

:block_exec
echo X .\npm exec is blocked by the SCG shim.
echo   npm exec / npx fetches and runs code without going through
echo   npm install, so scg cannot intercept it. Install the tool
echo   as a dev dependency and invoke it via package.json scripts
echo   instead.
exit /b 1

:passthrough
REM Find the real npm.cmd, skipping the current directory to avoid recursion.
REM We rely on `where` and pick the first hit that isn't ours.
set "shim_path=%~f0"
for /f "delims=" %%I in ('where npm.cmd 2^>nul') do (
  if /i not "%%~fI"=="%shim_path%" (
    "%%~fI" %*
    exit /b %errorlevel%
  )
)
echo X .\npm.cmd shim could not locate the real npm binary.
echo   Install Node.js or check your PATH.
exit /b 127
