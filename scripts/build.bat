@echo off
REM Build cc-bridge: frontend + Rust backend (win/linux-amd64/linux-arm64)
REM Frontend is embedded into the binary at compile time.
REM Requires: zig, cargo-zigbuild (for Linux cross-compilation)
REM Usage: build.bat [target]
REM   target: win | linux-amd64 | linux-arm64 | all (default)
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.."

set "TARGET=%~1"
if "%TARGET%"=="" set "TARGET=all"
set "OUTPUT_DIR=%CD%\dist"

echo === cc-bridge build ===

REM 1. Clean previous build
echo Cleaning previous build...
if exist "%OUTPUT_DIR%" rmdir /s /q "%OUTPUT_DIR%"
mkdir "%OUTPUT_DIR%" 2>nul
cargo clean

REM 2. Build frontend (embedded into binary at compile time)
echo Building frontend...
pushd web
if not exist "node_modules\@vue\tsconfig" (
    echo Installing frontend dependencies...
    call npm install
    if errorlevel 1 (
        popd
        popd
        exit /b 1
    )
)
call npm run build
if errorlevel 1 (
    popd
    popd
    exit /b 1
)
popd

REM 3. Copy config template
copy ".env.example" "%OUTPUT_DIR%\.env.example"

REM 4. Build targets
if "%TARGET%"=="all" (
    call :build_win
    call :build_linux_amd64
    call :build_linux_arm64
) else if "%TARGET%"=="win" (
    call :build_win
) else if "%TARGET%"=="linux-amd64" (
    call :build_linux_amd64
) else if "%TARGET%"=="linux-arm64" (
    call :build_linux_arm64
) else (
    echo Unknown target: %TARGET%
    echo Usage: build.bat [win^|linux-amd64^|linux-arm64^|all]
    popd
    exit /b 1
)

echo.
echo === Build complete ===
echo Output: %OUTPUT_DIR%\
dir /b "%OUTPUT_DIR%\cc-bridge-*" 2>nul

popd
exit /b 0

:build_win
echo.
echo --- Building win-amd64 (native) ---
cargo build --release
if exist "target\release\claude-code-gateway.exe" (
    copy "target\release\claude-code-gateway.exe" "%OUTPUT_DIR%\cc-bridge-win-amd64.exe"
    echo OK: cc-bridge-win-amd64.exe
) else (
    echo FAILED: win-amd64
)
exit /b 0

:build_linux_amd64
echo.
echo --- Building linux-amd64 (zigbuild) ---
rustup target add x86_64-unknown-linux-gnu >nul 2>&1
cargo zigbuild --release --target x86_64-unknown-linux-gnu
if exist "target\x86_64-unknown-linux-gnu\release\claude-code-gateway" (
    copy "target\x86_64-unknown-linux-gnu\release\claude-code-gateway" "%OUTPUT_DIR%\cc-bridge-linux-amd64"
    echo OK: cc-bridge-linux-amd64
) else (
    echo FAILED: linux-amd64
)
exit /b 0

:build_linux_arm64
echo.
echo --- Building linux-arm64 (zigbuild) ---
rustup target add aarch64-unknown-linux-gnu >nul 2>&1
cargo zigbuild --release --target aarch64-unknown-linux-gnu
if exist "target\aarch64-unknown-linux-gnu\release\claude-code-gateway" (
    copy "target\aarch64-unknown-linux-gnu\release\claude-code-gateway" "%OUTPUT_DIR%\cc-bridge-linux-arm64"
    echo OK: cc-bridge-linux-arm64
) else (
    echo FAILED: linux-arm64
)
exit /b 0
