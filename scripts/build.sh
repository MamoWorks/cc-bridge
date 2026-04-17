#!/bin/bash
# 构建 cc-bridge：前端 + Rust 后端
# 前端资源在编译时嵌入二进制，部署只需可执行文件 + .env
# 用法: ./build.sh [target]
#   target: linux-amd64 | linux-arm64 | 留空则构建当前平台
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

TARGET="${1:-native}"
OUTPUT_DIR="$PROJECT_DIR/dist"

# 目标映射
case "$TARGET" in
    linux-amd64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        BINARY_NAME="cc-bridge-linux-amd64"
        ;;
    linux-arm64)
        RUST_TARGET="aarch64-unknown-linux-gnu"
        BINARY_NAME="cc-bridge-linux-arm64"
        ;;
    native)
        RUST_TARGET=""
        BINARY_NAME="cc-bridge"
        ;;
    *)
        echo "Unknown target: $TARGET"
        echo "Usage: $0 [linux-amd64|linux-arm64]"
        exit 1
        ;;
esac

echo "=== cc-bridge build ==="
echo "Target: $TARGET"

# 1. 清理旧构建产物
echo "Cleaning previous build..."
rm -rf "$OUTPUT_DIR"
cargo clean

# 2. 构建前端（编译时嵌入二进制）
echo "Building frontend..."
cd web
if [ ! -d "node_modules/@vue/tsconfig" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
npm run build
cd ..

# 3. 安装目标工具链（如果交叉编译）
if [ -n "$RUST_TARGET" ]; then
    echo "Installing target: $RUST_TARGET"
    rustup target add "$RUST_TARGET"
fi

# 4. 构建 Rust 后端
echo "Building backend..."
if [ -n "$RUST_TARGET" ]; then
    cargo build --release --target "$RUST_TARGET"
    BINARY_SRC="target/$RUST_TARGET/release/claude-code-gateway"
else
    cargo build --release
    BINARY_SRC="target/release/claude-code-gateway"
fi

# 5. 打包产物
echo "Packaging..."
mkdir -p "$OUTPUT_DIR"
cp "$BINARY_SRC" "$OUTPUT_DIR/$BINARY_NAME"
cp .env.example "$OUTPUT_DIR/.env.example"

echo "=== Build complete ==="
echo "Output: $OUTPUT_DIR/"
ls -lh "$OUTPUT_DIR/$BINARY_NAME"
