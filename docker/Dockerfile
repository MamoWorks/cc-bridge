# Stage 1: Build frontend
FROM --platform=$BUILDPLATFORM node:22-alpine AS frontend
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: Build Rust backend
FROM --platform=$BUILDPLATFORM rust:slim-bookworm AS backend
ARG TARGETPLATFORM
WORKDIR /app

RUN apt-get update && apt-get install -y pkg-config libssl-dev gcc-aarch64-linux-gnu && rm -rf /var/lib/apt/lists/*

# 根据目标平台设置交叉编译
RUN case "$TARGETPLATFORM" in \
      "linux/arm64") \
        rustup target add aarch64-unknown-linux-gnu \
        ;; \
    esac

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
COPY craftls/ ./craftls/
COPY --from=frontend /app/web/dist ./web/dist/

RUN case "$TARGETPLATFORM" in \
      "linux/arm64") \
        export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc && \
        cargo build --locked --release --target aarch64-unknown-linux-gnu && \
        cp target/aarch64-unknown-linux-gnu/release/claude-code-gateway /app/cc-bridge-bin \
        ;; \
      *) \
        cargo build --locked --release && \
        cp target/release/claude-code-gateway /app/cc-bridge-bin \
        ;; \
    esac

# Stage 3: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY --from=backend /app/cc-bridge-bin ./cc-bridge

RUN useradd --system --uid 10001 --create-home appuser \
    && mkdir -p /app/data \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 5674
CMD ["./cc-bridge"]
