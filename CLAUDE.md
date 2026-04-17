# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Claude Code Gateway (cc-bridge) is a Rust reverse proxy for the Anthropic API that pools multiple Claude accounts with load balancing, rate limit handling, sticky sessions, TLS fingerprint spoofing, and request/response rewriting. It includes a Vue 3 management dashboard embedded into the single binary via `rust-embed`.

## Build & Run Commands

```bash
# Development (frontend + backend together)
cp .env.example .env
./scripts/dev.sh

# Or run separately:
cd web && npm ci && npm run dev    # Frontend dev server on :3000
cargo run                           # Backend on :5674 (frontend proxies to it)

# Production build (embeds frontend into binary)
./scripts/build.sh                  # Native
./scripts/build.sh linux-amd64     # Cross-compile

# Docker
docker build -f docker/Dockerfile -t cc-bridge:latest .
```

No test suite exists. Account validity is tested via the UI's "test" button.

## Architecture

### Request Flow

Auth middleware → API token lookup → account selection (sticky session + priority + concurrency) → request rewriting (headers, body, telemetry, identity) → TLS fingerprint spoofing via custom rustls (`craftls/`) → forward to api.anthropic.com → response header filtering → return to client.

### Key Modules

- **`src/handler/router.rs`** — All HTTP endpoints: SPA routes, `/admin/*` management API (password-protected), and the catch-all gateway proxy.
- **`src/service/gateway.rs`** — Core forwarding orchestration: account selection, slot acquisition with scopeguard, upstream request, rate limit detection (429 → quarantine account).
- **`src/service/rewriter.rs`** — Request/response transformation: header normalization, body patching (session hash, version, telemetry paths like event_logging/GrowthBook), system prompt env var injection, AI Gateway fingerprint header stripping.
- **`src/service/account.rs`** — Account selection logic: sticky sessions (SHA256 of UA+body, 24h TTL), OAuth token refresh with locking, concurrency slot management, usage/billing queries.
- **`src/tlsfp/tlsfp.rs`** — Custom TLS ClientHello builder that mimics Node.js fingerprint, using the forked rustls in `craftls/`.
- **`src/middleware/auth.rs`** — Extracts API key from `x-api-key` or `Authorization: Bearer` header, validates against token store.
- **`src/store/`** — SQLx-based persistence (SQLite default, PostgreSQL optional) with `CacheStore` trait implemented by `MemoryStore` and `RedisStore`.
- **`src/model/identity.rs`** — Generates canonical device identity (20+ env vars, process fingerprints) for upstream requests.

### Frontend

Vue 3 + Vite + TypeScript in `web/`. Components: Login, Dashboard, Accounts, Tokens. API client in `web/src/api.ts`. Uses shadcn-style UI components in `web/src/components/ui/`.

### Database

SQLite (WAL mode) or PostgreSQL, selected via `DATABASE_DRIVER` env var. Auto-migration on startup in `src/store/db.rs`. Incremental ALTER TABLE migrations for backward compatibility.

### Custom Rustls Fork

`craftls/` contains a patched rustls that exposes low-level TLS ClientHello construction for fingerprint spoofing. This is a workspace dependency, not published.

## Configuration

All via environment variables (see `.env.example`). Key ones: `SERVER_HOST`/`SERVER_PORT` (default 0.0.0.0:5674), `DATABASE_DRIVER`/`DATABASE_DSN`, `REDIS_HOST` (optional, falls back to in-memory), `ADMIN_PASSWORD` (default "admin"), `LOG_LEVEL`.

## Dual Auth Modes

Accounts support two auth types: **SetupToken** (classic API key) and **OAuth** (with automatic access token refresh via stored refresh tokens). Both flows converge in `AccountService::select_account`.

## KEY: EVERY TIME YOU WANT TO CHANGE STH, PLEASE REFER cc-gateway
