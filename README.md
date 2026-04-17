<div align="center">

# CC-Bridge

### Claude Code Anti-Detection Gateway & Account Pool Manager

[![Release](https://img.shields.io/github/v/release/MamoWorks/cc-bridge?style=flat-square&color=blue)](https://github.com/MamoWorks/cc-bridge/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/MamoWorks/cc-bridge/release.yml?style=flat-square)](https://github.com/MamoWorks/cc-bridge/actions)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green?style=flat-square)](./craftls/LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.82-orange?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Docker](https://img.shields.io/badge/docker-ghcr.io-blue?style=flat-square&logo=docker)](https://ghcr.io/mamoworks/cc-bridge)

<br/>

**基于 Rust 的高性能 Claude Code 反检测网关** — 将网关转发、账号调度、令牌鉴权、用量管理和 Web 管理后台整合到单一二进制文件中。

[快速开始](#-快速开始) &bull; [配置说明](#-配置说明) &bull; [API 文档](#-http-api) &bull; [部署指南](#-构建与部署)

</div>

---

## 目录

- [核心能力](#-核心能力)
- [快速开始](#-快速开始)
- [配置说明](#-配置说明)
- [构建与部署](#-构建与部署)
- [HTTP API](#-http-api)
- [OAuth 授权登录](#-oauth-授权登录)
- [自动遥测](#-自动遥测)
- [架构概览](#-架构概览)
- [项目结构](#-项目结构)
- [CI/CD](#-cicd)
- [限制与注意事项](#-限制与注意事项)
- [内部工作机制](#-网关内部工作机制)
- [数据库表结构](#-数据库表结构)
- [贡献者](#-贡献者)

---

## 核心能力

<table>
<tr>
<td width="50%">

**账号管理**
- 多账号池，Setup Token + OAuth 双认证
- 粘性会话 24h 绑定同一账号
- 优先级调度 + 同优先级随机
- 每账号独立并发上限
- OAuth 按用量窗口智能限流 / 403 永久停用
- 后台自动刷新用量，前端 60s 静默更新
- 手动一键启停

</td>
<td width="50%">

**反检测引擎**
- UA / 系统提示 / 环境指纹改写
- TLS 指纹伪装（自定义 `craftls`，模拟 Node.js ClientHello）
- AI Gateway 响应头过滤（LiteLLM / Helicone / Portkey / Cloudflare / Kong / BrainTrust）
- 自动遥测代发，10min TTL 续期

</td>
</tr>
<tr>
<td width="50%">

**鉴权与安全**
- API Token 鉴权，不暴露真实凭证
- OAuth PKCE 内置授权流程
- 管理后台密码保护

</td>
<td width="50%">

**平台支持**
- Vue 3 Web 管理后台
- SQLite / PostgreSQL 双数据库
- Redis / 内存缓存
- Docker 多架构镜像
- Linux / Windows 单二进制分发

</td>
</tr>
</table>

---

## 快速开始

### 环境要求

| 依赖 | 版本 | 说明 |
|------|------|------|
| Rust | >= 1.82 | 后端编译 |
| Node.js | 22 | 前端构建 |
| npm | - | 随 Node.js 安装 |
| Redis | 可选 | 多实例部署需要 |
| PostgreSQL | 可选 | 默认使用 SQLite |
| Docker | 可选 | 容器化部署 |

### 三步启动

```bash
# 1. 克隆项目
git clone https://github.com/MamoWorks/cc-bridge.git
cd cc-bridge

# 2. 配置环境
cp .env.example .env

# 3. 启动服务
./scripts/dev.sh          # Linux / macOS
# scripts\dev.bat         # Windows
```

### 启动后入口

| 入口 | 地址 | 说明 |
|------|------|------|
| 管理后台 | `http://127.0.0.1:5674/` | Vue 3 Web 界面 |
| 登录页 | `http://127.0.0.1:5674/login` | 默认密码 `admin` |
| API 网关 | `http://127.0.0.1:5674/*` | 除保留路径外的所有请求 |

### 基本使用流程

```
1. 登录管理后台 → 2. 新建账号（手动 / OAuth 一键授权）→ 3. 创建 API Token → 4. 调用网关
```

> **建议**：创建账号时同时填写 `account_uuid`、`organization_uuid`、`subscription_type`

### 调用示例

```bash
curl http://127.0.0.1:5674/v1/messages \
  -H "Authorization: Bearer sk-your-gateway-token" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "max_tokens": 128,
    "messages": [{"role": "user", "content": "hello"}]
  }'
```

---

## 配置说明

通过 `.env` 文件或环境变量配置。优先级：**进程环境变量 > `.env` > 代码默认值**。

### 服务端

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SERVER_HOST` | `0.0.0.0` | 监听地址 |
| `SERVER_PORT` | `5674` | 监听端口 |
| `TLS_CERT_FILE` | - | 证书路径（需反代终止 TLS） |
| `TLS_KEY_FILE` | - | 私钥路径 |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `ADMIN_PASSWORD` | `admin` | 管理后台密码 |
| `USAGE_POLL_INTERVAL_SECS` | `300` | OAuth 账号用量后台自动刷新间隔（秒） |

### 数据库

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DATABASE_DRIVER` | `sqlite` | `sqlite` 或 `postgres` |
| `DATABASE_DSN` | - | 完整 DSN，设置后优先使用；`DATABASE_DRIVER=postgres` 且留空时，程序会自动使用 `docker compose` 里的 `postgres` 容器 |
| `DATABASE_HOST` | 自动：宿主机 `127.0.0.1` / 容器内 `postgres` | PostgreSQL 主机 |
| `DATABASE_PORT` | `5432` | PostgreSQL 端口 |
| `DATABASE_USER` | `POSTGRES_USER` 或 `postgres` | PostgreSQL 用户名 |
| `DATABASE_PASSWORD` | `POSTGRES_PASSWORD` 或空 | PostgreSQL 密码 |
| `DATABASE_DBNAME` | `POSTGRES_DB` 或 `claude_code_gateway` | PostgreSQL 数据库名 |

> SQLite 自动创建目录并启用 WAL 模式。PostgreSQL 在未提供 `DATABASE_DSN` 时，会先拉起根目录 `docker-compose.yml` 里的 `postgres` 服务，然后自动创建 `DATABASE_DBNAME` 指定的数据库。

### Redis（可选）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `REDIS_HOST` | - | 不设置则使用内存缓存 |
| `REDIS_PORT` | `6379` | 端口 |
| `REDIS_PASSWORD` | - | 密码 |
| `REDIS_DB` | `0` | 数据库编号 |

> 单实例无需 Redis，多实例部署请启用以共享会话粘性和并发计数。

### 最小配置

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=5674
DATABASE_DRIVER=sqlite
DATABASE_DSN=data/claude-code-gateway.db
ADMIN_PASSWORD=change-me
LOG_LEVEL=info
```

### 完整配置方案
```env
# =========================
# cc-bridge
# =========================

# --- server ---
SERVER_HOST=0.0.0.0
SERVER_PORT=5674
LOG_LEVEL=info
ADMIN_PASSWORD=change-this-admin-password
USAGE_POLL_INTERVAL_SECS=300

# --- postgres ---
DATABASE_DRIVER=postgres
# 留空则自动使用 docker compose 中的 postgres，并自动建库
# DATABASE_DSN=postgres://postgres:change-this-db-password@127.0.0.1:5432/ccgateway?sslmode=disable
POSTGRES_USER=postgres
POSTGRES_PASSWORD=change-this-db-password
POSTGRES_DB=ccgateway

# --- redis ---
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=change-this-redis-password
REDIS_DB=0

# --- tls (optional) ---
# TLS_CERT_FILE=
# TLS_KEY_FILE=
```

---

## 构建与部署

### 开发模式

```bash
# 方式一：一键启动（自动检测前端变更）
./scripts/dev.sh

# 方式二：前后端分离
cd web && npm ci && npm run dev    # 终端 A：前端 :3000
cargo run                           # 终端 B：后端 :5674
```

### 生产构建

```bash
# 当前平台
./scripts/build.sh

# 交叉编译
./scripts/build.sh linux-amd64
./scripts/build.sh linux-arm64

# 手动构建
cd web && npm ci && npm run build && cd ..
cargo build --release
./target/release/claude-code-gateway
```

### Docker 部署

```bash
cp .env.example .env
cd docker && docker compose up -d
```



> SQLite 数据持久化到命名卷 `cc-bridge-data`。

> **⚠️ 从 `claude-code-gateway` 升级到 `cc-bridge`**:镜像地址由 `ghcr.io/mamoworks/claude-code-gateway` 迁移到 `ghcr.io/mamoworks/cc-bridge`,compose 服务名/容器名/卷名均已改为 `cc-bridge` / `cc-bridge-data`。升级旧部署需迁移数据卷:
>
> ```bash
> docker compose down                          # 不要加 -v
> docker volume create cc-bridge-data
> docker run --rm \
>     -v claude-code-gateway-data:/from \
>     -v cc-bridge-data:/to \
>     alpine sh -c 'cp -a /from/. /to/'
> docker compose pull && docker compose up -d  # 使用新 compose 文件
> # 确认无误后：docker volume rm claude-code-gateway-data
> ```
>
> Cargo crate 名、SQLite 默认文件名 (`data/claude-code-gateway.db`)、localStorage 登录态 key 均保持不变,本地构建、老配置、已登录会话不受影响。

### 生产建议

| 建议 | 说明 |
|------|------|
| TLS 终止 | 使用 Nginx / Caddy 等反代 |
| 强密码 | 设置强随机 `ADMIN_PASSWORD` |
| Redis | 多实例部署启用 |
| 网络隔离 | 管理后台路径做访问控制 |

---

## HTTP API

### 认证方式

| 类型 | Header |
|------|--------|
| 管理 API | `x-api-key: <ADMIN_PASSWORD>` 或 `Authorization: Bearer <ADMIN_PASSWORD>` |
| 网关 API | `x-api-key: <sk-...>` 或 `Authorization: Bearer <sk-...>` |

### 管理接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/admin/dashboard` | 仪表盘统计 |
| `GET` | `/admin/accounts` | 账号列表（`page`/`page_size`） |
| `POST` | `/admin/accounts` | 创建账号 |
| `PUT` | `/admin/accounts/:id` | 更新账号 |
| `DELETE` | `/admin/accounts/:id` | 删除账号 |
| `POST` | `/admin/accounts/:id/test` | 测试账号 Token |
| `POST` | `/admin/accounts/:id/usage` | 刷新用量 |
| `GET` | `/admin/tokens` | 令牌列表 |
| `POST` | `/admin/tokens` | 创建令牌 |
| `PUT` | `/admin/tokens/:id` | 更新令牌 |
| `DELETE` | `/admin/tokens/:id` | 删除令牌 |
| `POST` | `/admin/oauth/generate-auth-url` | 生成 OAuth 授权链接 |
| `POST` | `/admin/oauth/generate-setup-token-url` | 生成 Setup Token 授权链接 |
| `POST` | `/admin/oauth/exchange-code` | 交换 OAuth 授权码 |
| `POST` | `/admin/oauth/exchange-setup-token-code` | 交换 Setup Token 授权码 |

### 网关转发

所有未命中前端页面、`/assets/*`、`/admin/*` 的请求进入网关 fallback，经 API Token 鉴权后转发到 `https://api.anthropic.com`。

### 保留路径

`/`、`/login`、`/tokens`、`/favicon.svg`、`/assets/*`、`/admin/*` 不进入网关。

### 创建账号示例

<details>
<summary><b>Setup Token 模式</b></summary>

```bash
curl -X POST http://127.0.0.1:5674/admin/accounts \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "account-01",
    "email": "user@example.com",
    "auth_type": "setup_token",
    "setup_token": "sk-ant-xxxx",
    "proxy_url": "socks5://127.0.0.1:1080",
    "billing_mode": "strip",
    "account_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "organization_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "subscription_type": "pro",
    "concurrency": 3,
    "priority": 50,
    "auto_telemetry": false
  }'
```

</details>

<details>
<summary><b>OAuth 模式</b></summary>

```bash
curl -X POST http://127.0.0.1:5674/admin/accounts \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "account-02",
    "email": "user@example.com",
    "auth_type": "oauth",
    "access_token": "ant-oc_xxxx",
    "refresh_token": "ant-rt_xxxx",
    "expires_at": 1735689600000,
    "billing_mode": "rewrite",
    "account_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "organization_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "subscription_type": "max",
    "concurrency": 5,
    "priority": 10,
    "auto_telemetry": true
  }'
```

</details>

<details>
<summary><b>创建令牌</b></summary>

```bash
curl -X POST http://127.0.0.1:5674/admin/tokens \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{"name": "team-a", "allowed_accounts": "1,2", "blocked_accounts": ""}'
```

</details>

### 错误响应

统一格式 `{"error": "..."}`，常见状态码：`400` / `401` / `404` / `429` / `502` / `503` / `500`。

---

## OAuth 授权登录

管理后台内置 OAuth PKCE 授权流程：

1. 点击 **"授权登录"**，选择模式：
   - **OAuth（完整权限）**：获取 `access_token` + `refresh_token`
   - **Setup Token（仅推理）**：获取 365 天有效的 `access_token`
2. 可选填写代理地址
3. 复制授权链接到浏览器完成登录
4. 从回调 URL 复制 `code`，粘贴到管理后台交换
5. 系统自动获取凭证和 `account_uuid`、`organization_uuid`、`email` 等信息
6. 点击 **"应用到新账号"** 自动填入表单

> 授权会话有效期 30 分钟。

---

## 自动遥测

开启 `auto_telemetry` 后，网关代替客户端发送遥测：

| 功能 | 说明 |
|------|------|
| **拦截** | 客户端遥测请求返回 200，不转发上游 |
| **代发** | `/api/event_logging/batch`（每 10s）、`/api/eval/sdk-*`（每 6h） |
| **触发** | 账号收到 `/v1/messages` 请求时激活遥测会话（10min TTL，自动续期） |
| **拦截路径** | `/api/event_logging/batch`、`/api/eval/*`、`/api/claude_code/metrics`、`/api/claude_code/organizations/metrics_enabled` |

> Datadog 遥测由客户端直连 `browser-intake-datadoghq.com`，无法通过网关拦截。建议在网络层屏蔽。

---

## 架构概览

```
                                    CC-Bridge
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   Client Request                                                    │
│        │                                                            │
│        v                                                            │
│   ┌─────────┐    ┌──────────┐    ┌───────────┐    ┌─────────────┐  │
│   │  Auth    │───>│ Account  │───>│ Rewriter  │───>│  craftls    │──│──> api.anthropic.com
│   │Middleware│    │Scheduler │    │  Engine   │    │ TLS Spoof   │  │
│   └─────────┘    └──────────┘    └───────────┘    └─────────────┘  │
│        │              │                                             │
│        v              v                                             │
│   ┌─────────┐    ┌──────────┐                                      │
│   │  Token   │    │ Session  │                                      │
│   │  Store   │    │ Sticky   │                                      │
│   └─────────┘    └──────────┘                                      │
│        │              │                                             │
│        v              v                                             │
│   ┌──────────────────────────────┐                                  │
│   │   SQLite / PostgreSQL        │                                  │
│   │   Redis / Memory Cache       │                                  │
│   └──────────────────────────────┘                                  │
│                                                                     │
│   ┌──────────────────────────────┐                                  │
│   │   Vue 3 Web Dashboard        │    :5674                        │
│   └──────────────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 项目结构

```text
cc-bridge/
├── .github/workflows/       # GitHub Actions 发布流程
├── craftls/                 # 自定义 rustls 分支（TLS 指纹伪装）
├── docker/                  # Dockerfile & docker-compose.yml
├── scripts/                 # 开发与构建脚本
├── src/
│   ├── main.rs              # 程序入口
│   ├── config.rs            # 环境变量加载
│   ├── error.rs             # 统一错误类型
│   ├── handler/             # 路由与 HTTP handler
│   ├── middleware/          # 鉴权中间件
│   ├── model/               # Account / ApiToken / Identity 模型
│   ├── service/             # Gateway / Account / OAuth / Telemetry / Rewriter
│   ├── store/               # 数据库与缓存访问层
│   └── tlsfp/               # TLS 指纹客户端
├── web/                     # Vue 3 前端
│   ├── src/components/      # 页面组件（Dashboard / Accounts / Tokens / Login）
│   ├── src/api.ts           # API 封装
│   └── vite.config.ts       # Vite 配置
├── .env.example             # 配置模板
├── .version                 # 发布版本与镜像名
└── Cargo.toml               # Rust 项目清单
```

---

## CI/CD

通过 `.version` 文件控制发布版本。GitHub Actions 工作流：

| 触发方式 | 条件 |
|----------|------|
| 自动触发 | 推送到 `main` 且 `.version` 有变更 |
| 手动触发 | `workflow_dispatch` |

**产物：**
- Linux x86_64 / arm64 二进制
- Windows x86_64 二进制
- GHCR 多架构 Docker 镜像（`latest` / `<version>` / `v<version>`）

**发布步骤：** 修改 `.version` 中的 `version` → 合入 `main` → 等待自动构建。

---

## 限制与注意事项

| # | 限制 | 说明 |
|---|------|------|
| 1 | TLS 未接入 HTTPS 监听 | 需使用 Nginx / Caddy / Traefik 反代做 TLS 终止 |
| 2 | 无显式 `/_health` 和 `/v1/models` | 这些路径进入网关 fallback 转发到上游 |
| 3 | Token 明文存储 | 凭证以明文存储在数据库中，请保护数据库访问 |
| 4 | 单共享密码 | 无多用户/权限系统，建议强密码 + 可信网络 + 反代访问控制 |
| 5 | 多实例需 Redis | 否则会话粘性和并发计数无法跨实例共享 |
| 6 | 版本号硬编码 | identity 模块中的版本号为静态值，上游更新后需手动同步 |
| 7 | Datadog 遥测无法拦截 | 客户端直连发送，建议网络层屏蔽 |

---

<details>
<summary><h2>网关内部工作机制</h2></summary>

### 请求鉴权

网关请求经令牌鉴权中间件，令牌必须在 `api_tokens` 表中且状态为 `active`。

### 客户端类型识别

| 特征 | 模式 |
|------|------|
| `User-Agent` 以 `claude-code/` 或 `claude-cli/` 开头 | Claude Code |
| 请求体 `metadata.user_id` 存在 | Claude Code |
| 其余 | 纯 API |

### 会话哈希

- **Claude Code**：从 `metadata.user_id` 解析 `session_id`
- **纯 API**：`sha256(UA + system/首条消息 + 小时窗口)`

### 账号过滤

每个 API Token 可配置 `allowed_accounts` 和 `blocked_accounts`（逗号分隔 ID）。

### 账号选择

1. 粘性绑定命中且可调度 → 复用
2. 否则从可调度账号（active + 未限流 + 未排除）中按 `priority` 升序选最优组
3. 同优先级随机选择 → 写入 24h 粘性绑定

### 并发控制

每账号 `concurrency` 上限，请求命中后抢占槽位，失败返回 429。槽位请求结束后自动释放。

### 限速与停用

网关根据账号类型对上游 `429` 采取不同策略，避免把仍有额度的账号长时间挂起。

**SetupToken 账号**（无法查询用量接口，保守处理）：

| 上游状态码 | 行为 | 持续时间 |
|-----------|------|---------|
| `429` | 暂停调度（状态保持 active） | 5 小时自动恢复 |
| `403` | 永久停用（标记 disabled） | 手动启用 |

**OAuth 账号**（收到 `429` 后立即调用 `/api/oauth/usage` 判断实际触发的限额窗口）：

| 触发场景 | 判定条件 | 恢复时间 |
|---------|---------|---------|
| 7 天限额撞墙 | `seven_day.utilization >= 97%` | 到 `seven_day.resets_at` |
| 5 小时限额撞墙 | `five_hour.utilization >= 97%` | 到 `five_hour.resets_at` |
| 纯速率限制 | 两个窗口都未达阈值 | 1 分钟短冷却 |
| 用量查询失败 | 网络 / 认证异常 | 5 小时保守回退 |
| `403` | 认证失败 | 永久停用（手动启用） |

同时命中两个窗口时优先 7 天（限流更久）。Sonnet 周限额（`seven_day_sonnet`）暂不纳入判断。阈值在 `src/service/account.rs` 的 `USAGE_HIT_THRESHOLD` 常量中可调整。

> 429 期间再收到 403 不会触发永久停用，避免误判。

### 自动换号重试

收到 429 后网关会把当前账号加入本次请求的排除列表，从可调度账号中重新选号继续尝试，直到成功或无可用账号。客户端只看到最终结果，中间切换对其透明。

### 用量数据自动刷新

- **后台轮询**：启动时 spawn 一个任务，每 `USAGE_POLL_INTERVAL_SECS`（默认 300 秒）遍历所有 active 的 OAuth 账号，调用 Anthropic `/api/oauth/usage` 更新 `usage_data` 字段。账号之间 500ms 间隔，避免瞬时并发过高。
- **前端静默重载**：Accounts 页面打开时每 60 秒重新拉取账号列表，从本地数据库读取最新用量。页面切走后 `onUnmounted` 清理定时器。
- **手动刷新按钮**：点击"用量"按钮仍可立即刷新单个账号的用量数据。

### 请求头改写

- User-Agent → `claude-code/<version> (external, cli)`
- 注入/合并 `anthropic-beta`、固定 `anthropic-version`
- 强制使用账号真实 `Authorization`
- 追加 `beta=true` 查询参数
- 还原 header wire casing

### 请求体改写

| 路径 | 改写内容 |
|------|---------|
| `/v1/messages` | 系统提示词注入、`metadata.user_id`、环境/进程指纹、`cache_control`、billing 处理 |
| `/api/event_logging/batch` | `device_id`、`email`、`account_uuid`、`organization_uuid`、env/process 指纹、`user_attributes` JSON |
| `/api/eval/{clientKey}` | `id`、`deviceID`、`email`、`accountUUID`、`organizationUUID`、`subscriptionType`、移除 `apiBaseUrlHost` |
| 其他路径 | 通用身份字段改写 |

### TLS 指纹

所有上游请求通过 `craftls` 发出，模拟 Node.js TLS 指纹。每账号可配代理（HTTP / SOCKS5）。

### AI Gateway 指纹过滤

过滤响应头前缀：`x-litellm-`、`helicone-`、`x-portkey-`、`cf-aig-`、`x-kong-`、`x-bt-`。

</details>

<details>
<summary><h2>数据库表结构</h2></summary>

### `accounts` 表

| 字段 | 说明 |
|------|------|
| `id` | 主键 |
| `name` / `email` | 账号标识（email 检查重复） |
| `status` | `active` / `error` / `disabled` |
| `auth_type` | `setup_token` / `oauth` |
| `token` | Setup Token |
| `access_token` / `refresh_token` / `oauth_expires_at` / `oauth_refreshed_at` | OAuth 凭证 |
| `auth_error` | 认证错误信息 |
| `proxy_url` | 账号专用代理 |
| `device_id` | 自动生成的设备 ID |
| `canonical_env` / `canonical_prompt_env` / `canonical_process` | 指纹 JSON |
| `billing_mode` | `strip` / `rewrite` |
| `account_uuid` / `organization_uuid` / `subscription_type` | 遥测改写用 |
| `concurrency` / `priority` | 调度参数 |
| `rate_limited_at` / `rate_limit_reset_at` / `disable_reason` | 限流/停用状态 |
| `usage_data` / `usage_fetched_at` | 用量缓存 |
| `auto_telemetry` / `telemetry_count` | 自动遥测 |

### `api_tokens` 表

| 字段 | 说明 |
|------|------|
| `id` | 主键 |
| `name` | 令牌名称 |
| `token` | 自动生成的 `sk-...` 令牌 |
| `allowed_accounts` / `blocked_accounts` | 账号 ID 列表（逗号分隔） |
| `status` | `active` / `disabled` |

> 服务启动时自动执行内建 SQL 迁移，不依赖外部 migration 文件。

</details>

<details>
<summary><h2>账号字段参考</h2></summary>

| 字段 | 必填 | 说明 |
|------|------|------|
| `email` | 是 | 账号邮箱 |
| `auth_type` | 否 | `setup_token`（默认）或 `oauth` |
| `setup_token` / `token` | 条件 | Setup Token 模式必填 |
| `access_token` / `refresh_token` | 条件 | OAuth 模式必填 |
| `expires_at` | 否 | OAuth access_token 过期时间（ms 时间戳） |
| `name` | 否 | 显示名称 |
| `proxy_url` | 否 | 专用代理 |
| `billing_mode` | 否 | `strip` 或 `rewrite` |
| `account_uuid` | 否 | 推荐填写，用于遥测改写 |
| `organization_uuid` | 否 | 推荐填写，用于遥测改写 |
| `subscription_type` | 否 | `max` / `pro` / `team` / `enterprise`，推荐填写 |
| `concurrency` | 否 | 最大并发，默认 3 |
| `priority` | 否 | 数值越小优先级越高，默认 50 |
| `auto_telemetry` | 否 | 是否开启自动遥测，默认 false |

> 创建时系统自动生成 `device_id`、`canonical_env`、`canonical_prompt_env`、`canonical_process`。

</details>

---

## 许可与依赖说明

项目包含自定义 `craftls` 目录（基于 [rustls](https://github.com/rustls/rustls) 分支）。详见 `craftls/` 下的许可证文件。

---

## 贡献者

<table>
<tr>
<td align="center">
<a href="https://github.com/Rfym21">
<img src="https://github.com/Rfym21.png" width="80px;" alt="Rfym21"/>
<br/>
<sub><b>Rfym21</b></sub>
</a>
</td>
<td align="center">
<a href="https://github.com/FF-crazy">
<img src="https://github.com/FF-crazy.png" width="80px;" alt="FF-crazy"/>
<br/>
<sub><b>FF-crazy</b></sub>
</a>
</td>
<td align="center">
<a href="https://github.com/kao0312">
<img src="https://github.com/kao0312.png" width="80px;" alt="kao0312"/>
<br/>
<sub><b>kao0312</b></sub>
</a>
</td>
<td align="center">
<a href="https://github.com/2830897438">
<img src="https://github.com/2830897438.png" width="80px;" alt="2830897438"/>
<br/>
<sub><b>2830897438</b></sub>
</a>
</td>
</tr>
</table>

---

<div align="center">

**[MamoWorks](https://github.com/MamoWorks)** &copy; 2025

[![Star History Chart](https://api.star-history.com/svg?repos=MamoWorks/cc-bridge&type=Date)](https://star-history.com/#MamoWorks/cc-bridge&Date)

</div>
