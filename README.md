# Claude Code Gateway

`claude-code-gateway` 是一个基于 Rust 实现的 Claude Code 反检测网关与账号池管理平台。它将对外网关、账号调度、令牌鉴权、用量管理和 Web 管理后台整合到同一个项目中，适合需要统一管理多个 Claude 账号、控制对外访问口径、降低客户端指纹差异的场景。

项目当前由两部分组成：

- Rust 后端：负责网关转发、账号选择、请求改写、数据库与缓存、管理 API
- Vue 3 前端：负责管理后台界面，提供账号与令牌管理、仪表盘、登录界面

正常构建流程下，前端资源会在构建时准备好并由后端提供；开发时也可以使用 Vite 独立启动前端热更新。

## 目录

- [核心能力](#核心能力)
- [适用场景](#适用场景)
- [整体架构](#整体架构)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [开发指南](#开发指南)
- [构建与部署](#构建与部署)
- [网关工作机制](#网关工作机制)
- [管理后台说明](#管理后台说明)
- [HTTP API](#http-api)
- [数据与存储](#数据与存储)
- [CI/CD 与发布](#cicd-与发布)
- [项目结构](#项目结构)
- [OAuth 授权登录](#oauth-授权登录)
- [自动遥测](#自动遥测)
- [自动停用与手动启停](#自动停用与手动启停)
- [限制与注意事项](#限制与注意事项)

## 核心能力

- 多账号池管理：支持维护多个 Claude 账号，为每个账号单独配置 Setup Token 或 OAuth 凭证、代理、并发上限、优先级和 billing 处理策略
- 令牌化对外访问：通过数据库中的 API Token 对网关调用方做鉴权，而不是直接暴露真实账号 Token
- 粘性会话调度：同一会话在 24 小时内尽量命中同一个账号，降低频繁切换账号带来的行为漂移
- 优先级选号：优先选择 `priority` 数值更小的账号；同优先级账号之间随机挑选
- 并发控制：每个账号都有单独的并发上限，支持 Redis 或进程内内存计数
- 自动限速回避：上游返回 `429` 后，自动将账号暂停 5 小时（保留 `active` 状态但不可调度）
- 自动停用：上游返回 `403` 时永久停用账号（标记为 `disabled`），但若账号已在限流冷却期则跳过，避免误判
- 手动启停调度：管理后台支持一键启用/停用账号，停用后账号不参与调度
- 请求反检测改写：改写请求头、系统提示、环境信息、进程指纹和部分遥测字段，使流量更接近真实 Claude Code 客户端
- 遥测改写：改写 `event_logging/batch`、GrowthBook `remoteEval`、`user_attributes` 等遥测路径中的身份与环境信息，防止代理身份泄露
- AI Gateway 指纹过滤：过滤上游响应中的 AI Gateway / 代理指纹头（LiteLLM、Helicone、Portkey、Cloudflare AI Gateway、Kong、BrainTrust），防止客户端检测上报
- Node.js TLS 指纹伪装：通过自定义 `craftls` 复现 Node.js 风格的 TLS ClientHello
- 双认证类型：账号支持 `setup_token`（经典模式）和 `oauth`（OAuth 模式，自动刷新 access_token）
- OAuth 授权登录：内置 OAuth PKCE 授权流程，可在管理后台一键生成授权链接、交换令牌，自动获取 `account_uuid`、`organization_uuid`、`email` 等信息
- 自动遥测：按账号开启后，网关拦截客户端遥测请求并代为发送，模拟真实 Claude Code 客户端的遥测行为，10 分钟 TTL 自动续期
- 管理后台：内置 Web 界面，可进行账号增删改查、连接测试、用量刷新、OAuth 授权登录、API Token 管理与仪表盘查看
- 多存储后端：支持 SQLite 与 PostgreSQL；缓存层支持 Redis 和内存实现
- 单端口提供能力：同一个服务实例同时提供网关接口、管理 API 和 Web 管理后台

## 适用场景

- 需要统一暴露一个 Claude 兼容入口，但后端实际维护多个账号（支持 Setup Token 和 OAuth 两种认证方式）
- 希望把调用方与真实 Claude 账号解耦，通过中间层实施访问控制
- 需要按账号维度分配代理、并发和优先级
- 需要一个可视化后台来维护账号、观察状态和刷新 OAuth 用量
- 需要更接近真实 Claude Code 客户端请求画像的出站流量
- 需要改写遥测数据，防止代理身份和真实设备信息泄露到 Anthropic 后端
- 希望由网关代为发送遥测（自动遥测），减少客户端遥测泄露风险

## 整体架构

```text
Claude Code / 外部 API 客户端
        |
        | x-api-key 或 Authorization: Bearer <sk-...>
        v
  +------------------------+
  | claude-code-gateway 网关 |
  |------------------------|
  | 1. 令牌鉴权            |
  | 2. 会话哈希计算        |
  | 3. 账号过滤与选择      |
  | 4. 请求头/请求体改写   |
  | 5. TLS 指纹伪装        |
  | 6. 代理转发到上游      |
  +------------------------+
        |
        v
 https://api.anthropic.com

浏览器
    |
    | Authorization: Bearer <ADMIN_PASSWORD>
    v
  +------------------------+
  |   管理后台 / 管理 API  |
  +------------------------+
        |
        +--> SQLite / PostgreSQL
        |
        +--> Redis（可选）
```

后端的核心职责可以概括为三件事：

1. 对网关调用方做鉴权，并按会话和账号池规则决定这次请求应该由哪个账号执行
2. 对发往上游的请求进行必要的头部、提示词、环境和指纹改写
3. 对管理端暴露完整的账号与令牌管理能力

## 快速开始

### 环境要求

- Rust：建议 `1.82` 或更高版本
- Node.js：建议 `22`，与 CI 工作流保持一致
- npm：用于构建前端
- 可选：
  - Redis：用于跨实例共享粘性会话和并发计数
  - PostgreSQL：替代默认 SQLite
  - Docker / Docker Compose：用于容器部署
  - Zig 与 `cargo-zigbuild`：Windows 下交叉编译 Linux 产物时需要

### 最小启动方式

先复制环境变量模板：

```bash
cp .env.example .env
```

然后启动项目：

```bash
# Linux / macOS
./scripts/dev.sh

# Windows
scripts\dev.bat
```

默认情况下服务会监听：

- 管理后台：`http://127.0.0.1:5674/`
- 登录页：`http://127.0.0.1:5674/login`
- Claude 兼容网关：除前端页面、静态资源和 `/admin/*` 之外的其余路径

默认管理员密码是：

```text
admin
```

### 启动后的基本使用顺序

1. 打开管理后台并使用 `ADMIN_PASSWORD` 登录
2. 新建至少一个账号：
   - **方式一**：手动填写邮箱、认证凭证（Setup Token 或 OAuth access/refresh token）、代理配置和调度参数
   - **方式二**：点击”授权登录”，通过内置 OAuth 流程一键授权，自动获取凭证和账号信息
3. 强烈建议同时填写 `account_uuid`、`organization_uuid`、`subscription_type`（OAuth 授权登录会自动获取）
4. 在”令牌”页面创建一个 API Token
5. 调用网关时，将生成的 `sk-...` 令牌放入 `x-api-key` 或 `Authorization: Bearer` 头

### 启动后的访问入口

当前显式注册的前端页面路径为：

- `/`
- `/login`
- `/tokens`
- `/favicon.svg`

静态资源路径为：

- `/assets/*`

管理 API 路径为：

- `/admin/*`

除以上路径外，其余请求都会进入网关 fallback，并在完成 API Token 鉴权后转发到上游。

## 配置说明

服务启动时会调用 `dotenvy::dotenv()` 自动加载根目录 `.env` 文件，因此配置优先级通常可以理解为：

1. 进程环境变量
2. `.env` 文件
3. 代码内默认值

### 服务端配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `SERVER_HOST` | `0.0.0.0` | 服务监听地址 |
| `SERVER_PORT` | `5674` | 服务监听端口 |
| `TLS_CERT_FILE` | 空 | 证书路径，当前版本会读取该变量，但未真正接入 TLS 监听 |
| `TLS_KEY_FILE` | 空 | 私钥路径，当前版本会读取该变量，但未真正接入 TLS 监听 |
| `LOG_LEVEL` | `info` | 日志级别，支持 `debug`、`info`、`warn`、`error` |

### 数据库配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `DATABASE_DRIVER` | `sqlite` | 数据库驱动，支持 `sqlite` 或 `postgres` |
| `DATABASE_DSN` | `data/claude-code-gateway.db` | 完整 DSN；设置后优先使用 |
| `DATABASE_HOST` | `localhost` | PostgreSQL 主机，只有在 `DATABASE_DSN` 为空时才参与拼接 |
| `DATABASE_PORT` | `5432` | PostgreSQL 端口 |
| `DATABASE_USER` | `postgres` | PostgreSQL 用户名 |
| `DATABASE_PASSWORD` | 空 | PostgreSQL 密码 |
| `DATABASE_DBNAME` | `claude_code_gateway` | PostgreSQL 数据库名 |

说明：

- 当 `DATABASE_DRIVER=sqlite` 时，会自动创建数据库目录，并启用 SQLite `WAL` 模式和 `foreign_keys=ON`
- 当 `DATABASE_DRIVER=postgres` 且没有设置 `DATABASE_DSN` 时，程序会自动拼出如下连接串：

```text
postgres://<user>:<password>@<host>:<port>/<dbname>?sslmode=disable
```

### Redis 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `REDIS_HOST` | 空 | Redis 主机；不设置时退回进程内内存缓存 |
| `REDIS_PORT` | `6379` | Redis 端口 |
| `REDIS_PASSWORD` | 空 | Redis 密码 |
| `REDIS_DB` | `0` | Redis 数据库编号 |

Redis 主要用于：

- 粘性会话绑定
- 并发槽位计数

如果没有 Redis：

- 单实例运行完全可用
- 多实例部署时，实例之间不会共享会话和并发状态，不建议生产横向扩容后继续使用内存缓存

### 管理后台配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ADMIN_PASSWORD` | `admin` | 管理后台与管理 API 使用的共享密码 |

### 推荐的最小 `.env`

```env
SERVER_HOST=0.0.0.0
SERVER_PORT=5674
DATABASE_DRIVER=sqlite
DATABASE_DSN=data/claude-code-gateway.db
ADMIN_PASSWORD=change-me
LOG_LEVEL=info
```

### PostgreSQL 示例

```env
SERVER_PORT=5674
DATABASE_DRIVER=postgres
DATABASE_DSN=postgres://postgres:your_password@localhost:5432/claude_code_gateway?sslmode=disable
REDIS_HOST=localhost
REDIS_PORT=6379
ADMIN_PASSWORD=change-me
LOG_LEVEL=info
```

## 开发指南

### 方式一：使用项目脚本快速启动

```bash
./scripts/dev.sh
```

或：

```powershell
scripts\dev.bat
```

脚本行为：

- 如果 `web/dist` 不存在或前端源码有更新，则先执行前端构建
- 然后执行 `cargo run`

这意味着：

- 脚本会自动检测前端源码变更并增量重建
- 如果前端没有变化，不会重复构建

### 方式二：前后端分离开发

更推荐日常开发时采用以下方式：

终端 A：

```bash
cd web
npm ci
npm run dev
```

终端 B：

```bash
cargo run
```

此时：

- Vite 默认运行在 `http://127.0.0.1:3000`
- `/admin` 和 `/_health` 会代理到 `http://localhost:5674`
- 前端支持热更新

注意：

- 当前前端开发代理显式声明的是 `/admin` 和 `/_health`
- 运行时后端真实路由里已经不再单独注册 `/_health`
- 网关流量在生产模式下通过后端 fallback 处理，而不是依赖显式 `/v1/*` 路由

### 仅后端调试

如果你直接运行：

```bash
cargo run
```

但没有提前构建前端，则访问 `/` 时可能拿到：

```text
frontend not built
```

因为静态资源目录 `web/dist` 不存在，后端无法提供前端页面。

## 构建与部署

### 构建脚本

#### Linux / macOS

```bash
./scripts/build.sh
./scripts/build.sh linux-amd64
./scripts/build.sh linux-arm64
```

说明：

- 不带参数时构建当前平台产物
- 指定 `linux-amd64` 或 `linux-arm64` 时会尝试添加对应 Rust target
- 构建产物输出到 `dist/`

#### Windows

```powershell
scripts\build.bat
scripts\build.bat win
scripts\build.bat linux-amd64
scripts\build.bat linux-arm64
scripts\build.bat all
```

说明：

- Windows 脚本支持当前平台和 Linux 交叉构建
- 构建 Linux 产物依赖 Zig 与 `cargo-zigbuild`
- 构建结果输出到 `dist/`

### 手动构建

```bash
# 1. 构建前端
cd web
npm ci
npm run build
cd ..

# 2. 构建 Rust 后端
cargo build --release

# 3. 启动
./target/release/claude-code-gateway
```

### Docker 部署

项目提供了单独的 `docker/` 目录。

先准备 `.env`：

```bash
cp .env.example .env
```

然后启动：

```bash
cd docker
docker compose up -d
```

当前 `docker/docker-compose.yml` 的行为：

- 构建镜像时使用根目录上下文
- 将宿主机根目录 `.env` 作为容器环境文件
- 将 SQLite 数据持久化到命名卷 `claude-code-gateway-data`
- 默认暴露容器 `5674` 端口

如果你使用默认 SQLite，Docker 部署下的数据文件会保存在卷中，而不是代码仓库目录中。

### 生产部署建议

生产环境建议：

- 将服务放在反向代理之后，例如 Nginx 或 Caddy
- 使用强随机 `ADMIN_PASSWORD`
- 如需多实例部署，启用 Redis
- 将数据库放到持久化磁盘或外部 PostgreSQL
- 对管理后台路径做额外网络隔离，例如仅内网访问

## 网关工作机制

这一部分用于解释服务在收到一次网关请求后，内部究竟做了什么。

### 1. 网关请求鉴权

所有网关请求都经过令牌鉴权中间件。支持两种传参方式：

- `x-api-key: sk-...`
- `Authorization: Bearer sk-...`

校验逻辑：

- 令牌必须存在于数据库 `api_tokens` 表
- 令牌状态必须为 `active`

### 2. 客户端类型识别

后端会区分两类请求：

- Claude Code 模式
- 纯 API 模式

识别规则当前如下：

- `User-Agent` 以 `claude-code/` 或 `claude-cli/` 开头，视为 Claude Code
- 或请求体 `metadata.user_id` 存在，也视为 Claude Code
- 其余情况视为纯 API 模式

### 3. 会话哈希生成

会话哈希用于粘性调度。

Claude Code 模式：

- 优先从 `metadata.user_id` 中解析 `session_id`
- 兼容旧格式 `_session_...` 后缀

纯 API 模式：

- 使用 `sha256(User-Agent + system 或首条消息 + 小时窗口)` 生成哈希
- 这样同一类请求在同一小时内更容易命中同一账号

### 4. API Token 的账号过滤

每个 API Token 可以配置两组账号限制：

- `allowed_accounts`：允许使用的账号 ID，留空表示不限制
- `blocked_accounts`：禁止使用的账号 ID，留空表示不限制

字段在数据库中以逗号分隔字符串保存，例如：

```text
1,2,5
```

### 5. 账号选择策略

网关选择账号的顺序为：

1. 如果当前会话已有粘性绑定且账号仍可调度，则直接复用
2. 否则从所有“可调度”账号中筛选候选集
3. 候选集按照 `priority` 升序挑选最优组
4. 同优先级账号之间随机选择
5. 为当前会话写入 24 小时粘性绑定

可调度的账号必须满足：

- `status=active`
- 没有处于限流冷却期
- 没有被当前 API Token 排除

### 6. 并发控制

每个账号都有自己的 `concurrency` 上限。

当请求命中账号后，系统会先尝试抢占一个并发槽位：

- 成功：继续向上游发起请求
- 失败：直接返回 `429 too many requests`

槽位在请求结束后自动释放。

### 7. 自动限速处理

当上游返回 `429` 时，账号会被自动暂停 5 小时：

- 账号状态保持 `active`，但 `rate_limit_reset_at` 被设为 5 小时后
- 在冷却期内账号不参与调度（`is_schedulable()` 返回 `false`）
- 冷却期结束后账号自动恢复可调度
- `disable_reason` 记录为 `429 速率限制`

### 8. 自动停用（403）

当上游返回 `403` 时，账号会被永久停用：

- 账号状态标记为 `disabled`
- `disable_reason` 记录为 `403 认证失败`
- 需要管理员手动在管理后台重新启用

**例外**：如果账号当前已处于 429 限流冷却期（`rate_limit_reset_at` 未过期），则不会因 403 而永久停用。这是因为限流期间的 403 可能是临时性的误判。

### 9. 手动启停

管理后台账号卡片上提供启用/停用切换按钮：

- **停用**：将账号标记为 `disabled`，`disable_reason` 记录为 `手动停用`
- **启用**：将账号恢复为 `active`，清除 `disable_reason`、`rate_limited_at` 和 `rate_limit_reset_at`

### 10. 请求头改写

后端会对出站请求头做多项处理，包括但不限于：

- 将 `User-Agent` 改写为 `claude-code/<version> (external, cli)`
- 注入或合并 `anthropic-beta`
- 固定 `anthropic-version`
- 保留/还原部分 header wire casing
- 为 API 模式补充 `X-Claude-Code-Session-Id`
- 强制使用真实账号的 `Authorization: Bearer <account.token>`
- 追加 `beta=true` 查询参数

### 11. 请求体改写

根据路径和客户端类型，服务会对不同路径的请求体进行分类改写：

#### `/v1/messages` — 主对话请求

- 注入 Claude Code 系统提示词
- 改写或清理 system 块中的 `cache_control`
- 注入 `metadata.user_id`（使用 `account_uuid` 或衍生 UUID）
- 改写系统提示词中的环境信息
- 写入账号对应的 canonical env / prompt / process 指纹
- 根据 `billing_mode` 对 billing 相关内容做 `strip` 或 `rewrite`
- 清理部分额外遥测字段

#### `/api/event_logging/batch` — 1P 遥测事件

- 改写 `device_id`、`email` 为账号对应值
- 改写 `account_uuid`、`organization_uuid` 为账号配置或衍生值
- 改写 `env`、`process` 指纹数据
- 清理 `baseUrl`、`base_url`、`gateway` 等代理暴露字段
- 解码并改写 `user_attributes` JSON 字符串中的身份信息（`deviceID`、`email`、`accountUUID`、`apiBaseUrlHost` 等）

#### `/api/eval/{clientKey}` — GrowthBook remoteEval

- 改写 `attributes` 中的 `id`、`deviceID`、`email`、`accountUUID`、`organizationUUID`、`subscriptionType`
- 移除 `apiBaseUrlHost` 防止代理主机名泄露
- 对齐 `platform`、`appVersion` 到账号指纹

#### 其他路径

- 通用身份字段改写（`device_id`、`email` 等）

### 12. TLS 指纹与代理

所有上游请求都会通过自定义 `craftls` 客户端发出，以模拟更接近 Node.js 的 TLS 指纹。

每个账号还可以配置自己的代理地址：

- 直连：`proxy_url` 为空
- HTTP 代理：例如 `http://127.0.0.1:7890`
- SOCKS5 代理：例如 `socks5://127.0.0.1:1080`

### 13. AI Gateway 指纹过滤

Claude Code 客户端会主动扫描上游响应头以检测是否经过 AI Gateway 或中间代理。网关会过滤以下前缀的响应头，防止客户端检测并上报：

| 前缀 | 对应平台 |
| --- | --- |
| `x-litellm-` | LiteLLM |
| `helicone-` | Helicone |
| `x-portkey-` | Portkey |
| `cf-aig-` | Cloudflare AI Gateway |
| `x-kong-` | Kong |
| `x-bt-` | BrainTrust |

### 14. 遥测改写

Claude Code 客户端通过三条遥测路径向上游发送使用数据，均经过网关并被改写：

| 路径 | 说明 | 改写内容 |
| --- | --- | --- |
| `/api/event_logging/batch` | 1P BigQuery 事件上报 | device_id、email、account_uuid、organization_uuid、env、process、user_attributes JSON 字符串 |
| `/api/eval/{clientKey}` | GrowthBook remoteEval 实验评估 | attributes 中的 id、deviceID、email、accountUUID、organizationUUID、subscriptionType、apiBaseUrlHost |
| `/v1/messages` | 主对话请求 metadata | user_id（嵌入 account_uuid） |

> **注意**：Datadog 遥测（`browser-intake-datadoghq.com`）由客户端直连发送，不经过 API 网关，因此无法通过网关改写。如需阻止，建议在客户端或网络层面屏蔽该域名。

### 15. 自动遥测拦截

当账号开启了 `auto_telemetry` 功能后，网关在转发请求前会额外执行：

1. **遥测路径拦截**：如果请求路径为遥测端点，直接返回 200 空响应，不转发到上游
2. **会话激活**：如果请求路径为 `/v1/messages`，激活或续期该账号的遥测会话（10 分钟 TTL）
3. **后台发送**：遥测会话激活期间，网关按官方周期自动代发遥测请求

详见 [自动遥测](#自动遥测) 章节。

## 管理后台说明

管理后台默认挂在根路径 `/`，登录成功后可以看到两类页面：

- 账号
- 令牌

### 登录

登录页本质上是对 `/admin/dashboard` 的一次探测请求。

前端行为：

- 将输入的管理员密码放入 `Authorization: Bearer <password>`
- 登录成功后将密码写入浏览器 `localStorage`
- 刷新页面时尝试恢复登录状态

这意味着管理后台适合作为内部运维工具，而不是复杂的多用户权限系统。

### 仪表盘

仪表盘展示：

- 账号总数
- 活跃账号数
- 异常账号数
- 停用账号数
- API Token 总数

### 账号页

账号页支持以下操作：

- 新建账号
- 编辑账号
- 删除账号
- 测试 Token 可用性
- 刷新 OAuth 用量
- OAuth 授权登录（一键生成授权链接、交换令牌、自动填充账号信息）
- 启用/停用账号调度
- 查看停用原因和限流倒计时
- 查看基础状态、并发、优先级、代理、billing 模式和用量窗口
- 查看自动遥测状态、遥测计数和会话过期时间
- 查看设备指纹信息（canonical_env、canonical_prompt_env、canonical_process）

创建账号时常用字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `email` | 是 | 账号邮箱，当前创建逻辑会检查重复 |
| `auth_type` | 否 | 认证类型：`setup_token`（默认）或 `oauth` |
| `setup_token` / `token` | 条件 | Setup Token 模式下必填 |
| `access_token` | 条件 | OAuth 模式下必填 |
| `refresh_token` | 条件 | OAuth 模式下必填 |
| `expires_at` | 否 | OAuth access_token 过期时间（毫秒时间戳） |
| `name` | 否 | 管理后台显示名称 |
| `proxy_url` | 否 | 该账号专用代理 |
| `billing_mode` | 否 | `strip` 或 `rewrite` |
| `account_uuid` | 否 | OAuth Account UUID（强烈推荐填写，用于遥测改写） |
| `organization_uuid` | 否 | OAuth Organization UUID（强烈推荐填写，用于遥测改写） |
| `subscription_type` | 否 | 订阅类型：`max` / `pro` / `team` / `enterprise`（强烈推荐填写） |
| `concurrency` | 否 | 账号最大并发，默认 `3` |
| `priority` | 否 | 数值越小优先级越高，默认 `50` |
| `auto_telemetry` | 否 | 是否开启自动遥测，默认 `false` |

> **关于 `account_uuid`、`organization_uuid`、`subscription_type`**
>
> 这三个字段用于遥测改写。当客户端发送的遥测事件、GrowthBook 实验请求中包含这些身份字段时，网关会使用账号配置的值进行替换。如果未填写，`account_uuid` 会根据 `device_id` 衍生生成；`organization_uuid` 和 `subscription_type` 在客户端原始请求中存在时会被移除。
>
> 推荐通过管理后台的"授权登录"功能自动获取这些字段。也可以从 Claude 客户端登录后的 `~/.claude.json` 的 `oauthAccount` 字段手动获取。

账号认证类型：

- `setup_token`：经典模式，使用 Setup Token 换取临时凭证
- `oauth`：OAuth 模式，直接使用 access_token / refresh_token，网关自动刷新过期令牌

账号状态值：

- `active`
- `error`
- `disabled`

创建账号时系统会自动生成：

- `device_id`
- `canonical_env`
- `canonical_prompt_env`
- `canonical_process`

### 令牌页

令牌页支持以下操作：

- 创建新 API Token
- 编辑令牌名称、允许账号、禁止账号
- 启用/停用令牌
- 删除令牌
- 一键复制完整令牌值

令牌特点：

- 创建时由服务端自动生成，格式为 `sk-` 开头的 64 位字符串
- `allowed_accounts` 和 `blocked_accounts` 都使用逗号分隔的账号 ID
- 令牌状态只有两种：`active` 和 `disabled`

## HTTP API

### 认证方式

#### 管理 API

支持：

- `x-api-key: <ADMIN_PASSWORD>`
- `Authorization: Bearer <ADMIN_PASSWORD>`

#### 网关 API

支持：

- `x-api-key: <sk-...>`
- `Authorization: Bearer <sk-...>`

### 网关接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| 任意方法 | 任意未命中前端、静态资源和管理 API 的路径 | 网关 fallback 透传到上游 |

说明：

- 当前路由层不再显式注册 `/v1/*`、`/api/*`、`/v1/models` 或 `/_health`
- 所有未命中前端页面、`/assets/*`、`/admin/*` 的请求，都会进入网关 fallback
- fallback 会先做 API Token 鉴权，再把原始路径转发到 `https://api.anthropic.com`
- 因此你仍然可以调用 `/v1/messages`、`/api/event_logging/batch` 等路径，但它们现在属于 fallback 路径而不是显式路由

### 管理接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/admin/dashboard` | 仪表盘统计 |
| `GET` | `/admin/accounts` | 分页获取账号列表 |
| `POST` | `/admin/accounts` | 创建账号 |
| `PUT` | `/admin/accounts/:id` | 更新账号 |
| `DELETE` | `/admin/accounts/:id` | 删除账号 |
| `POST` | `/admin/accounts/:id/test` | 测试账号 Token |
| `POST` | `/admin/accounts/:id/usage` | 刷新账号用量 |
| `GET` | `/admin/tokens` | 分页获取令牌列表 |
| `POST` | `/admin/tokens` | 创建令牌 |
| `PUT` | `/admin/tokens/:id` | 更新令牌 |
| `DELETE` | `/admin/tokens/:id` | 删除令牌 |
| `POST` | `/admin/oauth/generate-auth-url` | 生成 OAuth 授权链接（完整权限） |
| `POST` | `/admin/oauth/generate-setup-token-url` | 生成 Setup Token 授权链接（仅推理权限） |
| `POST` | `/admin/oauth/exchange-code` | 交换 OAuth 授权码 |
| `POST` | `/admin/oauth/exchange-setup-token-code` | 交换 Setup Token 授权码 |

### 分页参数

账号列表：

- `page`：默认 `1`
- `page_size`：默认 `12`，最大 `100`

令牌列表：

- `page`：默认 `1`
- `page_size`：默认 `20`，最大 `100`

分页响应结构：

```json
{
  "data": [],
  "total": 0,
  "page": 1,
  "page_size": 12,
  "total_pages": 0
}
```

### 创建账号示例（Setup Token 模式）

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

### 创建账号示例（OAuth 模式）

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
    "proxy_url": "",
    "billing_mode": "rewrite",
    "account_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "organization_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "subscription_type": "max",
    "concurrency": 5,
    "priority": 10,
    "auto_telemetry": true
  }'
```

返回示例：

```json
{
  "id": 1,
  "name": "account-01",
  "email": "user@example.com",
  "status": "active",
  "auth_type": "setup_token",
  "setup_token": "sk-ant-xxxx",
  "proxy_url": "socks5://127.0.0.1:1080",
  "device_id": "generated-device-id",
  "canonical_env": {},
  "canonical_prompt_env": {},
  "canonical_process": {},
  "billing_mode": "strip",
  "account_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "organization_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "subscription_type": "pro",
  "concurrency": 3,
  "priority": 50,
  "auto_telemetry": false,
  "telemetry_count": 0,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

### 更新账号示例

```bash
curl -X PUT http://127.0.0.1:5674/admin/accounts/1 \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{
    "proxy_url": "http://127.0.0.1:7890",
    "billing_mode": "rewrite",
    "concurrency": 5,
    "priority": 10,
    "status": "active",
    "auto_telemetry": true
  }'
```

### 创建令牌示例

```bash
curl -X POST http://127.0.0.1:5674/admin/tokens \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "team-a",
    "allowed_accounts": "1,2",
    "blocked_accounts": ""
  }'
```

返回示例：

```json
{
  "id": 1,
  "name": "team-a",
  "token": "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "allowed_accounts": "1,2",
  "blocked_accounts": "",
  "status": "active",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

### 使用网关调用上游示例

```bash
curl http://127.0.0.1:5674/v1/messages \
  -H "Authorization: Bearer sk-your-gateway-token" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet-4-6",
    "max_tokens": 128,
    "messages": [
      { "role": "user", "content": "hello" }
    ]
  }'
```

### 当前保留路径

以下路径不会进入网关 fallback：

- `/`
- `/login`
- `/tokens`
- `/favicon.svg`
- `/assets/*`
- `/admin/*`

如果你打算为网关增加新的内部端点，建议避免与这些路径冲突。

### 测试账号示例

```bash
curl -X POST http://127.0.0.1:5674/admin/accounts/1/test \
  -H "Authorization: Bearer admin"
```

返回：

```json
{
  "status": "ok"
}
```

或者：

```json
{
  "status": "error",
  "message": "internal: token invalid: status 401 Unauthorized"
}
```

### 刷新用量示例

```bash
curl -X POST http://127.0.0.1:5674/admin/accounts/1/usage \
  -H "Authorization: Bearer admin"
```

成功时返回：

```json
{
  "status": "ok",
  "usage": {
    "five_hour": {
      "utilization": 0.32,
      "resets_at": "2026-01-01T05:00:00Z"
    },
    "seven_day": {
      "utilization": 0.21,
      "resets_at": "2026-01-08T00:00:00Z"
    },
    "seven_day_sonnet": {
      "utilization": 0.44,
      "resets_at": "2026-01-08T00:00:00Z"
    }
  }
}
```

### 错误响应格式

统一错误响应形如：

```json
{
  "error": "..."
}
```

典型状态码包括：

- `400 Bad Request`
- `401 Unauthorized`
- `404 Not Found`
- `429 Too Many Requests`
- `502 Bad Gateway`
- `503 Service Unavailable`
- `500 Internal Server Error`

## 数据与存储

### `accounts` 表

账号表核心字段包括：

| 字段 | 说明 |
| --- | --- |
| `id` | 账号主键 |
| `name` | 账号名称 |
| `email` | 邮箱，当前创建逻辑会检查重复 |
| `status` | `active` / `error` / `disabled` |
| `auth_type` | 认证类型：`setup_token` / `oauth` |
| `token` | Setup Token |
| `access_token` | OAuth access token |
| `refresh_token` | OAuth refresh token |
| `oauth_expires_at` | OAuth access token 过期时间 |
| `oauth_refreshed_at` | 最近一次 OAuth 刷新时间 |
| `auth_error` | 认证错误信息 |
| `proxy_url` | 该账号使用的代理 |
| `device_id` | 自动生成的设备 ID |
| `canonical_env` | 环境指纹 JSON |
| `canonical_prompt_env` | 系统提示词环境改写数据 |
| `canonical_process` | 硬件与进程指纹配置 |
| `billing_mode` | `strip` 或 `rewrite` |
| `account_uuid` | OAuth Account UUID，用于遥测改写 |
| `organization_uuid` | OAuth Organization UUID，用于遥测改写 |
| `subscription_type` | 订阅类型：`max` / `pro` / `team` / `enterprise` |
| `concurrency` | 最大并发 |
| `priority` | 调度优先级，数值越小优先级越高 |
| `rate_limited_at` | 最近一次被标记限流的时间 |
| `rate_limit_reset_at` | 限流恢复时间 |
| `disable_reason` | 停用原因：`429 速率限制`、`403 认证失败`、`手动停用` |
| `usage_data` | OAuth 用量原始缓存 |
| `usage_fetched_at` | 最近一次刷新用量时间 |
| `auto_telemetry` | 是否开启自动遥测 |
| `telemetry_count` | 累计发送的遥测请求次数 |

### `api_tokens` 表

API Token 表核心字段包括：

| 字段 | 说明 |
| --- | --- |
| `id` | 主键 |
| `name` | 令牌名称 |
| `token` | 自动生成的 `sk-...` 令牌 |
| `allowed_accounts` | 允许使用的账号 ID 列表 |
| `blocked_accounts` | 禁止使用的账号 ID 列表 |
| `status` | `active` / `disabled` |

### 自动迁移

服务启动时会自动执行内建迁移逻辑：

- 创建 `accounts` 表
- 创建 `api_tokens` 表
- 对部分历史字段执行增量 `ALTER TABLE`

这套迁移逻辑是代码内嵌 SQL，不依赖外部 migration 文件。

## CI/CD 与发布

项目通过根目录 `.version` 文件描述发布版本信息，当前字段包括：

```env
project_name=claude-code-gateway
version=1.4.0
image_name=ghcr.io/mamoworks/claude-code-gateway
```

注意：

- GitHub Actions 发布流程读取的是 `.version`
- 它不依赖 `Cargo.toml` 里的 crate version 作为发布版本号

### 当前工作流触发规则

仓库当前只有一个发布工作流：

- 文件：`.github/workflows/release.yml`
- 自动触发条件：
  - 推送到 `main`
  - 且本次 push 包含 `.version` 文件变更
- 手动触发条件：
  - `workflow_dispatch`

### 发布流程会做什么

工作流会自动执行：

- 读取 `.version`
- 构建前端并上传中间产物
- 构建多平台二进制：
  - Linux x86_64
  - Linux arm64
  - Windows x86_64
- 构建并推送 GHCR 多架构 Docker 镜像
- 创建 GitHub Release，并附带压缩后的二进制产物

### Docker 镜像标签

工作流会推送以下标签：

- `latest`
- `<version>`
- `v<version>`

### 典型发布步骤

1. 修改 `.version` 中的 `version`
2. 将变更合入或推送到 `main`
3. 等待 GitHub Actions 自动构建和发布

如果不想通过自动触发，也可以在 GitHub Actions 页面手动运行工作流。

## 项目结构

```text
.
├── .github/workflows/       # GitHub Actions 发布流程
├── craftls/                 # 自定义 rustls 分支，用于 TLS 指纹伪装
├── dist/                    # 构建产物输出目录
├── docker/                  # Dockerfile 与 docker-compose.yml
├── scripts/                 # 开发与构建脚本
├── src/
│   ├── main.rs              # 程序入口
│   ├── config.rs            # 环境变量加载
│   ├── error.rs             # 统一错误类型与 HTTP 响应映射
│   ├── handler/             # 路由组装与 HTTP handler
│   ├── middleware/          # 管理密码与网关令牌鉴权
│   ├── model/               # Account / ApiToken / Identity 模型
│   ├── service/             # Gateway / Account / OAuth / OAuthFlow / Telemetry / Rewriter 业务逻辑
│   ├── store/               # 数据库与缓存访问层
│   └── tlsfp/               # 自定义 TLS 指纹客户端
├── web/
│   ├── src/                 # Vue 3 前端源码
│   │   ├── components/      # 页面组件与基础 UI 组件
│   │   ├── composables/     # 前端组合式逻辑
│   │   ├── lib/             # 前端工具函数
│   │   ├── api.ts           # 管理后台 API 封装
│   │   ├── router.ts        # 前端路由
│   │   ├── main.ts          # 前端入口
│   │   └── style.css        # 全局样式
│   ├── dist/                # 前端构建结果（运行时由后端读取）
│   ├── package.json         # 前端依赖与脚本
│   └── vite.config.ts       # Vite 配置与本地代理
├── .env.example             # 配置模板
├── .version                 # 发布版本与镜像名
├── Cargo.toml               # Rust 项目清单
└── README.md
```

## OAuth 授权登录

管理后台内置了 OAuth PKCE 授权流程，可以直接在页面上完成账号授权，无需手动复制 token。

### 授权流程

1. 在管理后台"账号"页面点击"授权登录"
2. 选择授权模式：
   - **OAuth（完整权限）**：获取 `access_token` + `refresh_token`，拥有完整的 OAuth 权限范围（`user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload`）
   - **Setup Token（仅推理）**：获取有效期 365 天的 `access_token`，仅包含 `user:inference` 权限
3. 可选填写代理地址（用于网络受限环境下的令牌交换）
4. 点击生成，复制授权链接到浏览器中完成 Claude 登录授权
5. 授权完成后，浏览器会跳转到回调页面，从 URL 中复制 `code` 参数
6. 将 `code` 粘贴到管理后台的输入框中，点击交换
7. 系统自动获取 `access_token`、`refresh_token`（OAuth 模式）、`account_uuid`、`organization_uuid`、`email` 等信息
8. 点击"应用到新账号"，将结果自动填入创建账号表单

### OAuth API

#### 生成授权链接

```bash
# OAuth 完整权限
curl -X POST http://127.0.0.1:5674/admin/oauth/generate-auth-url \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{"proxy_url": ""}'

# Setup Token 仅推理
curl -X POST http://127.0.0.1:5674/admin/oauth/generate-setup-token-url \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{"proxy_url": ""}'
```

返回：

```json
{
  "auth_url": "https://claude.ai/oauth/authorize?client_id=...&code_challenge=...&state=...",
  "session_id": "base64url-encoded-state"
}
```

#### 交换授权码

```bash
# OAuth 完整权限
curl -X POST http://127.0.0.1:5674/admin/oauth/exchange-code \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "...", "code": "..."}'

# Setup Token
curl -X POST http://127.0.0.1:5674/admin/oauth/exchange-setup-token-code \
  -H "Authorization: Bearer admin" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "...", "code": "..."}'
```

返回：

```json
{
  "access_token": "ant-oc_xxxx",
  "refresh_token": "ant-rt_xxxx",
  "expires_in": 3600,
  "expires_at": 1735689600,
  "scope": "user:profile user:inference ...",
  "account_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "organization_uuid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "email_address": "user@example.com"
}
```

> **注意**：授权会话有效期 30 分钟，生成授权链接后需在此时间内完成授权码交换。

## 自动停用与手动启停

### 自动停用

网关会根据上游响应自动处理异常账号：

| 上游状态码 | 行为 | 持续时间 | `disable_reason` |
| --- | --- | --- | --- |
| `429` | 暂停调度，状态保持 `active` | 5 小时 | `429 速率限制` |
| `403` | 永久停用，状态改为 `disabled` | 直到手动启用 | `403 认证失败` |

**429 处理细节**：
- 账号保持 `active` 状态，但 `rate_limit_reset_at` 设为 5 小时后
- 冷却期内 `is_schedulable()` 返回 `false`，账号不参与调度
- 冷却期结束后自动恢复

**403 处理细节**：
- 如果账号当前已在 429 限流冷却期内，跳过永久停用（避免误判）
- 否则将账号标记为 `disabled`，需要管理员手动启用

### 手动启停

管理后台账号卡片上提供启用/停用切换按钮：

- **停用**：`PUT /admin/accounts/:id` 传入 `{"status": "disabled"}`，`disable_reason` 记录为 `手动停用`
- **启用**：`PUT /admin/accounts/:id` 传入 `{"status": "active"}`，清除 `disable_reason`、`rate_limited_at` 和 `rate_limit_reset_at`

前端会显示：
- 停用原因（`429 速率限制`、`403 认证失败`、`手动停用`）
- 429 限流时的剩余冷却时间倒计时（格式如 `4h23m15s`）

## 自动遥测

自动遥测功能允许网关代替客户端发送遥测数据，模拟真实 Claude Code 客户端行为。开启后，网关会：

1. **拦截客户端遥测请求**：对遥测路径返回 200 空响应，不转发到上游
2. **代为发送遥测**：由网关按照官方周期主动发送遥测请求，使用账号自身的设备指纹信息

### 启用方式

在创建或编辑账号时，将 `auto_telemetry` 设置为 `true`。

### 工作机制

- **触发条件**：当开启了自动遥测的账号收到 `/v1/messages` 请求时，网关自动激活该账号的遥测会话
- **会话 TTL**：10 分钟。每次 `/v1/messages` 请求都会将过期时间重置为 10 分钟后。无新请求后，会话自动过期并停止后台发送
- **遥测计数**：每次成功发送遥测请求后，账号的 `telemetry_count` 自动递增并持久化到数据库

### 自动发送的遥测端点

| 端点 | 发送周期 | 说明 |
| --- | --- | --- |
| `POST /api/event_logging/batch` | 每 10 秒 | 1P 事件上报，构造 `tengu_api_success` 等心跳事件 |
| `POST /api/eval/sdk-zAZezfDKGoZuXXKe` | 每 6 小时 | GrowthBook 实验评估，记录上次发送时间避免重复 |

> **注意**：`/api/claude_code/metrics` 端点因不支持 OAuth 认证而被跳过。Datadog 遥测由客户端直连发送，不经过网关。

### 拦截的遥测路径

当账号开启自动遥测后，以下路径的客户端请求会被网关拦截（返回 200 但不转发）：

- `/api/event_logging/batch`
- `/api/eval/*`
- `/api/claude_code/metrics`
- `/api/claude_code/organizations/metrics_enabled`（返回 `{"metrics_logging_enabled": true}`）

### 前端显示

管理后台账号卡片上会显示：

- 自动遥测状态（已开启/关闭）
- 累计发送的遥测次数
- 当前遥测会话的过期时间（活跃时显示）

## 限制与注意事项

### 1. TLS 配置项目前尚未真正接入 HTTPS 监听

`TLS_CERT_FILE` 和 `TLS_KEY_FILE` 已经出现在配置结构中，但当前服务监听逻辑仍然是普通 TCP + HTTP，并没有实际启用 TLS 终止。

如果你需要 HTTPS，请优先使用：

- Nginx
- Caddy
- Traefik

等反向代理在前面做 TLS 终止。

### 2. 当前不再显式提供 `/_health` 与 `/v1/models`

当前路由结构已经改成：

- 前端与管理 API 显式注册
- 其余全部走网关 fallback

这意味着：

- `/_health` 已不再是后端显式端点
- `/v1/models` 也不再是本地静态返回端点
- 如果请求这些路径，会按普通网关请求处理，并尝试转发到上游

如果后续仍需要本地健康检查或本地模型列表，需要重新显式注册对应路由。

### 3. Token 以明文形式保存在数据库中

当前实现中：

- 账号 `token`（Setup Token）
- 账号 `access_token` / `refresh_token`（OAuth 凭证）
- 网关 `api_tokens.token`

都以明文形式存储在数据库表中，没有额外加密层。请务必保证数据库和备份介质的访问控制。

### 4. 管理后台是单共享密码模型

当前没有多用户系统，也没有细粒度权限控制。浏览器登录后会把密码写入 `localStorage` 以便恢复会话，因此建议：

- 使用高强度管理员密码
- 仅在可信网络环境使用管理后台
- 结合反向代理做访问控制

### 5. 多实例部署请启用 Redis

如果你部署多个 `claude-code-gateway` 实例但没有 Redis，那么：

- 会话粘性只在单个进程内生效
- 并发计数无法跨实例共享

这会导致调度行为与并发限制不再全局一致。

### 6. `scripts/dev.sh` 与 `scripts/dev.bat` 会自动检测前端变更

它们会比较前端源码文件的时间戳与 `web/dist` 的时间戳，仅在源码有更新时重新构建前端。对前端进行高频开发时，仍建议使用 `npm run dev` 以获得热更新体验。

### 7. Datadog 遥测无法通过网关拦截

Claude Code 客户端会直连 `browser-intake-datadoghq.com` 发送 Datadog 遥测数据（包含 device_id、session_id、env 等），这些请求不经过 API 网关。如需阻止，建议通过 hosts 文件或网络防火墙屏蔽该域名。

### 8. 版本号与构建时间为静态硬编码

当前 identity 模块中的 Claude Code 版本号和构建时间是静态硬编码值。当 Claude Code 客户端更新后，需要手动同步更新这些值以保持指纹一致性。

## 许可与依赖说明

项目包含自定义 `craftls` 目录作为 TLS 指纹能力的一部分。发布和分发时，建议一并检查该目录下附带的许可证文件，并根据你的使用方式决定如何在最终发行物中保留许可证说明。
