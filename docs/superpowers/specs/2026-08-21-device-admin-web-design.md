# 设备管理 Web 后台设计

状态：已批准
日期：2026-08-21
任务：`TASK-0007`

## 决策摘要

新增独立 Go 管理服务，不把 HTTP 管理接口编入 TCP 设备网关。管理服务复用现有 `deviceadmin.Service` 和 PostgreSQL 设备注册表，只监听服务器回环地址，由部署者把任意 HTTPS 域名反向代理到该地址。域名、证书、管理员密码和 Session 密钥均不进入代码或公开仓库。

首版使用管理员账号加密码登录。管理员账号和密码哈希保存在 PostgreSQL；密码采用 Argon2id，Session 使用高熵随机令牌且数据库只保存令牌摘要。界面支持设备添加、列表、停用、恢复、修改到期时间、管理员修改密码和审计查看，不提供 Credential 明文查看或设备删除。

## 已考虑的方案

### 方案 A：独立 Go 管理服务（选定）

管理面与设备数据面分开运行。后台重启、登录攻击或页面错误不会影响 TCP 长连接网关；后台可以使用更严格的 HTTP 安全策略和独立资源限制。它复用领域服务而不是复制 SQL，是当前规模下边界最清晰的方案。

### 方案 B：管理 HTTP 接口并入网关

镜像和部署项更少，但会让公网 HTTP 认证、静态文件和设备 TCP 处理共享进程、依赖和故障域。后台攻击面会直接扩大核心网关攻击面，因此拒绝。

### 方案 C：接回旧 PHP 后台

可能复用部分页面，但会重新引入旧运行时、旧依赖和数据库耦合，也无法保证与新注册表的审计和秘密边界一致，因此拒绝。

## 系统边界

新增组件：

- `admin-web`：HTTP 服务、登录、Session、CSRF、页面和 JSON API。
- `admin-user`：仅在服务器本机运行的管理员创建/重置命令，密码从终端隐藏输入读取。
- `adminauth`：密码哈希、Session 和登录限流领域逻辑。
- `adminhttp`：路由、输入验证、安全响应和嵌入式静态资源。

保持不变的组件：

- `gateway` 继续只处理 TCP/Protobuf、设备会话和注册表鉴权。
- `deviceadmin.Service` 继续负责设备领域校验和管理操作。
- PostgreSQL 继续是唯一设备注册表；不增加旧 MySQL 运行时依赖。

`admin-web` 与 `gateway` 共享 PostgreSQL 和 pepper secret，但不共享进程、监听端口或容器镜像。管理服务无法读取 Credential 明文，因为数据库从未保存明文。

## 部署与域名

管理服务默认监听 `127.0.0.1:18181`；Compose 模式仅在显式容器配置下监听容器网络，并且容器端口仍只发布到宿主机回环地址。显式容器模式才信任由该受控入口重建的代理头，因此回环发布不得改为公网绑定。部署文档提供由部署者填写 `server_name` 的通用 Nginx 反向代理片段，因此可以使用任意域名；应用不根据 Host 生成安全决策，也不把域名编译进前端资源。

公网入口必须由 Nginx/宝塔终止 HTTPS，并转发标准代理头。生产模式只接受被可信反向代理标记为 HTTPS 的请求；直接访问回环端口仅用于服务器本机健康检查。未配置 HTTPS 时不得开放公网后台。

PostgreSQL 保持内部 Docker 网络且不发布端口。`admin-web` 使用非 root 用户、只读根文件系统、删除 capabilities、`no-new-privileges`、临时目录和独立 CPU/内存/PID 上限。

## 管理员数据模型

新增 `admin_users`：

- `id`：内部 UUID。
- `username`：显示名称，首版仅允许 3—64 位 ASCII 字母、数字、点、下划线和连字符。
- `username_normalized`：小写规范化值，唯一索引用于登录。
- `password_hash`：包含 Argon2id 版本、参数、盐和摘要的编码字符串。
- `status`：`active` 或 `disabled`。
- `password_version`：修改或重置密码时递增，用于使旧 Session 失效。
- `last_login_at`、`created_at`、`updated_at`：管理时间；不记录源 IP。

新增 `admin_sessions`：

- 数据库只保存 32 字节随机 Session Token 的 SHA-256 摘要。
- 关联管理员 ID 和创建时的 `password_version`。
- 保存到期时间、最后使用时间和撤销时间。
- Session 最长八小时，空闲一小时失效；每次请求不必写库，最后使用时间按固定窗口合并更新。

随机 Session Token 具有足够熵，因此这里使用 SHA-256 作为不可逆索引，不用于保护可枚举设备编号。密码仍必须使用 Argon2id，设备编号仍必须使用现有 pepper HMAC。

设备管理审计继续使用 `device_admin_events`，迁移扩展 `actor_type` 以支持 `admin_web`。另建固定枚举的管理员安全事件，用于记录账号创建、密码修改和本机重置；事件不保存密码、Session、Credential、指纹、完整源 IP或自由文本。

## 管理员初始化和恢复

首次部署不提供公网自助注册。运维人员在服务器终端运行 `admin-user create`，输入用户名并隐藏输入两次密码。命令在本机计算 Argon2id 后写入数据库，终端和日志不输出密码。

忘记密码时使用 `admin-user reset-password`。重置会递增 `password_version` 并撤销该管理员全部 Session。首版不发送邮件、短信或恢复链接。

## 登录与 Session 安全

- Argon2id 使用固定、可版本化的安全参数和每个密码独立随机盐；参数在测试中设较小值，生产使用至少 64 MiB 内存、3 次迭代和 32 字节输出。
- 用户名不存在、密码错误、账号停用和内部错误向客户端返回相同的登录失败文案。
- 按完整用户名摘要和反向代理提供的来源地址进行进程内令牌桶限制；地址不写入日志或数据库。
- 登录成功后轮换 Session，Cookie 设置 `Secure`、`HttpOnly`、`SameSite=Strict`、固定 Path，且不设置跨子域 Domain。
- 所有修改请求要求同源检查和同步器 CSRF Token；Token 只存在于当前 Session 和页面，不进入日志。
- 修改密码后递增 `password_version`，撤销其他 Session，并为当前浏览器重新签发 Session。
- 响应设置严格 CSP、`frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、不缓存管理页面和合理的 Referrer Policy。
- 所有数据库和内部错误转换为固定外部错误码，不向页面返回 SQL、文件路径或配置细节。

## 页面和功能

前端采用嵌入 Go 二进制的原生 HTML、CSS 和少量 JavaScript，不引入外部 CDN、Node 构建链或第三方前端运行时。

首版页面：

1. 登录页：管理员账号、密码和统一错误提示。
2. 设备列表：标签、内部 UUID、状态、到期时间、最后成功鉴权时间；不显示 Credential 或指纹。
3. 添加设备弹窗：设备编号、标签、初始状态以及永久或明确的到期时间。设备编号使用密码型输入，不提供回显或复制。
4. 设备操作：停用、恢复、修改到期时间；高影响操作要求二次确认。
5. 操作记录：固定动作、目标内部 UUID、管理员账号和时间。
6. 账号设置：修改当前管理员密码和退出登录。

列表首版最多支持一千台设备，与当前单网关百台目标匹配；分页和搜索在设备数量实际超过该范围后再设计。空列表、数据库暂时不可用、重复添加和会话过期均提供明确但不泄密的用户提示。

## HTTP 接口

所有接口位于 `/api/admin/v1`，使用 JSON，修改接口要求有效 Session 和 CSRF Token：

- `POST /session`：登录并创建 Session。
- `DELETE /session`：退出并撤销当前 Session。
- `GET /me`：返回当前管理员的非敏感信息和新的 CSRF Token。
- `PUT /me/password`：修改密码并轮换 Session。
- `GET /devices`：返回安全设备视图。
- `POST /devices`：添加设备；Credential 只存在于请求处理内存并在计算 HMAC 后丢弃。
- `PUT /devices/{id}/status`：启用或停用。
- `PUT /devices/{id}/expiry`：设置永久或 RFC3339 到期时间。
- `GET /device-events`：返回固定字段的设备管理审计记录。

接口不提供删除、Credential 查询、指纹查询、批量 SQL、任意原因文本或数据库直通能力。请求体设置严格大小上限，JSON 拒绝未知字段和尾随数据。

## 数据流

添加设备：浏览器通过 HTTPS 提交设备编号 → Nginx 转发到回环 `admin-web` → Session/CSRF/输入校验 → `deviceadmin.Service.Add` 立即计算 HMAC → PostgreSQL 只保存指纹和非敏感元数据 → 页面只收到内部 UUID。

停用设备：后台调用现有设备仓储事务更新状态和写入审计事件 → PostgreSQL 通知现有网关监听器 → 网关按内部 UUID 关闭在线连接。后台不直接访问网关进程。

登录：浏览器提交账号密码 → 登录限流 → 查询规范化账号 → Argon2id 常量时间验证 → 生成随机 Session/CSRF Token → 数据库保存摘要 → 浏览器获得安全 Cookie。

## 错误与可观测性

日志只记录稳定事件类别、HTTP 状态、耗时和请求关联 ID。禁止记录用户名原文、密码、Session、CSRF Token、Credential、指纹、完整源 IP、请求体、数据库 DSN 或 SQL 参数。

健康端点分为存活和就绪；就绪要求数据库可用。认证失败、CSRF 拒绝、输入拒绝、数据库不可用和限流使用不同内部计数，但外部错误保持最小化。管理员操作成功依靠数据库审计表追溯，不依靠访问日志保存敏感上下文。

## 测试策略

- 密码测试：Argon2id 编码/验证、随机盐、错误密码、参数边界和密码修改失效。
- Session 测试：随机令牌、摘要存储、过期、空闲、撤销、密码版本和并发使用。
- HTTP 测试：未登录拒绝、登录统一失败、安全 Cookie、CSRF、同源、JSON 严格解析、安全响应头和错误脱敏。
- 设备操作测试：添加、重复、启停、到期和审计，复用合成 Credential。
- PostgreSQL 16 集成测试：迁移、约束、事务、Session 和审计。
- 容器 smoke：只读/非 root/资源上限、回环端口、内部数据库、管理员初始化、登录、设备全生命周期和服务重启。
- 完整验证：`go test ./... -count=1`、`go test -race ./... -count=1`、`go vet ./...`、PostgreSQL 集成和容器 smoke。

## 部署与切换

1. 在现有隔离候选中先运行数据库迁移，再通过服务器本机创建首个管理员。
2. 启动只绑定回环端口的 `admin-web`，先用服务器本机和合成设备验证。
3. 部署者解析任意域名，在 Nginx/宝塔配置 HTTPS 和反向代理；确认 HTTP 自动跳转 HTTPS。
4. 登录后台添加一台真实设备，通过候选 TCP 端口完成真实 APK 鉴权。
5. 真实验证通过后才把新网关切换到公网 `19090`。
6. 后台失败时回滚后台镜像，不回滚或删除设备注册表；网关继续独立运行。

## 后续阶段

- 多管理员角色和权限。
- TOTP、Passkey 或企业身份提供商。
- 设备分页、搜索、批量导入和导出非敏感元数据。
- 后台管理模型、记忆、知识库和客服运营功能；这些能力分别建立新任务和安全边界。
