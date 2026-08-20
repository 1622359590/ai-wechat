# 部署与容量基线

状态：本机多设备注册表 staging 已验证；远程仍为旧 deny-all/单设备候选，尚未切换
最后更新：2026-08-20

## 当前可运行部署

`deploy/smoke.sh` 会创建完全临时的本机 Docker 项目，用随机合成 Credential、随机 pepper 和一次性 PostgreSQL 数据卷执行多设备注册表验证，完成后自动删除容器、网络、数据卷和临时密钥。它不读取真实设备、旧数据库、客户数据或公网入口。

- TCP/健康检查：smoke 自动选择空闲的本机回环端口，避免影响现有 staging
- 容器：非 root UID/GID `65532:65532`、只读根文件系统、删除全部 Linux capabilities、启用 `no-new-privileges`
- 限额：1 CPU、256 MiB 内存、100 PID，默认最大消息体 1 MiB
- 镜像：网关 scratch 运行时只包含 `gateway` 和 CA 根证书；管理/导入二进制只存在于独立 tools 镜像
- 数据库：PostgreSQL 16 只加入内部 registry 网络，不发布主机端口；迁移成功后网关才启动

本机启动或重建：

```sh
./deploy/smoke.sh
```

smoke 会自行清理，不需要手动停止。若要长期运行 Compose，先在仓库外创建 PostgreSQL 密码、单行无换行 DSN 和正好 32 字节 pepper 文件，将权限设为 `0600`，再通过 `POSTGRES_PASSWORD_FILE`、`DEVICE_DATABASE_DSN_FILE`、`DEVICE_PEPPER_FILE` 指向它们后执行 `docker compose -f deploy/compose.yaml up -d --build`。不要把真实路径或内容写进 Compose 或仓库。

## 鉴权模式

网关只接受显式的 `GATEWAY_AUTH_MODE`：`deny-all`、`pairing` 或 `device-registry`。未设置时默认为 `deny-all`。不同模式的变量不能混用，部分配置会直接拒绝启动。

### 一次性设备配对（仅回滚/受控测试）

网关默认仍使用 `deny-all`。本机 Compose 只挂载 Git 忽略的 `deploy/state/` 到容器内专用目录，不设置配对环境变量，也不会自动接收设备。服务器目录必须只允许容器 UID/GID `65532:65532` 访问；状态文件由网关以 `0600` 创建，禁止复制到仓库、日志或聊天。

配置项：

| 环境变量 | 含义 | 安全要求 |
|---|---|---|
| `GATEWAY_AUTH_MODE` | 鉴权模式 | 配对时必须显式设为 `pairing` |
| `GATEWAY_PAIRING_STATE_FILE` | 容器内状态文件路径 | 必须是 `/var/lib/ai-wechat/pairing/` 下的绝对路径 |
| `GATEWAY_PAIRING_ENABLED` | 是否开启首次配对窗口 | 仅首次配对临时设为 `true`；非法布尔值会拒绝启动 |
| `GATEWAY_PAIRING_ALLOWED_CIDRS` | 首次配对允许来源 | 开启配对时必填，使用逗号分隔的最窄 CIDR；锁定后删除 |

安全启用顺序：

1. 先使用 `GATEWAY_AUTH_MODE=deny-all` 且不设置其他鉴权变量部署候选镜像，确认容器健康。
2. 在服务器创建专用状态目录并设置 UID/GID `65532:65532`，不要在仓库内创建真实状态文件。
3. 设置状态文件路径，临时开启配对，并填入服务器现场确认的单设备最窄 CIDR。文档地址如 `192.0.2.8/32` 仅为示例，不能直接用于真实部署。
4. 第一台设备成功后，将配对开关设为 `false` 并删除 CIDR，只保留 `GATEWAY_AUTH_MODE=pairing` 和状态文件路径后重启。此时配对记录锁定，网络变化不会覆盖已配对设备。
5. 重新配对必须由运维人员先停服务并安全移走旧状态文件；应用没有远程清除接口。

状态文件损坏、版本错误或权限不是 `0600` 时，网关拒绝启动。状态只包含 Credential 的 SHA-256 允许列表指纹和创建时间；该指纹仍属于服务器秘密，不能公开。

### 多设备注册表

正式多设备模式使用 `GATEWAY_AUTH_MODE=device-registry`，并要求以下两个容器内文件路径：

| 环境变量 | 文件内容 | 安全要求 |
|---|---|---|
| `GATEWAY_DEVICE_DATABASE_DSN_FILE` | 单行 PostgreSQL DSN | 绝对路径、普通文件、非符号链接、权限 `0400` 或 `0600`；不得含 CR/LF/NUL |
| `GATEWAY_DEVICE_PEPPER_FILE` | 正好 32 字节随机二进制 pepper | 同上；必须建立服务器外加密备份，丢失后现有设备指纹无法查询 |

注册表模式启动时只连接并验证 PostgreSQL，不自动修改数据库结构；Compose 的一次性 `migrate` 容器必须成功退出，网关才会启动。数据库不可用、表未迁移、任一密钥文件缺失或权限不安全时均拒绝启动。网关运行时只依赖新 PostgreSQL 注册表，不读取旧数据库或配对状态文件。`prepare-secrets` 一次性容器将外部文件复制为 UID/GID `65532:65532`、模式 `0400` 的 Docker 卷文件；网关只读挂载该卷。

默认连接保护为：最多 50 个未鉴权连接、每个来源 IP 最多 5 个未鉴权连接、最多 150 个已鉴权设备连接；环境变量分别为 `GATEWAY_MAX_UNAUTHENTICATED_CONNECTIONS`、`GATEWAY_MAX_UNAUTHENTICATED_PER_IP` 和 `GATEWAY_MAX_AUTHENTICATED_CONNECTIONS`，均只接受正整数。

设备 Credential 仅在请求处理中用于计算 `HMAC-SHA-256`，数据库只存 32 字节指纹。认证尝试还受每 IP 令牌桶和每设备指数退避限制；停用或修改设备后，PostgreSQL 管理事件会关闭该设备当前连接，监听器断线后按事件游标补偿。

### 设备管理与一次性导入

`device-admin` 是本地受控命令，支持 `migrate`、`add`、`list`、`enable`、`disable` 和 `set-expiry`。每个子命令都必须显式传入 `--database-dsn-file` 和 `--pepper-file`；`add` 只从标准输入读取一条 Credential，终端输入隐藏，重定向输入必须是唯一一行并以 LF 结束。命令输出只包含内部 UUID、标签、状态和时间，不显示 Credential、指纹或 Token。

Compose 中的 `tools` 服务带 profile，不会常驻启动。受控管理示例：

```sh
docker compose -f deploy/compose.yaml run --rm tools list \
  --database-dsn-file /run/secrets/device_database_dsn \
  --pepper-file /run/secrets/device_pepper
```

新增设备时不要把 Credential 写进命令行参数；直接运行同一命令的 `add` 子命令并在隐藏提示中输入。

`device-import` 只用于一次性旧库迁移，必须同时提供 `--legacy-dsn-file`、`--database-dsn-file`、`--pepper-file`、`--query-file`，可先加 `--dry-run`。四个文件都必须是权限 `0400`/`0600` 的非符号链接普通文件；私有查询文件最大 64 KiB，且必须只返回 `credential`、`status`、`auth_expires_at` 三个别名。查询文件、旧库表字段、DSN 和真实计数不得进入仓库或日志。

导入器用只读、单连接、带超时的 MySQL 事务读取并验证完整批次，随后才打开新库写事务。任一无效记录会使本批次零写入；重复指纹只计数，不修改新库中已有设备的状态、到期时间或标签。输出只有 `total/imported/duplicates/rejected/dry_run` 聚合值。迁移验证完成后，应从运行环境移除旧库 DSN 和私有查询文件。

## 远程 staging

2026-08-20 已通过宝塔面板在一台 Alibaba Cloud Linux 3、x86-64 测试服务器上更新候选部署。公开仓库不记录服务器 IP、面板入口、来源地址或凭据。

- 部署目录：`/opt/ai-wechat-gateway`
- 镜像：与提交 `ac1bca6` 对应的远程候选镜像
- 运行方式：宝塔 Docker Compose 项目 `ai-wechat-gateway`
- TCP：配对测试期间由主机防火墙限制为单一现场来源；完成测试后必须重新收口
- 健康检查：远程主机 `127.0.0.1:18080`
- 限额：1 CPU、256 MiB、100 PID
- 安全：UID/GID `65532:65532`、只读根文件系统、`cap_drop: ALL`、`no-new-privileges`
- 产物：Linux AMD64 静态二进制，SHA-256 `cf7d9a687b9ff31510cc9f63a6cc3804dbcb42d629d451f3e6c9a1f8aeeffadd`

服务器端实际验证结果：容器 `running` 且 `healthy`，重启次数为 0；`/livez`、`/readyz` 均返回 200；异常 TCP 帧后仍为 `healthy` 且无重启；`ss` 确认 18080/19090 仅监听 `127.0.0.1`。空载采样约使用 2.1 MiB 容器内存、5 个 PID 和接近 0% CPU；该数字只代表无设备连接的存活基线，不是容量结论。

远程环境当前只用于单设备 staging。真实鉴权适配与临时单来源防火墙限制已部署，但首次配对尚未发生；TLS 或受控专网入口、持久化防火墙规则、面板 HTTPS、面板凭据轮换和系统安全更新评估仍未完成。

## 容量驱动因素

注册设备数不是唯一指标。容量测试必须同时给出在线连接数、每秒入站/出站消息、平均/峰值帧长、媒体比例、模型并发、数据保留期和可用性目标。

## 建议环境

| 环境 | 计算资源起点 | 数据组件 | 适用范围 |
|---|---|---|---|
| 本地开发 | 开发机 Docker Compose | PostgreSQL、Redis 本地容器 | 合成数据和单元/集成测试 |
| 小规模试点 | 1×4核8G 或 1×8核16G | 托管 PostgreSQL、Redis 或同机非生产实例 | 功能验证，不能承诺高可用 |
| 约 1,000 台设备 | 2×4核8G 网关/应用起步 | PostgreSQL 4核8G、Redis 4GB、对象存储 | 实际日活和吞吐压测后调整 |
| 约 10,000 台设备 | 2×8核16G 网关 + 2×8核16G 应用/Worker 起步 | PostgreSQL 4–8核16–32G、Redis 8–16GB | 双可用区、独立队列与监控 |
| 约 50,000 台设备 | 分片网关池与独立 Worker 池 | 高可用数据库、Redis 集群、分区存储 | 必须用真实流量模型专项设计 |

表中资源只是预算起点，不是容量承诺。Go 网关在协议恢复后需要连接压测和消息回放，才能给出每实例安全上限。

## 生产最低配置原则

- 至少两个无状态网关实例，通过 Redis/注册中心公布设备所在实例。
- PostgreSQL 启用自动备份、时间点恢复和跨可用区副本。
- Redis 开启持久化或使用托管高可用版；关键消息仍落 PostgreSQL/outbox。
- 模型 Worker 与设备网关分开扩容，避免模型调用拖慢连接心跳。
- 对日志、指标和 trace 设置脱敏规则及保留期。
- 密钥使用云密钥管理或部署平台 Secret，不写入镜像和仓库。

## 上线前压测门槛

- 目标峰值在线连接数的 1.5 倍，持续至少 2 小时。
- 目标峰值消息吞吐的 2 倍短时冲击。
- 网关滚动重启、Redis 短时不可用、模型供应商超时和数据库主备切换演练。
- 验证重复消息、乱序、半包、粘包、超大帧和慢速连接。
- 记录 P50/P95/P99 延迟、错误率、重试量、CPU、内存和队列积压。
