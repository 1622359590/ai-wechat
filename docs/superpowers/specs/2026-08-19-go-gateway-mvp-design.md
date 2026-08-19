# Go 协议网关最小闭环设计

状态：已批准
日期：2026-08-19
对应任务：`TASK-0004`

## 目标

把 TASK-0003 的最小协议变成可运行、可回放、可容器化的 Go TCP 服务。服务必须正确处理四字节大端帧、Protobuf `TransportMessage`、设备鉴权状态、心跳和好友消息，并能把业务处理器生成的 `TalkToFriendTaskMessage` 写回连接。

## 方案选择

### 采用：运行时加载已验证描述符

把仓库根目录变成 Go module，在 `proto/schema` 内嵌并编译 `proto/minimal/*.proto`。网关通过 `dynamicpb` 解码，直接复用 TASK-0003 已测试的 wire schema。

优点：不依赖本机 `protoc` 或新增生成工具链；不会提交大批生成文件；恢复字段变化时只维护唯一 `.proto` 来源。代价是启动时有一次描述符编译开销，消息访问不如生成类型直观。对于当前五类消息和单次启动，该代价可接受；协议稳定后可单独评估生成强类型绑定。

### 未采用：立即生成 `.pb.go`

强类型和性能更好，但当前机器没有 `protoc`，需要再引入 Buf/protoc 插件与版本治理。现阶段会扩大工具链范围，不增加 wire 兼容证据。

### 未采用：继续用 PHP 承担 Socket

短期改动少，但无法形成目标 Go 网关的连接、限流和部署基线，也会继续扩大 Workerman 与业务代码耦合。

## 模块边界

| 模块 | 职责 | 不负责 |
|---|---|---|
| `proto/schema` | 内嵌、编译并缓存最小描述符 | 网络连接、业务策略 |
| `internal/frame` | 读取/写入四字节大端长度帧，执行长度上限 | Protobuf 和鉴权 |
| `internal/protocol` | 解码 Transport/Any、验证 MsgType 与具体消息映射、编码发送任务 | TCP 生命周期 |
| `internal/gateway` | 每连接状态、鉴权接口、心跳/好友消息路由、可选回复 | 数据库、AI、长期记忆 |
| `internal/server` | TCP accept loop、deadline、优雅关闭、连接级错误隔离 | 业务字段解释 |
| `internal/health` | `/livez` 与 `/readyz` | 管理后台 |
| `cmd/gateway` | 配置、依赖装配、信号处理 | 领域逻辑 |

## 数据流

1. TCP 服务接受连接并设置读写 deadline。
2. `frame.Decoder` 读取 4 字节长度；拒绝零长度和超过配置上限的帧，再分配 body。
3. `protocol.Codec` 解码 `TransportMessage`，校验 `MsgType`、`Any.type_url` 与具体消息类型一致。
4. 未鉴权连接只允许 `DeviceAuthReq`。鉴权由接口注入；默认实现拒绝全部设备，避免误上线。
5. 鉴权后允许心跳和好友消息。好友消息交给 `Responder`；默认不回复，测试实现可生成 `TalkToFriendTask`。
6. 有回复时编码 Transport + Any，再由 frame writer 写回同一连接。
7. 单连接协议错误只关闭该连接；监听器继续服务。日志只记录错误类别、消息类型和连接计数，不记录 credential、标识或消息内容。

## 配置与安全默认值

- TCP 默认 `:19090`，健康检查默认 `:18080`。
- 默认最大 frame body 为 1 MiB，可通过非秘密环境变量降低或提高，但硬上限为 16 MiB。
- 未鉴权读超时 10 秒，已鉴权空闲读超时 90 秒，写超时 10 秒。
- 默认 `DenyAllAuthenticator`；TASK-0005 接入真实测试设备时再提供受控适配器。
- 容器以非 root 用户运行，运行时文件系统只读，Compose 默认只绑定 `127.0.0.1`。
- 本任务不配置 TLS；因此远程部署不得把 TCP 端口直接暴露到公网。

## 测试

- frame 单元测试：正常、半包、粘包、零长度、超限、截断、写入失败。
- protocol 回放：读取 TASK-0003 的 15 个 fixture，校验消息类型、Any、未知字段及发送任务编码。
- gateway 状态测试：鉴权前拒绝心跳、鉴权失败、鉴权成功、心跳、好友事件、可选回复。
- server 集成测试：真实 localhost 临时端口，多连接隔离、优雅停止。
- health 测试：live 始终反映进程存活；ready 只在 TCP 监听成功后返回 200。
- 容器测试：构建、非 root、只读根文件系统、健康检查和回放 smoke test。

## 部署边界

第一步部署为本机 Docker staging，端口只绑定回环地址，鉴权默认拒绝。远程测试服务器部署需要可识别的 SSH/平台目标；当前本机 SSH 配置仅发现 GitHub，因此代码完成后若仍没有目标，只会请求服务器地址、登录方式和允许开放的端口，不会猜测或扫描外部主机。
