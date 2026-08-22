# 真实设备一次性安全配对设计

状态：已批准
日期：2026-08-20
任务：`TASK-0005`

## 背景

手机 AI 销售应用使用独立的 `HOST` 与 `PORT` 建立 TCP 长连接。真实设备已经配置到测试服务器的 Go 网关端口，公网 TCP 可达，但当前网关使用 `DenyAllAuthenticator`，并且鉴权成功路径没有返回旧设备要求的鉴权响应，因此设备无法完成上线。

旧 PHP 行为已经确认：`DeviceAuthReqMessage.Credential` 被直接作为设备编号；只要非空就生成 Token，并返回 `DeviceAuthRspMessage`。该行为不校验设备归属，不能直接暴露在公网。

## 目标

- 允许一台用户控制的真实测试设备通过一次性配对接入远程 staging。
- 不保存或记录明文 `Credential`，不把设备标识、Token 或连接源地址提交到公开仓库。
- 返回与旧设备兼容的 `DeviceAuthRsp = 1011` 和会话 `AccessToken`。
- 配对完成后自动进入锁定状态；未知设备不能通过鉴权。
- 已鉴权消息必须携带当前连接签发的 Token。
- 保留默认拒绝模式，未显式配置配对状态目录时不得放宽鉴权。

## 不在范围

- 多租户设备管理、账号后台、数据库设备表或人工审批界面。
- 生产级证书、负载均衡、多实例 Token 共享或跨实例会话迁移。
- 文件上传接口 `/api/wechatUpload`、AI 回复、消息持久化和完整管理后台。
- 恢复 `DeviceAuthRspMessage.ExtraMessage` 的业务值；首个响应只发送 `AccessToken`，`Extra` 保持未设置。

## 已选方案

采用“受来源限制的一次性配对 + 本地指纹锁定”。不采用旧 PHP 的“非空即通过”，也不要求用户手工获得手机内部不可见的 Credential。

### 配对状态

网关支持三个状态：

1. `deny-all`：没有状态目录或未启用配对，拒绝所有设备。
2. `pairing`：显式启用配对、状态文件不存在，且连接来源属于允许的 CIDR；第一条结构合法、Credential 非空的鉴权请求可以配对。
3. `locked`：状态文件已存在；只有 Credential 指纹匹配的设备可以鉴权。即使配对开关仍为 true，也不会覆盖既有状态。

配对只允许一个 Credential。重新配对必须由运维人员在确认目标后移走旧状态文件并重新开启受限配对窗口；应用本身不提供远程清除入口。

### 运行时状态

状态文件位于配置的 `GATEWAY_PAIRING_STATE_FILE`，远程 staging 使用服务器专属、Git 忽略的目录。文件只包含版本号、SHA-256 Credential 指纹和创建时间，不包含明文 Credential、Token、源 IP 或聊天数据。

写入使用同目录临时文件、`0600` 权限和原子重命名；已存在文件时创建必须失败，防止并发首连覆盖。容器继续使用非 root 用户和只读根文件系统，只给单独状态目录写权限。

SHA-256 指纹是设备允许列表键，不宣称匿名化；日志不得输出该指纹。状态文件属于服务器秘密运行数据，禁止提交仓库、复制到任务文档或聊天。

### 来源限制

配对模式必须同时配置 `GATEWAY_PAIRING_ALLOWED_CIDRS`。服务端从 TCP 连接的真实远端地址取得源 IP，并在进入配对逻辑前匹配 CIDR。空列表、解析失败或来源不匹配都拒绝配对。

锁定状态不依赖源 IP，以允许手机网络变化；它只比较 Credential 指纹。公网入口仍应保留主机防火墙、连接速率限制和后续 TLS 迁移计划。

## 协议兼容

从旧生成代码恢复最小协议：

```proto
message DeviceAuthRspMessage {
  string AccessToken = 1;
  ExtraMessage Extra = 2;
}
```

`ExtraMessage` 的字段证据保留在协议文档，但本任务不发送它。`EnumMsgType.DeviceAuthRsp = 1011`。响应外层 `TransportMessage` 设置 `MsgType=1011` 和对应 `Any Content`，`Id`、`AccessToken` 与 `RefMessageId` 保持默认值，这与旧 PHP `buildMessage()` 行为一致。

为 `DeviceAuthRsp` 增加正常、边界和未知字段三类公开合成 fixture，并执行 Go 与旧 PHP decode/encode 兼容验证。fixture 只使用 `synthetic-token` 等公开合成值。

## 鉴权与会话

`Authenticator` 不再只返回 error，而是返回包含新会话 Token 的 `AuthResult`。成功步骤为：

1. 校验 `AuthType` 为旧设备允许的值，首个兼容范围接受 `DeviceCode`；如果真实设备证据表明使用 `Default`，只在记录脱敏验证结果后增加该值。
2. 校验 Credential 非空并限制长度，避免滥用内存。
3. 在配对或锁定状态下校验来源与 Credential 指纹。
4. 使用 `crypto/rand` 生成 32 字节随机 Token，并编码为 64 位小写十六进制字符串。
5. 把 Token 存入当前 `Session`，有效期 1 小时。
6. 编码并返回 `DeviceAuthRsp`，之后才把 Session 标记为已鉴权。

鉴权响应编码或写回失败时，Session 不得进入已鉴权状态。

后续消息必须满足：外层 `TransportMessage.AccessToken` 与 Session Token 使用常量时间比较且未过期。缺失、错误或过期 Token 都关闭当前连接，设备可以重新连接并重新鉴权。

## 组件边界

- `proto/minimal`：增加 `DeviceAuthRsp.proto` 和消息类型 1011。
- `proto/compat`：验证恢复字段、类型 URL、未知字段和旧 PHP 兼容性。
- `internal/pairing`：解析配置、CIDR 校验、Credential 指纹、原子状态存储和一次性配对。
- `internal/gateway`：接收鉴权结果、管理 Session Token、返回鉴权响应并验证后续 Token。
- `internal/protocol`：编码 `DeviceAuthRsp`，暴露解码后的外层 AccessToken。
- `internal/server`：把远端 IP 放入 Session；不记录完整地址。
- `cmd/gateway`：只有配置完整时构造配对鉴权器，否则保持 deny-all；启动日志只记录模式，不记录秘密。
- `deploy`：挂载独立状态目录，提供无真实值的配置说明；不在 Compose 中写入设备指纹或生产 CIDR。

## 错误处理与可观测性

- 日志只记录事件类型和稳定错误分类：`pairing-created`、`auth-rejected`、`token-invalid`、`token-expired`。
- 不记录 Credential、Credential 指纹、AccessToken、设备 ID、完整远端 IP 或消息体。
- 配对状态文件损坏、权限错误或配置非法时启动失败，不回退到宽松模式。
- 同时到达的首次配对请求只有一个能原子创建状态；其余重新读取锁定状态并按指纹判断。
- 健康检查只表示进程和监听状态，不泄露是否已配对或设备是否在线。

## 测试与验收

自动测试先行，覆盖：

- 配置缺失保持 deny-all。
- CIDR 不匹配不能创建状态文件。
- 第一个允许来源的合法 Credential 原子配对；第二个不同 Credential 被拒绝。
- 状态重载后同一 Credential 可通过，不同 Credential 被拒绝。
- 状态文件不含明文 Credential，权限为 `0600`。
- `DeviceAuthRsp` 的 MsgType、type URL 和 AccessToken 正确，旧 PHP 能解码。
- 鉴权响应成功后 Session 才进入已鉴权状态。
- 后续心跳 Token 正确时通过，缺失、错误和过期时拒绝。
- 并发首次配对、半包、粘包、断线重连和异常帧不造成进程重启。
- `go test ./...`、`go test -race ./...`、`go vet ./...` 和远程 smoke 通过。

真实设备验收只记录不可识别结果：TCP 建立、鉴权响应、心跳持续时间、断线重连结果、容器健康和重启次数。不得保存抓包、真实报文、设备标识或明文 Token。

## 部署顺序与回滚

1. 在本地使用合成 fixture 完成红绿测试和兼容验证。
2. 远程部署仍保持默认拒绝，验证镜像和健康状态。
3. 从当前设备连接确定临时允许 CIDR，但不把地址写入仓库或聊天。
4. 创建服务器专属状态目录并开启一次性配对。
5. 第一台设备配对成功后确认状态自动锁定，随后移除配对开关和临时 CIDR配置并重启。
6. 验证同一设备重连、心跳和未知合成 Credential 拒绝。

回滚时恢复上一版镜像和 deny-all 配置；保留配对状态文件但不加载。回滚不删除服务器状态、不修改旧 PHP 服务，也不影响文件上传 URL。

## 安全后续

该方案只用于单设备 staging。进入多设备或生产前，必须用数据库/API 设备注册替换本地状态文件，并完成 TLS、限流、审计、密钥轮换和后台设备撤销功能。
