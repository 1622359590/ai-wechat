# 客服通信协议调查基线

状态：部分确认，仍需恢复与实测
最后更新：2026-08-18

## 已确认内容

- 设备与服务端使用 TCP 长连接。
- 单帧由四字节数据长度和 Protobuf 消息体组成。
- 根消息为 `TransportMessage`，已观察字段包括 `Id`、`AccessToken`、`MsgType`、`Content` 和 `RefMessageId`。
- `Content` 使用 Protobuf `Any` 承载具体消息。
- PHP 依赖 Google Protobuf，生成代码位于旧服务端的 `extend/lib/protobuf`。
- 已发现 `TransportMessage.php`、`EnumMsgType.php`、`DeviceAuthReqMessage.php`、`FriendTalkNoticeMessage.php`、`TalkToFriendTaskMessage.php` 等生成类，以及 `GPBMetadata` 描述符。
- 消息类型枚举约 160 项；业务处理目录约 117 个文件、约 14,438 行。

上述路径是对本机旧源码的调查记录，不是本公开仓库当前内容。

## 尚未确认

- 四字节长度的大小端、长度是否包含头部、零长度是否合法。
- 最大帧长、拆包/粘包策略和慢速连接超时。
- TLS 或应用层加密是否存在，以及证书和密钥轮换方式。
- AccessToken 生命周期、重放防护和设备身份绑定。
- 心跳间隔、断线重连、重复消息和 ack 语义。
- 时间字段的秒/毫秒单位；原文档存在不一致。
- `Any.type_url` 规范和所有 MsgType 到消息体类型的完整映射。
- 文档中重复或疑似拼写错误的消息定义应以何者为准。

## 恢复 `.proto` 的建议流程

1. 从 `GPBMetadata` 和生成 PHP 类提取 package、message、field number、类型、repeated/map/oneof 信息。
2. 为枚举和根消息先建立最小 `.proto`，使用固定二进制样本做双向兼容测试。
3. 按实际业务优先级恢复认证、心跳、好友消息和发送任务，而不是一次恢复全部枚举。
4. 用现有 PHP 实现和 Go 新实现对同一脱敏样本进行 decode → encode 字节对比。
5. 对未知字段保持 Protobuf 兼容，不随意复用已出现过的 field number。

## Go 网关最低安全要求

- 读取长度前设置 deadline，并限制未认证连接数量。
- 在分配消息缓冲区前拒绝超过上限的帧，初始上限需通过样本统计确定。
- Protobuf 解码失败只关闭对应连接并记录脱敏元数据，不输出完整消息体。
- 鉴权、重放、限流和设备封禁使用独立状态，不仅依赖 Base64 形式的账号密码。
- 未确认线上传输加密前，不允许把该协议暴露到公网生产环境。
