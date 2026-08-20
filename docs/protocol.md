# 客服通信协议调查基线

状态：最小子集已恢复并完成合成兼容测试，真实设备仍需实测
最后更新：2026-08-20

## 已确认内容

- 设备与服务端使用 TCP 长连接。
- 单帧由四字节数据长度和 Protobuf 消息体组成。旧 PHP 发送使用 `pack('N', strlen(message))`、接收使用 `unpack('N', buffer)`，确认长度头为网络字节序（大端），且长度不包含四字节头。
- 根消息为 `TransportMessage`，已观察字段包括 `Id`、`AccessToken`、`MsgType`、`Content` 和 `RefMessageId`。
- `Content` 使用 Protobuf `Any` 承载具体消息。
- PHP 依赖 Google Protobuf，生成代码位于旧服务端的 `extend/lib/protobuf`。
- 已发现 `TransportMessage.php`、`EnumMsgType.php`、`DeviceAuthReqMessage.php`、`FriendTalkNoticeMessage.php`、`TalkToFriendTaskMessage.php` 等生成类，以及 `GPBMetadata` 描述符。
- 旧 PHP `DeviceAuthReqHandler` 将 `DeviceAuthReqMessage.Credential` 直接作为设备编号；它不是可以保密的客户端密钥。旧处理器忽略 `AuthType`，生成 Token 后返回 `DeviceAuthRsp=1011`。
- 当前生成 `EnumMsgType.php` 有 225 个数字常量；`app/common/workerman/wechat` 有 138 个 PHP 文件、约 14,438 行。
- 已恢复六个可编译的最小 Protobuf 3 文件，package 为 `Jubo.JuLiao.IM.Wx.Proto`；Go 描述符测试和旧 PHP 生成类均可往返 18 个公开安全的合成帧。
- 合成帧使用四字节大端长度头；Go 与旧 PHP 均保留测试加入的未知字段 127。

上述路径是对本机旧源码的调查记录，不是本公开仓库当前内容。

## 已恢复的最小 wire schema

源文件位于 [`proto/minimal`](../proto/minimal)，只恢复首条链路所需子集，不等同于完整旧协议。

| 消息 | 字段号与类型 |
|---|---|
| `TransportMessage` | `Id=1 int64`、`AccessToken=2 string`、`MsgType=3 EnumMsgType`、`Content=4 google.protobuf.Any`、`RefMessageId=5 int64` |
| `DeviceAuthReqMessage` | `AuthType=1 EnumAuthType`、`Credential=2 string` |
| `DeviceAuthRspMessage` | `AccessToken=1 string`、`Extra=2 ExtraMessage`；嵌套 `ExtraMessage` 为 `SupplierId=1 int64`、`UnionId=2 int64`、`AccountType=3 EnumAccountType`、`SupplierName=4 string`、`NickName=5 string`、`Token=6 string` |
| `HeartBeatMessage` | `Imei=1 string`、`WeChatId=2 string` |
| `FriendTalkNoticeMessage` | `WeChatId=1 string`、`FriendId=3 string`、`ContentType=5 EnumContentType`、`Content=6 bytes`、`MsgId=7 int64`、`msgSvrId=8 int64`、`Ext=9 string`、`CreateTime=10 int64`、`NickName=11 string` |
| `TalkToFriendTaskMessage` | `WeChatId=1 string`、`FriendId=2 string`、`ContentType=3 EnumContentType`、`Content=4 bytes`、`Remark=8 string`、`MsgId=9 int64`、`Immediate=10 bool` |

首批消息类型：`HeartBeatReq=1001`、`DeviceAuthReq=1010`、`DeviceAuthRsp=1011`、`FriendTalkNotice=1024`、`TalkToFriendTask=1070`。认证类型：`Default=0`、`DeviceCode=1`、`Username=2`、`InternalCode=3`。账号类型：`UnknownAccountType=0`、`Main=1`、`SubUser=2`。内容类型当前只恢复 `UnknownContent=0` 和 `Text=1`。

合成夹具位于 [`proto/testdata/synthetic_frames.json`](../proto/testdata/synthetic_frames.json)，每类包含 normal、boundary 和 unknown 三种，共 18 个。内层 `Any.type_url` 使用 `type.googleapis.com/Jubo.JuLiao.IM.Wx.Proto.<MessageName>`；该格式已通过合成 Go/PHP 兼容测试，但真实设备是否完全一致仍待实测。

## 尚未确认

- 零长度是否合法，以及设备端是否存在不同版本的帧格式。
- 最大帧长、拆包/粘包策略和慢速连接超时。
- TLS 或应用层加密是否存在，以及证书和密钥轮换方式。
- 真实 APK 实际发送的 `AuthType` 是 `Default=0` 还是 `DeviceCode=1`。
- 旧 APK 是否始终在后续消息中携带 AccessToken，以及真实断线重连行为。
- 心跳间隔、断线重连、重复消息和 ack 语义。
- 时间字段的秒/毫秒单位；原文档存在不一致。
- 真实设备使用的 `Any.type_url` 是否与合成夹具一致，以及所有 MsgType 到消息体类型的完整映射。
- 文档中重复或疑似拼写错误的消息定义应以何者为准。

## 后续恢复流程

1. TASK-0004 使用已恢复最小协议实现 Go 帧解析和消息路由，不重新定义字段。
2. TASK-0005 用真实测试设备和不可逆脱敏样本确认 `Any.type_url`、时间单位和连接行为。
3. 发现新消息时继续从 `GPBMetadata` 恢复 package、message、field number、类型、repeated/map/oneof，并补兼容 fixture。
4. 对未知字段保持 Protobuf 兼容，不随意复用已出现过的 field number。

## Go 网关最低安全要求

- 读取长度前设置 deadline，并限制未认证连接数量。
- 在分配消息缓冲区前拒绝超过上限的帧，初始上限需通过样本统计确定。
- Protobuf 解码失败只关闭对应连接并记录脱敏元数据，不输出完整消息体。
- 鉴权、重放、限流和设备封禁使用独立状态，不仅依赖 Base64 形式的账号密码。
- 未确认线上传输加密前，不允许把该协议暴露到公网生产环境。
