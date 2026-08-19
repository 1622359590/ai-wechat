# 旧系统迁移与协议恢复交接

审计日期：2026-08-19

## 模块处置

| 模块 | 决定 | 原因 |
|---|---|---|
| `app/common/workerman/wechat` | 用作行为参考，Go 重新实现 | 连接、帧、路由和业务耦合，需要契约拆分 |
| `extend/lib/protobuf/Jubo`、`GPBMetadata` | 只读恢复证据 | 生成代码可恢复字段，但不替代 `.proto` 源文件 |
| `app/adminapi`、`app/api` | 迁移期保留 PHP | 1,229 个 PHP 文件，完整重写风险过高 |
| 业务模型/服务 | 按业务切片保留或重写 | 先建立契约测试，再决定语言 |
| SQL 安装/升级脚本 | 脱敏和分类后仅迁移 schema | 可能混有默认账号、配置或历史数据 |
| `vendor/` | 丢弃安装产物 | 新服务用锁文件重建最小依赖 |
| `runtime/`、`.DS_Store` | 丢弃 | 运行/本机产物 |
| 敏感二进制 | 禁止迁移 | 潜在数据和密钥 |
| FFmpeg/Protobuf 压缩包 | 不直接迁移 | 来源、版本和许可证不明确 |

## 已确认的帧格式

旧发送路径使用：

```text
pack('N', strlen(protobuf_message)) + protobuf_message
```

接收路径使用 `unpack('N', buffer)`。因此当前 PHP 行为表明长度头为四字节网络字节序（大端），长度值只包含后续 Protobuf 消息体，不包含四字节头。本结论需要在 `TASK-0003` 用脱敏二进制样本固定为回归测试。

## 首批消息字段

- `TransportMessage`：`Id`、`AccessToken`、`MsgType`、`Content`、`RefMessageId`。
- `DeviceAuthReqMessage`：`AuthType`、`Credential`。
- `HeartBeatMessage`：`Imei`、`WeChatId`。
- `FriendTalkNoticeMessage`：`WeChatId`、`FriendId`、`ContentType`、`Content`、`MsgId`、`MsgSvrId`、`CreateTime`、`NickName`、`Ext`。
- `TalkToFriendTaskMessage`：`WeChatId`、`FriendId`、`ContentType`、`Content`、`MsgId`、`Remark`、`Immediate`。

字段编号、标量类型、optional/repeated/oneof 和 `Any.type_url` 必须从 `GPBMetadata` 恢复，不能只根据 getter 名猜测。

## 首批行为参考

- 鉴权：`handlers/device/DeviceAuthReqHandler.php`
- 心跳：`handlers/device/HeartBeatReqHandler.php`
- 好友消息入站：`handlers/device/FriendTalkNoticeHandler.php`
- 好友消息出站：`handlers/client/TalkToFriendTaskHandler.php`
- 帧拆包：`DeviceSocketService.php`
- 消息封装/发送：`services/MessageService.php`
- 连接绑定/跨进程发送：`services/ConnectionService.php`

## TASK-0003 验收输入

生成类的 PHP namespace / Protobuf package 为 `Jubo.JuLiao.IM.Wx.Proto`。首批只读证据的精确相对路径如下：

| 消息 | 生成类 | 元数据 |
|---|---|---|
| 传输封装 | `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/TransportMessage.php` | `extend/lib/protobuf/GPBMetadata/TransportMessage.php` |
| 设备鉴权 | `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/DeviceAuthReqMessage.php` | `extend/lib/protobuf/GPBMetadata/DeviceAuthReq.php` |
| 心跳 | `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/HeartBeatMessage.php` | `extend/lib/protobuf/GPBMetadata/HeartBeat.php` |
| 好友消息入站 | `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/FriendTalkNoticeMessage.php` | `extend/lib/protobuf/GPBMetadata/FriendTalkNotice.php` |
| 好友消息出站 | `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/TalkToFriendTaskMessage.php` | `extend/lib/protobuf/GPBMetadata/TalkToFriendTask.php` |

枚举证据位于 `extend/lib/protobuf/Jubo/JuLiao/IM/Wx/Proto/EnumMsgType.php`。首批映射固定为：`HeartBeatReq = 1001`、`DeviceAuthReq = 1010`、`FriendTalkNotice = 1024`、`TalkToFriendTask = 1070`；`TransportMessage` 是外层封装，不单独占用消息类型值。`TalkToFriendTaskResultNotice = 1028` 和 `TalkToFriendTaskReceived = 3064` 属于后续响应/确认语义，不能与 `TalkToFriendTask = 1070` 混用。

TASK-0003 的验收输入：

1. 上表 5 类消息的生成 PHP 类与对应 `GPBMetadata`。
2. `EnumMsgType` 的 225 个数字常量作为只读校验源；最小 `.proto` 首批只定义上述 4 个明确映射。
3. 每类至少 3 个合成或不可逆脱敏帧：正常、空/边界字段、包含未知字段。
4. PHP 与 Go 对相同样本执行 decode → encode；语义字段一致且未知字段不丢失。
5. 帧解析覆盖半包、粘包、零长度、超大长度、非法 Protobuf 和断线重连。

## 下一步

`TASK-0003` 先恢复最小 `.proto` 和跨语言兼容 fixture；通过后 `TASK-0004` 才创建正式 Go 网关 module。AI、记忆、数据库和后台不进入这两个协议任务的实现范围。
