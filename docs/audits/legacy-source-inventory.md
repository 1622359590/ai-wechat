# 旧服务端源码结构清单

审计日期：2026-08-19

## 统计口径

运行者在本机把 `LEGACY_SOURCE_ROOT` 指向仓库外的旧服务端目录。8,723 是“非 vendor/runtime 项目文件”总量，不代表自有源码，也不代表允许迁移；其中仍包含 SQL、敏感二进制、归档、`extend/` 中手工复制的第三方库及 `public/` 构建产物。

```bash
find "$LEGACY_SOURCE_ROOT" -type f \
  -not -path "$LEGACY_SOURCE_ROOT/vendor/*" \
  -not -path "$LEGACY_SOURCE_ROOT/runtime/*" \
  -not -name '.DS_Store'
```

另外按迁移预筛口径排除 `.git/`、临时目录、SQL、转储、日志、抓包、敏感二进制和归档后，共有 8,603 个“待判定文件”。它们仍须逐项通过所有权、许可证和秘密扫描，不能直接公开：

```bash
find "$LEGACY_SOURCE_ROOT" -type f \
  -not -path "$LEGACY_SOURCE_ROOT/vendor/*" \
  -not -path "$LEGACY_SOURCE_ROOT/runtime/*" \
  -not -path "$LEGACY_SOURCE_ROOT/.git/*" \
  -not -path '*/tmp/*' -not -path '*/temp/*' \
  -not -name '.DS_Store' \
  -not -name '*.sql' -not -name '*.dump' -not -name '*.log' \
  -not -name '*.pcap' -not -name '*.bin' \
  -not -name '*.zip' -not -name '*.tar' -not -name '*.tar.gz' -not -name '*.tgz'
```

## 规模

| 指标 | 数量 | 排除说明 |
|---|---:|---|
| 非 vendor/runtime 项目文件 | 8,723 | 仅排除 `vendor/`、`runtime/`、`.DS_Store`，包含不可迁移类别 |
| 迁移预筛后的待判定文件 | 8,603 | 进一步排除 Git、临时、数据库/日志/抓包、二进制和归档类别 |
| PHP 文件 | 2,529 | 排除 `vendor/`、`runtime/` |
| PHP 行数 | 392,591 | `wc -l` 物理行，不代表有效业务代码 |
| `vendor/` 文件 | 45,266 | 第三方安装产物 |
| SQL 文件 | 114 | 排除 `vendor/` |
| SQL 总大小 | 4,338,157 bytes | 仅统计大小，未记录内容 |

主要顶层目录文件数：`app/` 2,087、`config/` 28、`extend/` 3,329、`public/` 3,275、`vendor/` 45,266。`extend/` 和 `public/` 必须继续拆分来源，不能整体迁移。

## PHP 业务区域

| 区域 | PHP 文件 | 初步职责 |
|---|---:|---|
| `app/adminapi` | 507 | 管理后台 API、列表、验证和配置 |
| `app/api` | 722 | 客户端/业务 API 与业务逻辑 |
| `app/common` | 805 | 模型、服务、命令、队列、设备通信 |
| `app/queue` | 3 | 队列入口/任务基类 |
| `app/common/command` | 71 | CLI、定时任务和服务启动命令 |
| `app/common/Jobs` | 10 | 异步任务 |
| `app/common/workerman/wechat` | 138 | 微信设备连接、路由、处理器与服务 |
| `app/common/workerman/rpa` | 61 | RPA 设备连接与处理器 |

微信 Workerman 子树为 14,438 行 PHP。该数字与早期记录行数一致，但文件数的当前可复现口径是 138，不再沿用早期“117 个处理器文件”的模糊表述。

## 运行入口

- HTTP：`public/index.php`、`public/router.php`、`route/app.php`。
- ThinkPHP CLI：根目录 `think`、`config/console.php`。
- Workerman：`app/common/command/WorkermanServie.php`。
- 单 Worker/Channel：`app/common/command/SingleWorkerService.php`、`app/common/command/StartChannel.php`。
- 配置：`config/worker.php`、`config/worker_server.php`、`config/gateway_worker.php`、`config/queue.php`。
- 微信 Socket：`app/common/workerman/wechat/DeviceSocketService.php`、`WechatSocketService.php`。
- 微信连接/消息服务：`services/ConnectionService.php`、`services/MessageService.php`。

## 协议资产

| 资产 | 数量 |
|---|---:|
| `extend/lib/protobuf` 生成 PHP | 439 |
| Jubo namespace 消息类 | 257 |
| `GPBMetadata` 描述文件 | 182 |
| `EnumMsgType` 数字常量 | 225 |

首批恢复资产：

- `TransportMessage.php` 与 `GPBMetadata/TransportMessage.php`
- `EnumMsgType.php`
- `DeviceAuthReqMessage.php`
- `HeartBeatMessage.php`
- `FriendTalkNoticeMessage.php`
- `TalkToFriendTaskMessage.php`
- 对应 device/client handler 与 `MessageService.php`

## 结论

旧系统不是只有通信模块的轻量服务，而是包含后台、内容/视频、设备、支付、云服务和 AI 业务的综合系统。完整迁移不应作为第一阶段目标；先以生成协议类和微信 Workerman 子树作为行为参考，其他 PHP 业务通过契约逐步保留或重写。
