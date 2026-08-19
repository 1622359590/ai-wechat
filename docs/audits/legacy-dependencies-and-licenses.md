# 旧服务端依赖与许可证审计

审计日期：2026-08-19

## Composer 状态

- PHP 要求：`>=8.0`。
- 直接 `require`/`require-dev` 项目：41（包含 PHP 与扩展要求）。
- 当前安装包：109。
- `composer.lock`：缺失。
- 项目根目录 `LICENSE`/`COPYING`：未发现。

没有锁文件意味着当前 `vendor/` 无法仅凭仓库元数据精确重建；没有项目许可证文件意味着不能依据这份本地副本判断自有业务代码是否允许公开发布。源码所有权需要用户或原供应方书面确认。

## 关键直接依赖

| 类别 | 依赖 |
|---|---|
| 框架 | `topthink/framework ^8.0.2`、`think-orm ^3.0`、`think-multi-app ^1.0` |
| 长连接/并发 | `workerman/workerman ^4.2`、`workerman/channel ^1.2`、`topthink/think-swoole ^4.1` |
| 队列/缓存 | `topthink/think-queue 3.0.8`、`predis/predis ^3.0` |
| 协议 | `google/protobuf ^4.31` |
| HTTP/微信 | `guzzlehttp/guzzle ^7.9`、`w7corp/easywechat ^6.8` |
| 云服务 | 阿里云、腾讯云、七牛、COS、OSS、短信和媒体处理 SDK |
| 文档/媒体 | `phpoffice/phpspreadsheet`、`phpoffice/phpword`、`getid3`、二维码与 FFmpeg 相关本地资产 |
| 文本处理 | Jieba、拼音、敏感词 DFA、Symfony Translation/YAML |

直接依赖可通过以下只输出名称和约束的命令复核：

```bash
jq -r '(.require // {}) | to_entries[] | [.key,.value] | @tsv' "$LEGACY_SOURCE_ROOT/composer.json"
jq -r '(."require-dev" // {}) | to_entries[] | [.key,.value] | @tsv' "$LEGACY_SOURCE_ROOT/composer.json"
```

## 安装包许可证声明

安装元数据中没有缺失 license 字段的包。声明计数以每个 license identifier 分别累计，因此多许可证包会重复计数：MIT 70、Apache-2.0 29、BSD-3-Clause 3、GPL-3.0-only 2、GPL-2.0-only 2、LGPL-3.0-only 2，另有 BSD-2-Clause、MPL、ISC 等。

需要单独确认选择方式和分发影响的包：

- `clagiordano/weblibs-configmanager`：LGPL-3.0-or-later
- `ezyang/htmlpurifier`：LGPL-2.1-or-later
- `james-heinrich/getid3`：GPL/LGPL/MPL 多许可证声明
- `nette/php-generator`、`nette/utils`：BSD/GPL 多许可证声明
- `phpoffice/phpword`：LGPL-3.0-only

本报告只记录包元数据，不构成法律意见。新 Go/Python 服务优先重新声明最小依赖并生成锁文件与 SBOM，不复制现有 `vendor/`。

## 迁移决定

- `composer.json`：可作为依赖调查证据；公开前仍需检查私有 repository 配置，本次没有复制文件。
- `vendor/`：禁止迁移，使用新锁文件重建必要依赖。
- 旧业务 PHP：在所有权确认前只读参考，不公开导入。
- 新项目：每个服务必须提交 lock/checksum 文件、项目许可证决定和自动依赖扫描配置。
