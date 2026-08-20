# 数据模型基线

状态：概念设计，尚未建库
最后更新：2026-08-20

## PostgreSQL 建议实体

| 实体 | 关键字段 | 用途 |
|---|---|---|
| `tenants` | `id`, `name`, `status` | 多租户边界 |
| `devices` | `id`, `tenant_id`, `credential_fingerprint`, `credential_version`, `label`, `status`, `auth_expires_at`, `last_authenticated_at` | 设备登记，不保存明文 Credential |
| `device_sessions` | `id`, `device_id`, `gateway_id`, `connected_at`, `closed_at` | 连接历史 |
| `customers` | `id`, `tenant_id`, `external_ref_hash`, `profile_json` | 客户主体与受控画像 |
| `conversations` | `id`, `customer_id`, `status`, `assigned_to`, `last_message_at` | 会话生命周期 |
| `messages` | `id`, `conversation_id`, `direction`, `kind`, `content_ref`, `occurred_at` | 标准化消息元数据 |
| `message_payloads` | `message_id`, `ciphertext`, `key_version`, `retention_until` | 加密内容及保留期 |
| `outbox_commands` | `id`, `device_id`, `idempotency_key`, `status`, `attempts` | 可靠出站发送 |
| `model_calls` | `id`, `message_id`, `provider`, `model`, `prompt_version`, `tokens_in`, `tokens_out`, `cost_estimate`, `status` | 模型审计与费用 |
| `memories` | `id`, `customer_id`, `type`, `content_ref`, `source_message_ids`, `valid_from`, `valid_to`, `version` | 供应商无关记忆索引 |
| `knowledge_sources` | `id`, `tenant_id`, `source`, `version`, `acl`, `valid_until` | 知识来源及权限 |
| `audit_events` | `id`, `tenant_id`, `actor`, `action`, `target`, `created_at` | 安全与管理审计 |

字段名称将在实现前通过迁移文件和 API 契约最终确定。

`TASK-0006` 确定首个设备库实现使用带服务端 pepper 的 HMAC-SHA-256 生成 `credential_fingerprint`。旧 APK 的 Credential 实际是设备编号，不是密码；HMAC 只降低数据库泄漏后的离线枚举风险，不代表客户端已具备强身份。详细约束见 `docs/superpowers/specs/2026-08-20-legacy-apk-multi-device-auth-design.md`。

## Redis 建议用途

- `device:{id}:presence`：带 TTL 的在线状态和网关实例。
- `connection:{id}`：短期连接元数据，不保存认证秘密。
- Streams：入站事件、AI 任务、出站命令和失败队列。
- 限流计数器、短期幂等键、热点会话缓存。

Redis 不作为客户消息或长期记忆的唯一持久化来源。

## 数据治理

- 所有业务实体带 `tenant_id` 或通过外键明确租户归属。
- 客户外部标识优先哈希/令牌化；必须可按客户执行导出和删除。
- 消息内容与索引元数据分离，内容加密并设置保留期。
- 记忆、向量和图谱节点必须能够追溯到来源消息，并随来源删除请求失效。
- 测试 fixture 只能使用合成或不可逆脱敏数据。
