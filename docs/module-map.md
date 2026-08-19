# 模块地图

状态：目录规划，尚未创建代码
最后更新：2026-08-18

## 建议仓库结构

```text
ai-wechat/
├── gateway/                 # Go：连接、协议与设备消息收发
├── services/
│   ├── business-legacy/     # 经审计后迁入的 PHP 业务（如决定保留在同仓库）
│   ├── ai-orchestrator/     # Python：模型、检索和回复编排
│   ├── memory/              # MemoryService 与供应商适配器
│   └── knowledge/           # 文档检索与知识图谱适配器
├── web/                     # 管理后台前端
├── proto/                   # 恢复并审核后的协议源文件
├── contracts/               # OpenAPI、事件 schema 和共享契约
├── deploy/                  # 容器、环境和部署清单，不含秘密
├── tests/
│   ├── fixtures/            # 仅允许脱敏或合成测试数据
│   ├── integration/
│   └── replay/
└── docs/
```

是否采用 monorepo 在源码审计任务中最终确认。模块边界无论单仓还是多仓都保持一致。

## 计划接口

| 接口 | 调用方 | 提供方 | 目的 |
|---|---|---|---|
| Device Event v1 | 网关 | 消息总线 | 标准化设备入站事件 |
| Outbound Command v1 | 业务服务 | 网关 | 向指定设备发送消息或任务 |
| Conversation API v1 | 后台、AI | 业务服务 | 查询及更新会话状态 |
| Model Gateway v1 | AI 编排 | 模型路由器 | 统一模型调用、预算和审计 |
| MemoryService v1 | AI 编排 | 记忆服务 | 写入、搜索、合并、删除记忆 |
| KnowledgeService v1 | AI 编排 | 知识服务 | 带来源的文档和图谱检索 |

## 所有权约束

- 网关拥有“设备当前连接在哪个实例”的短期状态。
- 业务服务拥有客户、会话、客服任务和发送授权。
- AI 服务拥有模型执行记录，但不成为客户/订单事实的权威数据源。
- 记忆项必须保留来源消息和生成版本；可随数据删除请求级联清除。
- 知识库内容必须保留来源、版本、有效期和访问范围。
