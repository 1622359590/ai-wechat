# 记忆与知识系统方案

状态：候选方案，尚未集成
最后更新：2026-08-18

## 两类数据不能混为一体

- 记忆：从某个客户历史互动中得到的偏好、约束、关系、待办和阶段性总结。
- 知识：产品、政策、流程、FAQ、合同模板等可由企业维护和版本化的资料。

模型生成的记忆不是业务事实。订单、余额、权限和交易状态必须实时查询权威业务系统。

## MemoryService 边界

建议项目先定义供应商无关接口：

```text
appendEvents(tenantId, subjectId, events, idempotencyKey)
search(tenantId, subjectId, query, filters, limit)
consolidate(tenantId, subjectId, scope, modelPolicy)
invalidate(tenantId, memoryIds, reason)
deleteSubject(tenantId, subjectId)
```

每个记忆结果必须包含 `memory_id`、类型、内容引用、来源消息、生成版本、置信度、有效时间和访问范围。

## TencentDB Agent Memory

可以作为首个试点适配器。已调查版本提供分层记忆思路，包括原始会话、原子记忆、场景和画像层，并有 Python/TypeScript 接入方式。

接入限制：

- 当前项目仍快速演进，API 和部署方式需要锁定版本。
- 单机默认存储适合验证，不应直接作为大规模生产系统的唯一数据层。
- 业务代码只调用 `MemoryService`；供应商 SDK、字段和错误码留在适配器内部。
- 试点必须验证多租户隔离、删除、重建、来源追踪、中文召回质量和故障恢复。

参考：[TencentDB Agent Memory](https://github.com/TencentCloud/TencentDB-Agent-Memory)

## 知识检索和图谱

第一阶段先实现带版本和权限的文档切块、向量/关键词混合检索及引用。第二阶段再评估：

- Graphiti：适合随时间变化的客户、人物和事件关系。
- Neo4j：作为图数据库及可视化、查询基础。
- LightRAG：可用于文档知识图谱检索试验，但应与权威业务数据隔离。

图谱节点和边必须保存租户、来源、有效时间和生成方式。任何模型推断关系都应标为推断，不得伪装成人工确认事实。

## 评估指标

- Recall@K、错误记忆率、过期记忆率和来源可追溯率。
- 记忆写入/查询 P95 延迟及每千次会话成本。
- 删除请求完成时间和所有派生数据清除率。
- 使用记忆后的一次解决率提升及错误个性化投诉率。
