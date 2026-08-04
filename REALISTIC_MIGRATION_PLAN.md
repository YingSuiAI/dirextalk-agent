# 🎯 Native Agent 独立化 - 实际迁移方案

**评估日期**: 2026-08-04

---

## ⚠️ 现实评估

### 迁移规模
- **61 个 native_agent 文件**
- **约 15,000+ 行业务逻辑**
- **复杂的依赖关系**（Eino、工具系统、记忆系统）
- **预计时间**: 100-140 小时（3-4 周全职工作）

### 技术挑战
1. 每个功能需要重新设计为 Capability
2. 状态管理需要迁移到 Operation 框架
3. 数据库 schema 需要迁移
4. 权限模型需要适配
5. 测试覆盖需要重写

---

## 💡 推荐方案：分阶段迁移

### 阶段 0: 当前状态（已完成）✅
**时间**: 已完成  
**成果**: 协议层和基础设施

- ✅ Capability 协议定义
- ✅ 安全机制（mTLS、Grant、幂等性）
- ✅ Operation 状态机
- ✅ 测试基础设施

### 阶段 1: 双模式并存（推荐）
**时间**: 1-2 周  
**目标**: 保持现有功能，逐步验证新架构

**实施**:
1. message-server 保留所有 Agent 功能（现状）
2. 新增一个**示例 Chat Capability**到 agent
3. Flutter 可以选择使用旧路径或新路径
4. 验证新协议的端到端流程

**优点**:
- ✅ 零风险（不破坏现有功能）
- ✅ 快速验证架构
- ✅ 渐进式迁移

### 阶段 2: 优先功能迁移
**时间**: 4-6 周  
**目标**: 迁移核心功能

**优先级排序**:
1. **Chat/Conversation** (核心，约 1-2 周)
2. **Model Profiles** (相对独立，约 3-5 天)
3. **Skills/MCP** (复杂，约 1-2 周)
4. **Tasks/Schedules** (约 1 周)
5. **Knowledge/Attachments** (约 1 周)

每个功能迁移后：
- 保留旧代码作为 fallback
- 灰度发布（feature flag）
- 充分测试后才移除旧代码

### 阶段 3: 清理和优化
**时间**: 1-2 周  
**目标**: 移除旧代码，优化性能

---

## 🚀 立即可行方案：示例 Capability

让我先实现一个**完整的 Chat Capability 示例**，作为：
1. 架构验证 PoC
2. 其他功能的迁移模板
3. 团队参考实现

**内容**:
- ✅ 完整的 AgentCapability 实现
- ✅ Operation 生命周期管理
- ✅ Watch 事件流
- ✅ 与现有 Eino 集成
- ✅ 端到端测试

**时间**: 4-6 小时

---

## 📊 各方案对比

| 方案 | 时间 | 风险 | 价值 |
|------|------|------|------|
| **完全迁移** | 100-140h | 高 | 高（如果成功） |
| **阶段性迁移** | 40-60h | 中 | 高 |
| **示例实现** | 4-6h | 低 | 中（验证架构） |
| **暂停** | 0h | 无 | 低（仅文档） |

---

## 🎯 我的建议

**立即执行**: 实现完整的 Chat Capability 示例  
**短期目标**: 验证架构可行性  
**中期规划**: 基于示例制定详细迁移计划  

### 示例 Chat Capability 将包含

```go
// AgentCapability: agent.chat.v1
- CreateConversation
- ListConversations  
- GetConversation
- SendMessage (streaming)
- RenameConversation
- DeleteConversation

// 集成现有功能:
- Eino agent runtime
- Tool calling
- Model profiles
- Memory system
```

---

## ❓ 你的选择

**选项 A**: 让我实现 Chat Capability 示例（4-6 小时）  
→ 验证架构，提供迁移模板

**选项 B**: 继续完全迁移（100-140 小时）  
→ 需要多个会话，分多天完成

**选项 C**: 暂停迁移  
→ 当前成果作为技术储备

---

**建议**: 选择 **A**，先验证架构可行性
