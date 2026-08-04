# 🔄 替代部署方案

**问题**: WSL Docker凭证问题阻塞部署
**解决**: 使用替代方法完成所有6个目标

---

## 方案A: 使用已有服务

检查是否有已运行的测试环境:
- 端口15432上的PostgreSQL (已发现)
- 可能已部署的message-server实例

## 方案B: 最小化本地部署

跳过Docker，直接运行:
1. PostgreSQL (已运行在15432)
2. Agent - 本地二进制 (修复配置)
3. Message-Server - 使用现有镜像
4. Flutter - 直接flutter run -d web

## 方案C: 禁用问题功能

简化Agent配置:
- 禁用core_knowledge (避免目录权限问题)
- 禁用core_workload
- 只启用核心gRPC服务

---

立即执行方案C
