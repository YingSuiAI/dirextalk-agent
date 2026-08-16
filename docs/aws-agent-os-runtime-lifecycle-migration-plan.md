# AWS Agent OS 动态运行时间与 Worker 生命周期迁移计划

## 1. 目标

将 `aws-agent-os` 已有的动态 Schedule、完成即销毁和 Reaper 异常兜底语义，迁移到
`codex/aws-agent-os-adam-integration` 三仓集成分支。任务的正常结束由经验证的
Worker `Complete` 事实触发；时间上限只是异常任务的费用和资源泄漏兜底。

## 2. 当前差异

| 能力 | `aws-agent-os` | 当前迁移分支 | 迁移要求 |
| --- | --- | --- | --- |
| 时间估算 | Central 为每个角色提供 minimum / expected / maximum | 全局 `max_runtime` | 改为每个 Plan 的动态估算 |
| 可信校验 | Compiler 检查依赖、并发、资源、策略和费用 | 配置直接复制进 Plan | 模型只提案，确定性代码编译 |
| 正常销毁 | 结果冻结后立即进入 `destroying` | 已具备 | 保留并补齐验收 |
| 异常上限 | Plan 最长时间 + 运维缓冲 | 统一 30 分钟 | 上限必须属于具体 Plan |
| 到期处理 | checkpoint / 恢复 + Reaper | 直接失败并销毁 | 首版先收口并上传已有成果 |
| 资源事实 | 独立回读 `verified_destroyed` | 已具备 | 保留 EC2/EBS/ENI/EIP/SG 五类回读 |

## 3. 目标机制

### 3.1 Central 提案

Central 在 `cloud_worker_propose` 中提供：

- minimum runtime：理想路径所需时间；
- expected runtime：用于用户预期和费用展示；
- maximum runtime：本次批准允许的最长执行时间。

模型不能提供 AMI、AWS 资源 ID、凭据或任意命令。

### 3.2 确定性编译

Agent 代码必须：

1. 校验 `minimum <= expected <= maximum`；
2. 校验 maximum 不超过服务端策略上限；
3. 将时间、资源、模型、费用和交付物上限写入不可变 Plan 摘要；
4. 将 maximum runtime 作为资源泄漏的硬性截止时间；
5. 任何变更必须产生新 Plan revision。

全局配置只定义策略上限，不再作为每个任务的运行时间。

### 3.3 正常完成

```text
running
  -> Worker Complete
  -> result validated
  -> artifacts frozen
  -> destroying
  -> verified_destroyed
  -> Central completion synthesis
```

Worker 必须通过受租约和 epoch 保护的 `Complete` 提交结果。心跳、CPU 空闲、
自然语言声明或文件存在都不能单独代表完成。

### 3.4 临期收尾

在 maximum runtime 之前进入收尾窗口：

1. Central 根据 Plan maximum 和心跳周期计算受信任的 `finish_before`；
2. Worker 在提示词中明确收尾时间，并在该时间终止模型/工具扩展；
3. Worker 在剩余授权时间内冻结工作区、生成 partial result manifest 并上传已有成果；
4. Pi 在收尾窗口前正常提交则按完整结果 `Complete`；
5. 没有可保存工作区的任务仍按失败收口，不伪造结论。

首个迁移版本不允许在没有新授权的情况下静默延长时间。
checkpoint/续跑属于后续版本，不冒充本次已完成能力。

### 3.5 Reaper 兜底

Reaper 只处理 Central 不可用、Worker 失联、租约过期或资源孤儿。它按已批准
destroy deadline 回收资源，并与 Central 通过 revision fencing 合并终态。

## 4. App 投影

批准卡必须显示：

- 预计运行时间；
- 最长执行时间；
- 最大授权费用；
- 实例、磁盘、网络和交付物保留策略。

运行中与临期状态属于 Agent 详情页；对话中只显示 Central 的真实回复、需要用户
决策的卡片和最终交付物。

## 5. 验收门槛

1. 5 分钟内完成的轻任务不等待 Plan maximum，结果冻结后立即销毁。
2. PPT 重任务使用 Central 生成的动态时间，完成 PPTX/PDF/PNG/QA 后立即销毁。
3. 模拟超时时，写工作区任务至少保留已有交付物和 partial result，不返回空交付。
4. 用户取消、心跳过期和 Central 重启都能恢复到同一终态。
5. EC2、EBS、ENI、EIP 和专用 Security Group 全部独立回读为不存在。
6. 交付物保留不少于 30 天，Worker 销毁后仍可在 App 中查看。
7. Message Server 不因 Agent 迭代被重启；旧 Plan 和已有完成事件仍可读取。

## 6. 发布规则

- 不在单元测和 demo4 真实闭环通过前提交 PR。
- 不覆盖三仓当前未提交修改。
- 不使用 Docker Hub 或公开镜像仓库。
- 部署只重启 Agent，不重启 Message Server。
- 真实测试后必须清理所有临时 AWS 资源并回读确认。
