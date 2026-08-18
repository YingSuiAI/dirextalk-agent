# AWS Agent OS Worker 生命周期与时间模型

## 1. 目标

将 `aws-agent-os` 的完成即销毁和 Reaper 异常兜底语义迁移到
`codex/aws-agent-os-adam-integration` 三仓集成分支。任务的正常结束由经验证的
Worker `Complete` 事实触发；用户只看到一项预计时长，不存在任务级最长运行时间。

## 2. 当前差异

| 能力 | `aws-agent-os` | 当前迁移分支 | 迁移要求 |
| --- | --- | --- | --- |
| 时间估算 | Central 为每个角色提供 minimum / expected / maximum | 全局 `max_runtime` | 一个 Plan 仅有 expected runtime |
| 可信校验 | Compiler 检查依赖、并发、资源、策略和费用 | 配置直接复制进 Plan | 模型只提案，确定性代码编译 |
| 正常销毁 | 结果冻结后立即进入 `destroying` | 已具备 | 保留并补齐验收 |
| 异常兜底 | 独立实例销毁 deadline | 旧 `max_runtime` 兼任任务上限 | 仅保留运维 `instance_lifetime` |
| 到期处理 | checkpoint / 恢复 + Reaper | 直接失败并销毁 | 首版先收口并上传已有成果 |
| 资源事实 | 独立回读 `verified_destroyed` | 已具备 | 保留 EC2/EBS/ENI/EIP/SG 五类回读 |

## 3. 目标机制

### 3.1 Central 提案

Central 在 `cloud_worker_propose` 中只提供 `expected_runtime_seconds`：

- expected runtime：用于用户预期和报价展示；
- 它不是执行 deadline，也不要求 Worker 等待至该时刻才能完成。

模型不能提供 AMI、AWS 资源 ID、凭据或任意命令。

### 3.2 确定性编译

Agent 代码必须：

1. 校验 expected runtime 为 60 秒至 24 小时的正整数；
2. 将预计时长、资源、模型、费用和交付物上限写入不可变 Plan 摘要；
3. 使用预计时长计算报价，不将它传为 Worker 的终止条件；
4. 将独立的 `instance_lifetime` 编译为 AWS destroy deadline；
5. 任何变更必须产生新 Plan revision。

`instance_lifetime` 是仅供运维的资源泄漏保险时长，不投影到 App。旧部署中的
`max_runtime` 仅作为它的兼容别名读取；新部署应使用 `instance_lifetime`。

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

### 3.4 异常保险时长

`instance_lifetime` 只在 Central 或 Worker 失联、租约无法恢复或 AWS 资源成为孤儿时
兜底。它保留清理窗口，届时 Reaper 回收资源；它不构成模型调用、工具调用或 Pi 子
Agent 的任务级限制。正常成功、失败和取消均在终态确认后立即进入销毁。

### 3.5 Reaper 兜底

Reaper 只处理 Central 不可用、Worker 失联、租约过期或资源孤儿。它按已批准
destroy deadline 回收资源，并与 Central 通过 revision fencing 合并终态。

## 4. App 投影

批准卡必须显示：

- 预计运行时间；
- 最大授权费用；
- 实例、磁盘、网络和交付物保留策略。

运行中与临期状态属于 Agent 详情页；对话中只显示 Central 的真实回复、需要用户
决策的卡片和最终交付物。

## 5. 验收门槛

1. 5 分钟内完成的轻任务不等待预计时长，结果冻结后立即销毁。
2. PPT 重任务使用 Central 生成的动态时间，完成 PPTX/PDF/PNG/QA 后立即销毁。
3. 模拟基础设施 deadline 时，写工作区任务至少保留已有交付物和 partial result，不返回空交付。
4. 用户取消、心跳过期和 Central 重启都能恢复到同一终态。
5. EC2、EBS、ENI、EIP 和专用 Security Group 全部独立回读为不存在。
6. 交付物保留不少于 30 天，Worker 销毁后仍可在 App 中查看。
7. Message Server 不因 Agent 迭代被重启；旧 Plan 和已有完成事件仍可读取。

## 6. 发布规则

- 不在单元测和 demo4 真实闭环通过前提交 PR。
- 不覆盖三仓当前未提交修改。
- 不使用 Docker Hub 或公开镜像仓库。
- 涉及公开 projection 契约时，原子更新 Agent 与 Message Server；不改变数据库、Worker AMI 或已有交付物。
- 真实测试后必须清理所有临时 AWS 资源并回读确认。
