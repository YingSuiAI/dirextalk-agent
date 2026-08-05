# Native Agent v2 Worker 运行监控与按需详情设计

> 状态：2026-08-06 产品设计已确认，尚未实施。
>
> 所属规划：`docs/native-agent-v2-system-plan.md`
>
> 实施进度仍以 `docs/delivery-tracker.md` 为唯一账本。

## 1. 决策

Worker Agent 按 Central Agent 的子 Agent 运行实例处理。

- 会话只承载用户目标、费用/权限确认、必须由用户处理的问题和最终结果。
- Worker 的启动、心跳、输入准备、运行、验证和清理进度不产生聊天消息。
- 用户从 Agent 详情入口进入独立的“运行与任务”页面，按需查看当前和历史运行。
- Central 无论 App 是否打开，都持续监控 Worker、结果验证和资源清理。
- 不展示或保存模型原始思考、自然语言运行日志、工具参数/结果、终端输出或秘密。

这不是隐藏故障。需要用户介入的失败仍可进入会话；普通进度和可恢复故障只进入
运行详情与 Central 监控面。

## 2. 当前事实与真实缺口

当前生产 Worker 已经能通过 `WorkerControlService.EmitMilestone` 上报封闭事件，
Agent 会重新校验会话、租约、Owner、Deployment、Connection 和 Foundation 后，
使用 Control Role 写入 CloudWatch。2026-08-05 的 v89 验收 Worker 已真实产生：

1. `execution_started`
2. `action_started(materialize-input)`
3. `action_succeeded(materialize-input)`
4. `action_started(execute-role)`
5. `action_succeeded(execute-role)`
6. `execution_finished(succeeded)`

因此缺口不是 Worker 没有进度，而是：

- 进度只写入保留 30 天的 CloudWatch，Central PostgreSQL 没有产品级持久记录。
- Control Role 只有 `CreateLogStream`/`PutLogEvents`，没有日志读取权限。
- `GetTeamExecutionV3` 只能返回执行级粗状态，不能解释每个角色当前在做什么。
- Message Server 和 Flutter 没有运行列表、角色进度和诊断详情合同。
- CloudWatch 写入当前位于 Worker 同步路径，日志服务故障可能反向阻塞任务。

CloudWatch 不能成为 App 或 Central 监控的真相源，也不应通过增加读权限来补产品合同。

## 3. 产品体验

### 3.1 会话

保留现有任务计划/批准卡和最终完成消息，但不增加 Worker 进度消息流。

- 计划卡可以保留一个紧凑的“执行中”状态和进入详情的入口。
- 不在会话中逐条发送“实例已启动”“正在执行工具”等消息。
- Central 只有在任务需要用户选择、补充凭据、重新批准或决定是否终止时才发消息。
- 最终结果继续回到原会话，并与 Task、Plan、Execution 保持唯一关联。

### 3.2 Agent 详情入口

当前 Agent 详情/设置页的 `Ying Agent` 区域增加“运行与任务”入口，打开独立页面，
不把运行面板直接塞进设置卡片或聊天页。

“运行与任务”页面包含两个视图：

- `运行中`：只列出未终止的执行，并显示运行数量。
- `历史`：分页显示已完成、失败、取消和超时的执行。

列表项只显示适合扫描的信息：任务/角色名称、当前阶段、健康状态、开始时间、
持续时长和最近更新时间。点击后进入一次执行的详情。

### 3.3 执行详情

详情页展示：

- Task、Plan 和 Execution 的用户可识别关联。
- 当前阶段、开始时间、持续时长和最终状态。
- 每个角色的运行时、已批准实例规格、尝试次数和心跳新鲜度。
- 受限阶段时间线、固定失败阶段/代码、结果验证和资源清理状态。
- 已有的取消能力；终止后仍由 Central 监督资源清理。
- 完成后跳转到原会话最终结果和已验证交付物的入口。

详情页不显示 EC2/ENI/EIP/安全组 ID、Worker/Deployment ID、S3/CloudWatch 坐标、
模型推理、工具参数/输出、供应商错误原文、凭据或秘密。

## 4. Central 监控模型

### 4.1 真相源

Central 使用已有的受信事实组合运行状态：

- `team_role_dispatches`：角色从准备、供应、活跃、结果就绪到销毁/完成的阶段。
- `worker_deployments`：注册、租约、心跳、取消和 Worker 终态。
- 新增的 `worker_milestone_events`：Worker 会话上报的封闭执行里程碑。
- 既有结果、报告、资源账本和销毁验证事实。

不新增一套可与这些表冲突的可写“总状态”。查询服务按固定优先级组合当前投影，
终态、结果和清理只能来自 Central 已有的受信事实，不能由 Worker 自报覆盖。

### 4.2 持久事件

新增迁移 `000064_worker_milestone_events`，保存不可变、去秘密的 Worker 收件事实：

- Central 接收的稳定 `event_id` 和单调 `event_seq`。
- Agent instance、Owner、Deployment、Task 和 Step 关联。
- attempt、lease epoch、固定 kind/action/outcome/failure stage/failure code。
- Central 接收时间和严格事件摘要。
- 用于精确重放比对的事件摘要 digest。

写入必须在 PostgreSQL 事务中再次检查当前 Worker 会话、租约和 Deployment 关联。
相同 `event_id` 和相同 digest 是成功重放；相同 ID、不同内容必须失败关闭。过期租约、
跨 Owner、跨 Deployment、乱序非法状态和未知字段均不能落库。

仅与 `team_role_dispatches` 唯一关联的事件才能进入用户可见 Team 进度；其他合法 Worker
事件可供 Central 内部诊断，但不能误投影到某个 Agent 任务。

### 4.3 CloudWatch 审计副本

数据库事务同时写入专用的 `worker_milestone_log_outbox`。后台投递器使用现有 Control
Role 将同一封闭事件异步写入 CloudWatch：

- Worker 在 PostgreSQL 成功提交后即可得到成功响应，不等待 AWS Logs。
- CloudWatch 故障不会导致 Pi 任务失败或重复执行。
- 投递器使用租约、退避和固定失败代码恢复，绝不记录供应商错误原文。
- CloudWatch 继续允许至少一次投递，稳定 `event_id` 用于识别重复。
- 不给 Control Role 增加 `GetLogEvents`、`FilterLogEvents` 或其他读取权限。

Central 产品查询只读 PostgreSQL。CloudWatch 仅用于运维审计和独立交叉验证。

### 4.4 公共阶段

Central 将内部事实映射为稳定、可本地化的公共阶段：

1. `queued`
2. `preparing`
3. `starting_worker`
4. `preparing_input`
5. `running`
6. `validating_result`
7. `cleaning_up`
8. `completed`
9. `failed`
10. `canceled`
11. `timed_out`

`running` 只表示 Worker 租约、心跳和执行里程碑共同证明 Agent runtime 正在执行，
不能描述为读取了模型“思考过程”。未来工具收据也只能使用审核过的固定工具类别，
不能暴露工具参数、返回值或自然语言日志。

健康状态独立于阶段：

- `healthy`：心跳和阶段更新时间在允许窗口内。
- `delayed`：仍在租约内，但超过进度新鲜度阈值。
- `recovering`：Central 已进入有界重试/恢复。
- `attention_required`：需要用户决定或重新批准。
- `terminal`：执行已终止。

健康状态是 Central 根据可信时间和恢复事实推导的投影，不由 Worker 提交。

## 5. 三仓合同

### 5.1 dirextalk-agent

- 持久化并精确重放 Worker milestones。
- 将 CloudWatch 写入移出 Worker 同步执行路径。
- 增加 Owner 限定、分页的 `ListTeamExecutionsV3`。
- 扩展 `GetTeamExecutionV3`，返回受限执行进度、角色进度和最近阶段时间线。
- 时间线有严格数量上限和确定性排序；历史分页使用不透明 cursor。
- 保持现有完成报告、制品和 `cleanup_verified` 权威边界不变。

### 5.2 dirextalk-message-server

- 增加 `agent.team.executions.list` ProductCore action。
- 扩展现有 `agent.team.executions.get` 的严格映射。
- 逐字段校验 Owner、枚举、时间、分页 cursor 和进度绑定。
- 不把进度写成 Matrix 消息，不向 ProductCore 实时事件流发布逐条 Worker milestone。
- 保留现有 `agent.team.execution.completed` 最终完成投递。

### 5.3 direxio-flutter

- 在 Agent 详情入口增加“运行与任务”，再进入独立列表和详情页。
- 页面打开时读取；运行中页面可每 2 秒刷新，页面离开或 App 非活跃时停止轮询。
- 使用分页历史、下拉刷新和诚实的空/错误状态。
- 固定失败代码在客户端本地化，不渲染后端自由文本。
- 取消操作继续使用现有 Task 取消合同，并显示 Central 继续清理的状态。
- 不为进度创建聊天消息或第二套本地消息存储。

## 6. 读取合同边界

公共执行概览最少包含：

- Execution/Task/Plan 关联和执行状态。
- 当前公共阶段、健康状态和最近更新时间。
- 总角色数、运行中角色数和终止角色数。
- 完成时的 `cleanup_verified`。

公共角色详情最少包含：

- role ID/title、固定 runtime family/adapter、公共阶段和健康状态。
- attempt、开始时间、最近心跳时间、最近阶段时间。
- 可选固定失败 stage/code。
- 有界、按 Central `event_seq` 排序的公共阶段时间线。

公共 API 不返回内部 event ID、event digest、Worker/Deployment ID、lease epoch、
CloudWatch/S3 引用、资源 ID 或任何自由文本诊断。

## 7. 故障与恢复

- Worker 响应丢失：稳定事件 ID 精确重放，不产生第二条 Central 事件。
- Agent 重启：从 PostgreSQL 恢复当前角色/Worker/里程碑状态，不读取 CloudWatch 重建。
- CloudWatch 不可用：任务继续；日志 Outbox 后台恢复。
- Worker 心跳停止：现有租约/恢复控制器处理，详情投影显示 delayed/recovering。
- Central 进程在里程碑提交后崩溃：事件和日志 Outbox 同事务，不丢产品事实。
- Message Server 或 App 离线：重新打开详情时重新读取最新投影，无需回放聊天消息。
- 任务取消：停止执行与销毁是两个阶段；只有 Central 验证清理后才显示清理完成。

## 8. 验证门槛

### Agent

- 正常、失败、取消、超时和恢复阶段映射测试。
- 重复 ID 同内容成功、同 ID 不同内容拒绝、乱序/过期租约拒绝。
- 跨 Owner/Execution/Role 投影拒绝和时间线边界测试。
- PostgreSQL 事务、竞争、重启恢复和日志 Outbox 测试。
- CloudWatch 故障不影响 Worker 完成的回归测试。
- secret/raw output/tool argument/provider error canary。

### Message Server

- List/Get 的严格 schema、Owner 范围、分页和未知字段拒绝测试。
- 进度不会产生聊天消息或 ProductCore milestone 的回归测试。
- 既有完成事件 cursor、幂等和最终结果投递保持通过。

### Flutter

- 运行中/历史列表、详情时间线、失败本地化、取消和空/错误状态测试。
- 轮询只在页面可见且 App 活跃时运行。
- 进度不会写入 Native Agent chat store。
- 小屏、长标题、深浅主题和返回/恢复路径的 widget 验证。

### 真实闭环

从 App 发布一项新的非项目重任务，并同时在原会话继续发送另一条消息：

1. Agent 详情页按顺序看到 Worker 启动、输入准备、运行、验证和清理。
2. 原会话没有逐条 Worker 进度刷屏，仍可正常处理另一条消息。
3. Central 在 App 详情页关闭期间继续更新并恢复状态。
4. 最终结果只投递一次并回到正确会话。
5. PostgreSQL、CloudWatch 和独立 AWS 资源读回能关联同一次执行。
6. 任务标记的 EC2、EBS、ENI、EIP 和安全组最终均为零。

## 9. 明确不做

- 不提供 SSH、SSM 或远程终端入口。
- 不展示模型 chain-of-thought 或原始 Pi 事件流。
- 不把 CloudWatch 变成产品数据库。
- 不为运行进度增加第二次 Central 模型总结。
- 不在本阶段实现 Worker Marketplace、多 Worker 编排 UI 或跨用户共享 Worker。
- 不承诺实时 CPU/内存/网络图表；阶段、租约、心跳、结果和清理是第一版监控范围。
