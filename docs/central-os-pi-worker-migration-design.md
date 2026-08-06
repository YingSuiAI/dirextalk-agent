# Agent Core v1 + Central OS Pi Worker 三仓统一迁移设计

状态：已由用户确认，进入三仓实施规划

日期：2026-08-06

## 1. 目标

以以下三个远端分支为新的代码与架构基线：

| 仓库 | 基线分支 | 冻结提交 |
| --- | --- | --- |
| `dirextalk-agent` | `origin/adam/agent-core-v1-integration` | `a5474faa8643b1d104c4deafea6e831a54a1872f` |
| `dirextalk-message-server` | `origin/adam/agent-core-v1-integration` | `51fac407aa552500a1e14c39ae142948ecb03795` |
| `dirextalk-flutter` | `origin/adam/agent-core-v1-integration` | `00a4d9d6b5c3e59c048c7aa26b26ee613dcf38e9` |

在不恢复旧 Native Agent 架构的前提下，把已完成真实 AWS 验收的 Central OS + Pi Worker 能力迁入 Agent Core v1，形成以下产品事实：

1. Agent Core 是唯一的 Central Agent 运行时和数据权威。
2. Central 可以把一个重任务编译成最多 3 个角色的受限 Team Plan。
3. Central 通过类型化 AWS 接口启动零入站 Pi Worker，完成身份认证、任务领取、执行、结果回收和资源销毁。
4. Message Server 只做代理和产品事件投递，不保存 Agent 执行历史。
5. Flutter 只连接 Message Server，聊天保留正常对话，任务详情在独立的“运行与任务”页面按需查看。
6. 最终验收必须重新证明 App 到 Worker 再回 App 的真实闭环和任务资源归零，不能用旧闭环证据代替新基线验收。

## 2. 已确认方案

采用“目标基线 + 能力级移植”，不采用 Git 历史级合并。

- 不把旧分支 merge 到 Agent Core v1。
- 不把旧闭环的 120 个 Agent 独有提交逐个 cherry-pick。
- 每个迁移单元先冻结行为测试，再在目标架构中重新接线。
- 旧闭环分支、发布镜像和验收记录只作为行为基准与回归证据，不作为新代码依赖。
- 新实现不能通过 `replace`、子模块、复制旧数据库或双写方式依赖旧仓库工作区。

## 3. 目标架构

```text
Flutter owner session
        |
        | ProductCore actions / Native Agent stream
        v
Message Server
        |
        | mTLS + capability grant + account generation
        v
Agent Core v1
  +-- coreconversation / coremodel / coreknowledge
  +-- coretask / coreconfirmation / coreaws
  +-- coreexecutionv2 / coreworkload
  +-- agent.team.v1                 [new capability]
        +-- Team compiler and pricing
        +-- Team execution controller
        +-- Worker identity and lease control
        +-- Pi Worker release and artifact contracts
        +-- typed AWS Worker lifecycle
        +-- result verification and cleanup proof
        +-- durable progress and audit outbox
                  |
                  | outbound-only authenticated control
                  v
        Ephemeral AWS Pi Workers, max concurrency 3
```

### 3.1 仓库责任

#### Agent

Agent 是 Team Plan、Team Execution、Worker、结果、进度、凭证绑定和云资源生命周期的唯一权威。新增能力 ID 固定为 `agent.team.v1`。该能力只有在数据库、Core Task、Core Confirmation、类型化 AWS、Worker 发布清单和后台控制器全部就绪后才进入 Capability catalog。

Team 是 Core 的一个执行能力，不是第二套 Agent。它复用：

- `coretask` 的任务、尝试、租约、取消、重试和事件语义；
- `coreconfirmation` 的消费、网络暴露和销毁确认；
- `coreaws` 的加密 AWS 凭证和请求内解密；
- Capability API 的 owner、account generation、mTLS、grant、schema digest 和操作日志；
- Agent 自己的 PostgreSQL、密钥和文件根目录。

Team 可以维护自己的角色 DAG、Worker 租约、资源账本和结果表，但必须绑定一个顶层 Core Task。不得创建第二套用户身份、模型配置、聊天历史、通用任务列表或 AWS 凭证库。

`agent.team.v1` 与 `agent.execution.v2` 是两个同级能力。Team 不把角色、Worker 或 Team Report 伪装成 Execution V2 resource；它只复用 Execution V2 已经建立的类型化 provider 端口和 AWS readiness 证明。

#### Message Server

Message Server 继续作为 owner-authenticated 产品门面。它只做：

- 将 `agent.team.*` ProductCore action 映射到 `agent.team.v1` 操作；
- 校验 Capability catalog 中的输入、输出 schema digest 和 readiness；
- 传递 owner、account generation、幂等键和受限参数；
- 接收封闭的 Team 完成通知并推动 Flutter 对账 Agent 已持久化的原会话消息；
- 向 Flutter 返回严格、去敏的列表和详情投影。

Message Server 不增加 Team 执行数据库，不复制 Worker 事件，不读取 CloudWatch，不保存 AWS 或模型明文凭证。

#### Flutter

Flutter 继续使用目标分支现有 Agent Core discovery、Native Agent chat、模型、知识和 Web Search 实现。新增范围限于：

- Team Plan 确认；
- 任务列表和详情；
- 取消、失败、重试和最终结果；
- 产物元数据；
- App 本地严格 DTO 和展示状态。

Flutter 不直接连接 Agent，不保存 Worker/AWS 坐标，不把运行过程写入聊天，不恢复旧 runtime profile 选择器。

## 4. 核心数据流

### 4.1 创建与批准

1. 用户在 Native Agent 会话中提出重任务。
2. Central 模型只能调用服务端内置 `team_plan_prepare` 工具，提交角色目标、依赖和能力需求。
3. `agent.team.v1` 用已签名的官方 Pi runtime catalog、AWS 凭证状态、区域价格和并发上限编译 Team Plan。
4. 计划持久化为一个 `task_kind=team_execution` 的顶层 Core Task 和不可变 Plan revision，状态为 `waiting_user`；Plan 投影包含通用 `confirmation_id`。
5. Flutter 通过现有 `agent.core.confirmations.get/confirm/reject` 操作处理确认。`coreconfirmation` 绑定 owner、Plan revision/digest、runtime/AMI digest、AWS credential revision、实例规格、区域、网络权限、预算、输入和过期时间。
6. 用户确认后，控制器原子消费 confirmation 并进入可执行状态。模型或 Message Server 均不能直接绕过确认启动 AWS。

### 4.2 Worker 执行

1. 控制器按依赖关系选择可运行角色，任何时刻最多 3 个 active Worker。
2. 类型化 AWS 适配器创建受标签约束的 SG、ENI、EIP、加密 EBS 和 EC2；Worker 无入站端口、无 IAM/EC2/Foundation 控制权限。
3. Worker 使用一次性身份材料主动连接 Agent，完成挑战、身份校验、领取、租约和心跳。
4. Agent 提供内容寻址的输入清单。Worker 只获得该角色允许的输入、模型使用材料和结果上传权限。
5. Pi 运行时执行固定角色任务，通过 `Complete` 只提交 canonical、有界、SHA-256 绑定的 `ResultPayloadV1` 候选结果；载荷只含状态、摘要、交付项、测试、风险和累计 token 用量，未知字段、敏感 Key、原始思考、工具调用流、终端输出和 provider 错误在落库前拒绝。
6. Agent 先把候选结果置于 `cleaning_up`，再校验 schema、大小、digest、角色/尝试/租约绑定和结果证据并迁入 ResultStore；校验和云资源清理都完成后才允许角色成功。

### 4.3 完成与清理

1. Central 汇总所有角色结果，生成不可变 Team Report。
2. Worker 输出只提供候选结论、交付物和测试结果；云资源是否已清理只能由 Central 的 AWS 读回事实决定。
3. 控制器销毁全部临时资源，并逐项读回 EC2、EBS、ENI、EIP 和 SG 状态。
4. 只有结果已验证且资源账本全部 `verified_destroyed`，Execution 才能进入 `completed`。
5. Agent 在一个本地事务边界内冻结 Team Report、向原 Agent-owned conversation 追加 Central 最终消息并写入 `team_completion_outbox`。异步通知只携带 `event_id`、`execution_id`、`task_id`、`conversation_id`、终态、`result_message_id` 和完成时间。
6. Message Server 幂等接收封闭通知并推送 realtime invalidation；Flutter 回读 Agent-owned conversation 和 Execution 详情，显示最终摘要和产物入口。Message Server 可以保存 event ID 去重收据，但不能保存 Team 执行历史。
7. 失败、取消或超时同样必须进入清理流程；清理不确定时保持 `attention_required`，不能伪装成完成。

异步完成发生时，原聊天 RPC 和短期用户 delegation 已经结束，因此完成通知不能重放或延长原用户 grant。通知固定走现有 Agent→Message Server Product Capability mTLS 连接上的专用 service-notification 分支：Message Server 从部署配置派生 owner 和 account generation，并同时校验 mTLS 客户端证书、方向 token、Agent instance ID、generation、固定 `product.agent_team.v1/completion_record`、规范请求 digest 和永久 operation ID 去重。该分支不能调用其他 Product operation，也不能携带用户可选 owner、scope 或业务 action；除此之外的 Product Capability 调用仍必须完整使用现有用户 delegation/grant。

## 5. 关键约束

### 5.1 并发和运行时

- MVP 全局 Worker 并发上限固定为 3，单个 Team Plan 角色数也固定为 1 到 3。
- MVP 只发布并执行官方 Pi runtime。其他 runtime 只能保留为未就绪 catalog vocabulary。
- 第一轮迁移先恢复单 Pi 闭环，再开放 3 Worker 并发；并发功能不能替代单 Worker 验收。
- 第一轮付费验收固定在大阪 `ap-northeast-3`，默认使用当前报价和容量均通过预检的 `t3.small`；变更实例规格或区域必须重新报价并重新绑定 confirmation。
- Central 所在 2 核 2G 节点负责计划、调度、状态检查、结果验证和轻量汇总；重执行和可选独立 review 由 Worker 角色承担。

### 5.2 AWS 凭证

- AWS key 由 App 通过 Message Server 的 write-only action 写入 Agent Core；Message Server 和 Flutter 不长期保存明文。
- Agent Core 使用现有 `core_aws_credentials` 加密存储和 credential revision，不建立 Team 私有凭证表。
- 创建、替换或删除 AWS key 前，Agent 必须在同一事务内确认该 `owner_id + account_generation` 没有非终态 Team Execution。
- 存在运行中任务时返回固定错误 `team_execution_active`，Flutter 提供“查看任务”和“终止任务”入口；不得边运行边换 key。
- Worker 永远不接收用户 AWS key，也不能获得创建或销毁云资源的权限。

### 5.3 模型配置

- 用户范围内存在 `queued` 或 `running` 的 Knowledge 索引任务时，禁止切换嵌入模型；App 应提示用户先等待任务完成，或进入“运行与任务”终止相关任务。
- 任务取消或进入终态并释放活动模型引用后，才允许切换；“检查活动任务”和“写入新模型配置”必须与任务创建使用同一数据库互斥边界，不能采用先查后改的竞态实现。
- 每个索引任务永久绑定排队时的 owner、account generation、模型 ID、模型 revision、向量维度和 collection config digest。即使旧版本进程或恢复竞态绕过切换门禁，Worker 也只能使用任务绑定，不能重新读取当前默认模型覆盖它。
- Central 的后台维护先处理系统内部范围，再枚举有 Knowledge 资料的公共用户，并为每位用户恢复独立 owner scope；禁止无上下文扫描跨用户资料或配置。

### 5.4 审批与费用

- Team 不迁入旧的独立 approval-device 数据库和密钥体系，统一使用 Agent Core 的 `coreconfirmation`。
- Team confirmation 必须扩展完整绑定字段，不能把预算、AMI、runtime、credential revision、区域或网络权限放进自由文本。
- 面向用户的 Task 与 Confirmation 必须由 Capability `PermissionContext` 派生 `owner_id + account_generation`，并在任务、事件、确认和幂等回执的数据层统一隔离；调用者不能在请求正文覆盖身份。
- 带 Agent service token 的 Core gRPC 只作为内部管理和运行时接口，不作为 Message Server 的 owner-authenticated 产品入口。
- 价格预估与 hard budget 必须由受信服务生成，模型只能提出角色和能力需求。
- 开发验收单次预计费用低于人民币 10 元时，可以按用户已有授权直接创建一次性测试资源；测试仍必须真实走产品 confirmation 和 hard budget，不能用自动化后门削弱正式契约。

### 5.5 进度和隐私

- Central PostgreSQL 是产品进度的唯一读源；CloudWatch 仅用于异步审计。
- Worker milestone 先在数据库中和 audit Outbox 原子落盘，再异步写 CloudWatch；CloudWatch 故障不能让已接收的 Worker 任务失败。
- Chat 只显示目标、必要确认、必须由用户处理的问题和最终结果。
- “运行与任务”页面按需读取 `queued`、`preparing`、`starting_worker`、`preparing_input`、`running`、`validating_result`、`cleaning_up` 和终态。
- 公共 API、日志和 UI 禁止出现原始思考、工具参数/结果、终端输出、provider 原始错误、密钥、Worker ID、Deployment ID、租约 epoch、日志引用、实例/IP/AMI 等云坐标。

## 6. 保留清单

| ID | 来源 | 保留内容 | 落点/约束 |
| --- | --- | --- | --- |
| K-01 | Agent Core v1 | 独立单用户 Agent、Agent 自有 PostgreSQL/文件/密钥 | 原样保留，Team 只能作为 Core 能力 |
| K-02 | Agent Core v1 | Capability API、mTLS、grant、account generation、catalog schema digest | `agent.team.v1` 必须完整接入 |
| K-03 | Agent Core v1 | `coretask` 的幂等、revision、attempt、lease、cancel、retry、events | 增加闭合的 `team_execution` Task kind/payload，不另建通用 Task |
| K-04 | Agent Core v1 | `coreconfirmation` 的等待、确认、消费、过期和不确定结果 fence | 增加 Team binding resolver |
| K-05 | Agent Core v1 | `core_aws_credentials` 加密存储、revision 和类型化 SDK | Team 只引用 credential ID/revision |
| K-06 | Agent Core v1 | `coreexecutionv2`、`coreworkload` 的 target/provider/readiness 能力 | 复用端口和 provider；不复制已有 EC2/CloudFormation 领域 |
| K-07 | Message Server | `internal/agentgateway`、catalog readiness、ProductCore owner action | 添加 Team action binding 和严格 schema pin |
| K-08 | Flutter | Agent Core discovery、聊天、模型、知识、Web Search 和账号隔离 | 保持目标分支实现，不回迁旧层 |
| K-09 | 已验收闭环 | Team Proposal 编译、角色依赖、最多 3 Worker、价格/预算和不可变 Plan | 行为测试先行后移植到新 `coreteam` 域 |
| K-10 | 已验收闭环 | Worker 身份挑战、一次性 enrollment、claim、heartbeat、lease fence | 协议语义与安全边界保留，重新接入 Core 服务 |
| K-11 | 已验收闭环 | 零入站 Worker、官方 Pi 0.83.0、AMI/ECR/rootfs/release digest | 保留发布制品契约，重新生成目标基线镜像 |
| K-12 | 已验收闭环 | 输入 materialization、输出预算、Pi closed failure code、结果扩展 | 保留封闭 schema 和真实二进制资格测试 |
| K-13 | 已验收闭环 | 结果/产物 digest 校验、不可变 Team Report、Central-owned cloud facts | 迁入新结果域，禁止 Worker 声称云清理 |
| K-14 | 已验收闭环 | EC2/EBS/ENI/EIP/SG 账本、销毁重试、Reaper 和独立读回 | 用目标 typed AWS 端口重新接线，行为不降级 |
| K-15 | 已验收闭环 | 原会话唯一关联完成事件和 App 自动显示 | 改用目标 Capability/Event 边界实现相同行为 |
| K-16 | 已确认设计 | Central 持久化 milestone、异步 CloudWatch Outbox、独立 Runs 页面 | 纳入最终迁移验收，不携带暂停草稿代码 |

## 7. 重写清单

| ID | 需要重写 | 原因 | 新实现要求 |
| --- | --- | --- | --- |
| R-01 | Team API/Proto | 旧 `TeamPlanService` 是目标架构外的直连 gRPC | 新建 `agent.team.v1` Capability descriptor；只保留必要 Core typed adapter |
| R-02 | Team Task 持久化 | 旧 `tasks/task_steps` 与 `core_tasks` 重复 | 顶层使用 Core Task；Team 子表用 `core_` 命名并外键绑定 Task |
| R-03 | Team confirmation | 旧 approval device/challenge 与 `coreconfirmation` 重复 | 用通用 confirmation 加 Team 精确 binding 和消费 fence |
| R-04 | AWS credential/connection | 旧 Cloud Connection/secret bootstrap 与 Core AWS 凭证重复 | 统一到 `core_aws_credentials`，加“无活动 Team 才能变更”规则 |
| R-05 | AWS Worker provider | 旧 provider 直接依赖旧 cloud composition | 通过目标 `coreaws/coreexecutionv2/coreworkload` typed ports 适配 |
| R-06 | Agent composition | 旧 `cloud_composition.go` 不存在于新 Core | 在 `serveCore` 中显式组合 Team，readiness 完整才发布 |
| R-07 | Worker RPC 边界 | 旧 `WorkerControlService` 使用旧 service token 和存储 | 独立 Worker listener/认证子服务，绑定 Agent instance、Task、role、attempt、lease |
| R-08 | Worker release | 旧 Agent 镜像和 Worker 镜像构建路径与统一 Core 镜像不同 | 重新生成 Core 基线下的 control image 和 Pi Worker release manifest |
| R-09 | 完成事件 | 旧 Agent `WatchEvents` 到 Message Server cursor relay 已不适配 | Agent conversation 消息 + durable completion Outbox + Message Server 去重通知 |
| R-10 | Message Server Team facade | 旧 `p2p/internal/agentgrpc` 已被 Agent Gateway 取代 | 在 `agentgateway` 增加 action binding、schema pins 和结果 adapter |
| R-11 | Message Server actions | 旧 action 集重复了 Core confirmation，且缺列表/取消/进度 | 只保留 Plan/Execution action；确认统一映射现有 Core confirmation |
| R-12 | Flutter Team client | 旧 `http_as_client` 和 runtime profile 分支已演进 | 在现有 Agent Core client 上增加严格 Team DTO/方法 |
| R-13 | Flutter Team UX | 旧计划卡、交付物页依赖旧聊天 Store | 重接现有 Native Agent turn coordinator，运行详情独立于聊天 |
| R-14 | Worker progress | 暂停草稿基于旧 migration 64 和旧表 | 在 `agent_migrations.sql` 当前 schema 后重新编号/设计，先写真实 PostgreSQL 测试 |
| R-15 | 文档和发布 | 旧 Native Agent v2 tracker 不属于新基线 | 新证据写入 Agent Core 的 delivery tracker，旧记录仅做迁移来源 |

## 8. 废弃清单

| ID | 废弃内容 | 处理方式 |
| --- | --- | --- |
| D-01 | 直接 merge 两个大分支 | 禁止；只做行为级移植 |
| D-02 | 批量 cherry-pick 旧 Agent 120 个提交 | 禁止；每个迁移单元必须在新架构重建测试和接口 |
| D-03 | 旧 `RuntimeService`、旧 Chat/Model/Search 配置 | 不迁移，目标 Core 已有权威实现 |
| D-04 | 旧通用 `TaskService` 和 `tasks/task_steps` 作为新主任务账本 | 不迁移，统一使用 `core_tasks` |
| D-05 | 旧 `CloudControlService` 大而全公共 RPC | 不迁移；复用 Core AWS/Execution V2 的类型化能力 |
| D-06 | Team 私有 AWS key/Cloud Connection 明文或平行存储 | 禁止；只使用 Core 加密凭证引用 |
| D-07 | Team 专用 approval-device/bootstrap 数据层 | 不迁移；统一使用 Core confirmation |
| D-08 | `agent.team.plans.approval.prepare/approve` 旧 action | 不迁移；Plan 直接返回 `confirmation_id`，App 使用 `agent.core.confirmations.*` |
| D-09 | Message Server `p2p/internal/agentgrpc` Team adapter | 不迁移；目标是 `internal/agentgateway` |
| D-10 | Message Server 保存 Agent 执行历史或 Worker milestone | 禁止；Agent 数据库是唯一权威 |
| D-11 | Flutter 旧 runtime profile 管理、旧 Agent HTTP 桥和旧模型/search 层 | 不迁移；目标分支实现继续作为权威 |
| D-12 | Worker 原始 reasoning、tool event、stdout/stderr、provider error 上送 | 永久禁止进入公共 API、日志和产品事件 |
| D-13 | CloudWatch 作为产品进度查询源或授予 Control Role 日志读取权 | 禁止；只允许异步写审计 |
| D-14 | 为测试保留长期 EC2/构建机或给 Worker 开 SSM/SSH | 禁止；发布完成即销毁，Worker 零入站 |
| D-15 | 暂停时未审查的 `000064_worker_milestone_events` 草稿 | 不复制；仅参考需求，在新 schema 上重新 TDD 实现 |
| D-16 | 旧分支测试通过即宣称新架构完成 | 禁止；必须重新执行新基线验收矩阵 |

## 9. 验收清单

| ID | 验收门 | 必须提供的当前证据 |
| --- | --- | --- |
| A-01 | 基线冻结 | 三仓从表 1 固定 SHA 创建迁移分支；工作区无旧分支代码污染 |
| A-02 | 基线健康 | Agent Linux build/测试、Message Server CI/测试、Flutter focused test/analyze 在迁移前可重复 |
| A-03 | Capability 合同 | `agent.team.v1` catalog readiness、operation schema/digest、owner/account-generation/grant 测试通过 |
| A-04 | 数据权威 | Team 顶层绑定 Core Task；PostgreSQL 重启后 Plan/Execution/role/Worker/result/cleanup 仍可恢复 |
| A-05 | 隔离与密钥 | Secret canary 不进入 DB 普通字段、事件、日志、错误、API、Worker bundle 或 Git；Worker 无 AWS key |
| A-06 | 确认与配置变更 | 未确认不能创建 AWS；活动 Team 时 AWS key 变更返回 `team_execution_active`；活动 Knowledge 索引时模型切换返回明确的 FailedPrecondition；取消或终态清理后才可变更 |
| A-07 | 单 Pi 本地资格 | 固定 Pi/extension/release digest；真实 Pi 二进制 loopback 产生合法结果；输出预算和 closed failure 分类通过 |
| A-08 | 单 Pi 控制器 | 本地/fake provider 从 Plan 到 completed，覆盖恢复、取消、失败、结果校验和全部资源销毁状态 |
| A-09 | Message Server | Product action contract、gateway schema pins、owner auth、结果去敏、完成通知去重收据和无本地执行账本测试通过 |
| A-10 | Flutter | Plan 确认、Runs 列表/详情、取消、产物和完成消息测试通过；页面不可见时不轮询；普通聊天不被进度打断 |
| A-11 | 真实单 Pi 闭环 | 从已登录 App 提交一个与项目无关的重任务；App/Task/Plan/Execution/role/Worker 关联唯一；Pi 首次或受控重试完成 |
| A-12 | 真实结果 | Central 下载并校验 `final.json` 和产物 digest，冻结 Team Report；App 收到 Central 验证过的总结和产物元数据 |
| A-13 | 真实清理 | Execution 终态前 EC2/EBS/ENI/EIP/SG 全部 `verified_destroyed`；独立 AWS API 按 Task tag 返回空集合 |
| A-14 | 失败与取消 | Worker 启动前、运行中、结果上传时各执行取消/故障注入；均不重复执行、不伪报成功并最终完成清理 |
| A-15 | 并发 3 | 三角色真实或受控 AWS 验收同时 active 数不超过 3，依赖顺序、失败传播、重试和资源隔离正确 |
| A-16 | 进度与审计 | Central DB 可查询封闭 milestone；CloudWatch 故障不阻塞 Worker ack；恢复后 Outbox 可重试且无敏感字段 |
| A-17 | 升级恢复 | Agent、Message Server 任一重启后任务、event cursor、Worker lease 和完成投递可恢复且不重复收费/执行 |
| A-18 | 三仓发布 | 三仓完整 focused/broad checks、diff check、生成合同、镜像 digest、demo2 健康和旧 App 兼容验证通过 |
| A-19 | 最终归零 | 临时 Worker、builder、卷、ENI、SG、角色/profile、S3 输入版本和临时容器全部回读不存在；保留项仅正式 AMI/ECR/必要审计 |
| A-20 | 完成声明 | 上述每项有当前命令、测试、CI、数据库或 AWS 读回证据；缺一项不得标记迁移完成 |

## 10. 公共操作边界

MVP ProductCore action 固定为：

| Action | 类型 | 说明 |
| --- | --- | --- |
| `agent.team.plans.get` | read | 获取不可变 Plan revision 和确认状态 |
| `agent.team.executions.list` | read | owner-scoped active/history 分页列表 |
| `agent.team.executions.get` | read | 获取受限进度、角色、结果和清理投影 |
| `agent.team.executions.cancel` | mutation | 请求取消并进入资源清理，不等同于立即完成 |

确认复用现有 `agent.core.confirmations.get/confirm/reject`。不再提供 Team 专用 approval-device bootstrap、approval prepare 或 approve action。Task retry 只有在原执行已终态且无残留资源时才能创建新 Execution；MVP 不提供原地继续执行的公共 action。

Central 内部模型工具固定为：

- `team_plan_prepare`：只提交受限 Team Proposal，不能审批、启动资源或接触凭证。
- `team_task_status`：只读取 Central 去敏投影和最终报告，不读取 Worker 原始输出。

这两个工具作为 `coreconversation.ExtensionResolver` 链上的服务端内置工具注入，只在当前 owner/account generation、Team capability readiness 和 runtime catalog 均通过时对模型可见。它们不是可安装 MCP，不允许被同名 Skill/MCP 覆盖，也不把 AWS 凭证、报价原文、Worker 结果或内部执行坐标写入模型上下文。

## 11. 错误和恢复

- 所有公共失败只返回固定 error code 和安全摘要。
- 同一 idempotency key + 相同输入返回首次结果；相同 key + 不同输入返回冲突。
- Worker milestone、claim、heartbeat、complete 都绑定 attempt 和 lease epoch，过期调用不得改变状态。
- AWS provider 调用必须使用稳定 client token 和资源标签，进程崩溃后先读回再决定继续、补偿或标记不确定。
- 不确定创建结果不能直接重试创建；不确定销毁结果必须持续读回到已销毁或需要人工处理。
- Agent 重启从 PostgreSQL 恢复；Message Server 重启从 Agent event cursor 恢复；Flutter 重连通过列表/详情和最终事件对账。
- CloudWatch、App 页面或聊天投递故障不改变 Agent 执行事实。

## 12. 实施分解

统一设计批准后，生成三个独立但有顺序的实施计划：

1. Agent：合同与 schema，Core Task/Confirmation/AWS 接入，Worker 控制面，单 Pi 闭环，结果/清理，进度审计。
2. Message Server：Capability catalog/action adapter、严格 DTO、完成事件和生成合同。
3. Flutter：Team client、Plan 确认、Runs 页面、产物和完成展示。
4. 三仓联调：本地 fake E2E、demo2 发布、真实单 Pi、取消/恢复、并发 3、资源归零。

每一阶段必须先有失败测试，再实现，再运行 focused checks。跨仓合同以 Agent descriptor 和 Message Server `ActionSpecs` 为源，Flutter 只在前两者固定后接入。任何阶段若发现目标基线与本设计冲突，先修改并重新审阅本设计，不在代码里暗自增加第二套架构。

## 13. 非目标

本次迁移不包含：

- Worker Market 开放给第三方开发者；
- 多 Agent Core 集群、多租户或跨用户 Worker 池；
- 超过 3 个 Worker 的弹性扩缩容；
- 非 Pi 官方 Worker 镜像；
- 用户自定义任意 DAG 或任意 AWS API；
- Worker SSH、SSM、永久实例或长期交互终端；
- 用户可编辑的通用部署自动化或共享 Worker 集群；固定的每任务临时 Worker 生命周期不属于这两类；
- 把执行过程持续刷入聊天；
- 用第二个模型重新总结每个 Worker 原始过程。

第三方 Worker Market 在官方 Pi 镜像、运行时 catalog、权限清单、签名、扫描、计费和下架标准分别完成后另立设计。

## 14. 设计完成标准

本设计获批只表示迁移边界已冻结，不表示功能已经迁移。只有 A-01 到 A-20 全部取得新基线的当前证据，才可以宣布“Agent Core v1 三仓主体 + Central OS Pi Worker 新增能力”完成。
