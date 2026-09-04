# Agent 可靠性学习 01：不确定写入

本节只学习一个问题：Agent 发起一次写入后收到错误，为什么不能立刻重试？

## 1. 三种结果

一次写入最终只能被可靠地描述为三种状态：

- `changed`：已经读到与本次请求匹配的持久化回执。
- `unchanged`：在与写入相同的串行化栅栏后，确认回执不存在。
- `unknown`：写入报错，随后连权威回执也无法读取或发生冲突。

网络错误只说明“调用方没有收到答案”，不说明数据库是否提交。因此不能把
`timeout` 或 `connection reset` 直接翻译成“失败”。

## 2. 这次修复的链路

```text
Turn ID + Tool Call ID
        |
        v
deterministic operation_id
        |
        v
CreateOffer 原子事务
  plan + execution + task + confirmation + receipt
        |
        +---- 返回成功 ------------------> changed
        |
        +---- 返回错误
                  |
                  v
          同 operation_id 加锁回读 receipt
             |             |             |
           匹配          不存在        读不到/冲突
             |             |             |
          changed       unchanged       unknown
```

关键不是“多试一次”，而是“用同一个身份询问已经发生了什么”。协调步骤只有
读取能力，不会创建新 Offer，也不会调用 AWS。

## 3. 对应代码

- `internal/cloudworker/intrinsic.go`：从 Turn ID 和 Tool Call ID 生成稳定的
  `operation_id`，并把三态变成模型可见的工具结果。
- `internal/cloudworker/service.go`：`CreateOffer` 返回错误后，使用独立且有界的
  context 调用 `ResolveOffer`。原请求即使已取消，协调仍有最多 5 秒完成回读。
- `internal/store/postgres/core_cloud_worker_store.go`：`ResolveOffer` 与写入使用
  同一个 PostgreSQL advisory lock，再校验 operation ID、request digest、Plan ID
  和 owner/account generation。
- `internal/cloudworker/intrinsic_test.go`：分别模拟“提交后响应丢失”“确认不存在”
  和“回读也失败”。

## 4. 为什么不会重复

1. 相同工具调用总是得到相同 `operation_id`。
2. 所有对象 ID 都由该 ID 确定，不会随机生成第二组任务。
3. 写入与回读竞争时使用同一把锁；回读必须等写事务提交或回滚。
4. 回读只查询 receipt，不执行 `CreateOffer`，所以协调本身不产生第二次写入。

## 5. 理解检查

假设数据库已经提交，但 HTTP 响应丢失。Worker inventory 仍显示空闲，能否证明
Offer 没创建？

答案：不能。inventory 是执行面的 Worker 快照；Offer、Plan、Task 和 receipt
属于控制面。必须读取同一 `operation_id` 的控制面回执，才能判断这次写入结果。
