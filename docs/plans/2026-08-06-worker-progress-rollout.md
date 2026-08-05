# Worker Progress Three-Repository Rollout Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver Central-owned Worker monitoring plus an on-demand App detail surface without adding progress messages to Chat.

**Architecture:** Agent owns durable receipts, audit delivery, and progress truth; Message Server is a strict owner-scoped query façade; Flutter reads only while the runs UI is open. The repositories integrate in that order because Message Server must compile against the committed Agent protocol and Flutter must follow the generated ProductCore contract.

**Tech Stack:** Go/PostgreSQL/gRPC/AWS in Agent, Go/ProductCore in Message Server, Flutter/Riverpod/GoRouter in App.

---

## Child Plans

- Agent: `docs/plans/2026-08-06-worker-progress-agent.md`
- Message Server: `/Users/liyanan/Documents/Dirextalk项目监控分析/repos/dirextalk-message-server-central-agent/docs/plans/2026-08-06-worker-progress-message-server.md`
- Flutter: `/Users/liyanan/Documents/Dirextalk项目监控分析/repos/direxio-flutter-native-agent-v2/docs/plans/2026-08-06-worker-progress-flutter.md`

### Task 1: Execute And Publish The Agent Contract

**Files:** Agent files listed in the Agent child plan.

- [ ] **Step 1: Execute Agent Tasks 1-7 in order**

Use TDD and the commit boundaries in `2026-08-06-worker-progress-agent.md`. Do not begin Message Server dependency changes before the Buf-generated contract and Agent focused tests pass.

- [ ] **Step 2: Run accumulated Agent verification**

Run the exact commands in Agent Task 7, including disposable PostgreSQL 18. Expected: all required lanes PASS and CloudWatch failure cannot fail Worker milestone acknowledgement.

- [ ] **Step 3: Push the Agent branch**

Run: `git push origin codex/pi-worker-real-task-fix`

Expected: remote branch contains the immutable protocol commit that Message Server can reference.

### Task 2: Execute The Message Server Façade

**Files:** Message Server files listed in its child plan.

- [ ] **Step 1: Execute Message Server Tasks 1-4 in order**

Adopt the real pushed Agent module revision, then implement list, query-only details, action registration, and contract generation.

- [ ] **Step 2: Prove completion-event compatibility**

Run the Agent gRPC, `agentcompletion`, action-registry, build, and diff checks in the child plan. Expected: no progress key in `agent.team.execution.completed`, no database migration, no Matrix message, and no realtime progress event.

- [ ] **Step 3: Push the Message Server branch**

Run: `git push origin codex/native-agent-v2`

Expected: remote branch contains the strict ProductCore contract used by Flutter.

### Task 3: Execute The Flutter Runs UI

**Files:** Flutter files listed in its child plan.

- [ ] **Step 1: Execute Flutter Tasks 1-7 in order**

Implement strict Team progress data, providers, localized text, Agent details entry, active/history list, execution detail, cancellation, and Chat isolation.

- [ ] **Step 2: Run focused and broad Flutter verification**

Run the exact Task 7 commands. Expected: widget/data/provider tests PASS, analysis and local verify PASS, and the App contains no progress-to-chat write path.

- [ ] **Step 3: Push the Flutter branch**

Run: `git push origin codex/native-agent-v2`

Expected: remote branch contains the on-demand runs UI and current ProductCore contract.

### Task 4: Review The Accumulated Cross-Repository Contract

**Files:** All changed files in the three branches.

- [ ] **Step 1: Run protocol and schema diff checks**

Compare Agent proto fields, Message Server JSON mapping, Flutter exact field sets, enum values, limits, and timestamps. Expected: names/types/limits are identical at all three boundaries.

- [ ] **Step 2: Run a security review**

Search changed code/tests/docs for `worker_id`, `deployment_id`, `lease_epoch`, `s3://`, `cloudwatch://`, access-key/token patterns, `reasoning`, raw `output`, tool arguments, and provider errors. Expected: internal Agent storage may contain fenced identifiers; Message Server/Flutter public payloads contain none.

- [ ] **Step 3: Run a behavior review**

Prove routine progress is query-only, final completion remains once-only, cancellation does not claim cleanup before verified destruction, and App polling stops when hidden/inactive.

- [ ] **Step 4: Fix review findings with focused tests**

Each behavioral fix receives a failing test in the owning repository, a focused commit, and rerun of that repository's accumulated checks.

### Task 5: Release To Demo2 Without Rebuilding The Worker AMI

**Files:** Release receipts and existing deployment configuration; no Worker image/rootfs input changes.

- [ ] **Step 1: Classify release impact**

Run `git diff --name-only <demo2-agent-revision>...HEAD` in Agent. Expected: Central Agent/API/database changes only; Worker runner/runtime/rootfs/AMI inputs are unchanged. Use the Agent-only image path in `docs/agent-image-release.md` and do not create a release builder EC2 unless local direct build is unavailable.

- [ ] **Step 2: Publish immutable Agent and Message Server images**

Use tags bound to each committed Git revision, read back ECR digest/tag immutability, and retain safe receipts. Do not use `latest` or mutable tags.

- [ ] **Step 3: Apply migration 64 and deploy exact digests**

Back up the Agent database, apply all pending migrations through normal Agent startup, update demo2 Agent and Message Server to exact `tag@sha256:digest`, and verify health, revision labels, image digests, restart counts, and pairwise scopes. The existing Message Server credential keeps `team.plan.read`; no new scope is granted.

- [ ] **Step 4: Update the simulator without uninstalling**

Build/install the Flutter branch over the existing simulator app, retain login/chat history, open Agent settings, and verify the “Runs and Tasks” entry and empty/history states.

### Task 6: Run One Correlated Real Acceptance

**Files:** No source edits unless a failing regression is first reproduced and tested.

- [ ] **Step 1: Submit a new unrelated heavy task from the App**

Use one approved Pi Worker and the existing concurrency/budget policy. Record conversation, Task, Plan, Execution, role, deployment, Worker, image, and AWS tag correlation privately; do not expose internal IDs in App payloads.

- [ ] **Step 2: Continue the conversation during execution**

Send a second unrelated message while the task runs. Expected: Chat remains usable and receives no Worker startup/input/runtime/cleanup progress messages.

- [ ] **Step 3: Verify the runs UI live stages**

Open the runs page and observe `starting_worker`, `preparing_input`, `running`, `validating_result`, `cleaning_up`, and terminal state as applicable. Close the page for part of execution, reopen it, and verify Central progressed without App polling.

- [ ] **Step 4: Verify backend monitoring and audit correlation**

Read Central PostgreSQL milestones/Outbox, Team dispatch, Worker heartbeat/lease, report, and cleanup facts. Independently read CloudWatch and verify matching stable event IDs. Product reads must still succeed if CloudWatch read access is unavailable.

- [ ] **Step 5: Verify final result and zero-resource cleanup**

Expected: final completion arrives once in the original conversation; report/artifact digests validate; Central marks cleanup verified; independent task-tagged AWS reads return zero EC2 instances, EBS volumes, ENIs, EIPs, and security groups.

- [ ] **Step 6: Record final evidence and push closeout commits**

Update the Agent delivery tracker and owning Message Server/Flutter contract docs with exact observed versions, tests, task correlation, CloudWatch/PostgreSQL evidence, and zero-resource read-back. Commit and push only after the evidence is complete.
