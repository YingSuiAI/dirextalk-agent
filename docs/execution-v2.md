# Agent-owned execution.v2

`agent.execution.v2.*` is an Agent-owned capability surface. Message Server
keeps the public ProductCore action names and forwards them through the
neutral Capability API; it does not persist analyses, targets, plans, runs,
deployments, confirmations, artifacts, bindings, or execution secrets.

The Agent migration `000007_execution_v2.up.sql` creates the fresh
`core_execution_v2_*` tables. Records (including durable run stages) are owner-scoped, revisions are
compare-and-swap protected, and request UUIDs replay the exact response only
when their canonical request digest matches. Events are sequence-numbered and
can be resumed after a cursor. Unknown provider outcomes are returned through
the reconcile port instead of being retried implicitly.

The capability adapter exposes the exact 33 action tokens and the operation
IDs consumed by the Message Server gateway. Analysis, AWS target import/
reserve/observe, reconciliation, and service-binding invocation are typed
provider ports. A missing port fails closed with `execution_v2_not_ready`/
`execution_v2_missing_port`; the adapter never invents an AWS result.

Secret create/get/list/revoke stores the value only in Agent-owned storage.
The value is write-only from ordinary read/list responses; responses contain
the provider, purpose, revision, status, and binding digest only.

Plans are compiled from a code-reviewed recipe/intent allowlist. `plans.create`
and `plans.revise` persist non-empty typed `command_step_specs`, the exact
provider command set, `recipe_digest`, and `command_steps_digest`; callers
cannot submit shell text. `runs.create` persists one deterministic stage with
stable `stage_id`, `task_id`, `confirmation_id`, revision, digest, and binding.
After confirmation, the public `runs.reconcile` action is the deterministic
provider dispatch/recovery path; a replay or process restart reuses the same
stage and idempotency slot.

For an EC2 reservation, the Agent writes a separate owner-scoped
`dispatch_intent` record before the first CloudFormation change-set request.
The intent pins the run/stage/confirmation IDs and revisions, plan/target
revisions, operation, and request digest. Its existence is a one-way fence:
if the process dies before the run CAS or loses the AWS response, the next
reconcile only performs typed CloudFormation read-back/reconcile and never
creates a second stack.

Composition (kept separate from `core_serve.go`) is:

1. create `coreexecutionv2.NewPostgresStore(store.Pool())`;
2. adapt the existing Core Workload/AWS SSM/ECS services through
   `coreexecutionv2.ProviderInterfaces` (or `TypedPorts`) and require every
   route's explicit configuration proof. Startup performs no AWS API calls;
   the first explicit target/reservation/observe/reconcile action performs the
   exact configured readiness probe;
3. create `coreexecutionv2.NewServiceWithProviderInterfaces` with the typed
   adapters (a missing route keeps the whole 33-operation capability
   unpublished because the neutral descriptor has no per-operation readiness);
4. create `executionv2.NewCapability(service)` and register it on the neutral
   capability registry; and
5. optionally register `rpcapi.NewCoreExecutionV2Service` for a typed Core
   gRPC probe.

No Message Server database table or migration is required by this domain.

## AWS provisioning boundary

The fixed EC2 reservation template uses a configured, non-wildcard
`core_aws_cloudformation_service_role_arn`. CloudFormation receives that ARN in
the typed change-set request; missing, malformed, cross-account, or unconfigured
roles fail closed, and the caller credential is never used as a fallback
service role. The role should be a dedicated least-privilege CloudFormation
execution role. The caller needs only the CloudFormation change-set/read/delete
calls plus `iam:PassRole` on this exact ARN; the service role owns the fixed
VPC/subnet/route/egress-SG/EC2/IAM-profile resource actions.

Every supported taggable resource and the stack carries
`dirextalk-managed=execution-v2`, the deterministic stack name, and the
reservation target UUID. Read-back returns the CloudFormation stack ID,
instance ID, and logical-to-physical resource identifiers. Cleanup must use the
exact stack name/ID and reservation tag, then independently audit the fixed
resource logical IDs and any orphaned `dirextalk-exec-*` stack.
