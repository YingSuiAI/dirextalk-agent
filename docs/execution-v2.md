# Agent-owned execution.v2

`agent.execution.v2.*` is an Agent-owned capability surface. Message Server
keeps the public ProductCore action names and forwards them through the neutral
Capability API; it does not persist analyses, targets, plans, runs,
deployments, confirmations, artifacts, bindings, or execution secrets.

## Durable contract

The migration bundle (`migrations/agent_migrations.sql`) creates the fresh
`core_execution_v2_*` tables. Records and run stages are owner-scoped and
revision/CAS protected. Request UUIDs replay the exact response only when the
canonical request digest matches; events are sequence-numbered and resumable.
Unknown provider outcomes go through reconcile rather than implicit retry.

The adapter exposes the exact 33 operation IDs consumed by the Message Server
gateway. Analysis, AWS target import/reserve/observe, reconciliation, and
service-binding invocation are typed provider ports. A missing port fails
closed with `execution_v2_not_ready`/`execution_v2_missing_port`; the adapter
never invents an AWS result.

Secret create/get/list/revoke stores secret bytes only in Agent-owned storage.
Ordinary responses contain provider, purpose, revision, status, and binding
digest, never the value.

Plans compile from a code-reviewed typed recipe/intent allowlist. The current
recipe is `generic-container-service` with `intent=deploy` and
`purpose=service`; callers cannot submit shell text. `plans.create` and
`plans.revise` persist non-empty typed command steps, provider command set,
recipe digest, and command-step digest. `runs.create` persists one deterministic
stage with stable stage/task/confirmation IDs, revision, digest, and binding.
After confirmation, `runs.reconcile` is the deterministic provider
dispatch/recovery path and reuses the same stage on replay or restart.

For an EC2 reservation, an owner-scoped `dispatch_intent` is written before
the first CloudFormation change-set request. It pins run/stage/confirmation,
plan/target revisions, operation, and request digest. Its one-way fence makes a
subsequent reconcile read back the existing stack instead of creating a
second one after a crash or lost provider response.

## Composition and publication

Composition creates the Agent store, adapts every typed Workload/AWS route,
constructs the Execution V2 service, registers the neutral capability, and may
register the typed `CoreExecutionV2Service` for gRPC probes. Startup performs
no AWS calls; the first explicit target/reservation/observe/reconcile action
performs the configured exact-target readiness probe.

`core_execution_v2_enabled` is required but insufficient: all typed provider
routes, the exact durable credential/target proof, the dedicated
CloudFormation service role, and the neutral adapter must be present before
the 33 operation IDs publish. A schema-only descriptor or Product Capability
bridge never publishes a partial surface. See the [delivery tracker](delivery-tracker.md)
for implementation and verification status.

No Message Server database table or migration is required by this domain.

## AWS provisioning boundary

The EC2 reservation path uses a fixed typed CloudFormation template and a
configured, non-wildcard `core_aws_cloudformation_service_role_arn`. Missing,
malformed, cross-account, or unconfigured roles fail closed; the caller
credential is never a fallback service role. The caller needs only the exact
CloudFormation change-set/read/delete calls plus `iam:PassRole` for that ARN.

The stack and supported taggable resources carry
`dirextalk-managed=execution-v2`, a deterministic stack name, and the
reservation target UUID. Read-back returns stack, instance, and logical-to-
physical identifiers. Cleanup uses the exact stack name/ID and reservation tag,
then independently audits the fixed logical IDs and orphaned
`dirextalk-exec-*` stacks.
