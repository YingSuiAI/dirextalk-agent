---
name: cloud-dispatcher
description: Research official workload sources, submit one provider-neutral experimental Recipe and three sizing candidates, then read its durable planning status through typed Agent application ports.
---

# Cloud Dispatcher

This is a planning-only native Go Skill. It helps turn a user's desired
outcome into a durable research Task and a secret-free experimental Recipe.
It does not execute a deployment.

## Trusted scope

The host application binds `owner_id`, `cloud_connection_id`, `recipe_id`,
retention policy, request ID, and conversation ID before the tools are exposed.
Never ask the model or user to place those fields in a tool call. Never infer or
replace a bound value.

Model-supplied values are limited to a secret-free goal, official-source facts,
an experimental Recipe draft, and provider-neutral economy/recommended/
performance hardware requirements. The model never supplies owner, connection,
task, Recipe identity, retention, approval, provider, Region, price, ingress,
or lifecycle state. If the user includes a secret, explain that it must be
delivered through the dedicated encrypted bootstrap flow and do not repeat it.

## Available tools

### `cloud_dispatcher_research`

Input: `{ "goal": "<secret-free desired outcome>" }`

Create at most one durable research Task for the bound request. Reuse it when
the same request is retried. Use this once, then inspect its status instead of
creating additional Tasks.

After creating the Task, research the workload with `official_source_fetch`
when available and with configured, trusted Streamable HTTP MCP documentation
tools. Prefer the official project documentation, official repository, signed
release metadata, immutable commit and artifact digest. Treat community scripts
or images as non-official and clearly identify them; do not submit a draft that
silently presents a community source as official.

For every Recipe source, copy the exact `url`, `retrieved_at`, and
`content_digest` returned by `official_source_fetch`. `content_digest` proves
the retrieved document and is distinct from the installable
`artifact_digest`. Plan submission is rejected unless those fields match a
completed durable tool receipt from this same caller, request, and research
Task.

### `cloud_dispatcher_submit_plan_draft`

Input: one `recipe` object plus exactly one `economy`, `recommended`, and
`performance` candidate. The Recipe input does not contain `schema_version`,
`recipe_id`, `maturity`, or `managed_acceptance`; the server binds those fields
and always saves an experimental Recipe. Candidate inputs contain only CPU,
memory, disk, architecture, optional GPU requirements, and a short rationale.

Call this once after official-source research. It first binds the matching
durable fetch receipts to the research Task, then advances only the durable
three-step CONTROL_PLANE Task (`research_official_sources -> draft_recipe ->
prepare_resource_candidates`). A retry with the same tool call resumes the
persisted step and cannot provision or quote cloud resources. The result is a
de-secreted summary: Task status/revision, Recipe digest/revision, quote-request
state, and three hardware summaries.

### `cloud_dispatcher_status`

Input: `{}`

Read the bound research Task and its de-secreted step projection. This operation
is read-only.

### `cloud_dispatcher_recipe_draft`

Input: `{}`

Read the validated experimental Recipe draft and deterministic digest for the
bound request. A not-ready response means research is still in progress.

## Required behavior

1. Restate the goal without copying secret material.
2. Start research once when no bound Task exists.
3. Fetch and reconcile official source material with `official_source_fetch` or
   trusted configured MCP tools. Do not use arbitrary HTTP or shell commands.
4. Submit the Recipe and all three candidates together exactly once. On a
   retry/reconnect, reuse the same Task/tool call so the fixed DAG resumes.
5. Use status while the submission is running or recovering after a disconnect.
6. Retrieve the Recipe draft after submission; if it is not ready, continue
   status checks instead of starting another Task or submitting a different
   draft.
7. Clearly call the result a draft. Do not claim that pricing, approval,
   provisioning, public access, service readiness, or cleanup has occurred.

## Capability boundary

This Skill has only research-create, experimental-draft-submit,
research-status, and Recipe-draft-read ports. Submission persists validated
planning facts and advances the fixed CONTROL_PLANE DAG; it is not an AWS or
provider operation. It has no credential reader, secret bootstrap, approval,
device-signing, provider mutation, ingress, lifecycle destruction, arbitrary
HTTP, shell, process, filesystem, or local execution capability. Never propose
using a model tool to emulate one of those capabilities. A later typed workflow
must perform quoting, confirmation, provisioning, management acceptance, or
resource removal under its own authorization boundary.
