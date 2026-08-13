# Dirextalk Agent release notes

## Unreleased

## v1.0.85

1. Resume durable turns without re-exposing intrinsic tools that were not accepted for the original model step.
2. Let substantial project, shell, deployment, test, isolated-workspace, and long-running tasks propose a priced Cloud Worker without requiring cloud-specific wording, while preserving owner confirmation before AWS execution.
3. Support an empty isolated writable Worker workspace for projects fetched from an authorized remote source; read-only workspaces still require exact current-turn inputs.

## v1.0.84

1. Return committed AWS credential updates without a cancellable post-commit read, so successful uploads do not report a false failure.
2. Enforce exactly one active AWS credential and reject concurrent or subsequent creates until the current credential is deleted.
3. Disable implicit CloudFormation mutation retries and let durable state plus explicit readback resolve uncertain provider responses.
4. Project model catalog entries from stable public fields before checking those fields for secret material.

## v1.0.83

1. Seed two network-free, read-only MCP installations that return live server UTC time and kernel load information through the isolated extension runner.

## v1.0.82

1. Bind the empty static-site list cursor as SQL NULL so the authenticated first page and subsequent cursor pages load correctly on PostgreSQL.

## v1.0.81

1. Return completed Cloud Worker results to the originating durable conversation with related tasks, plans, references, artifacts, and bounded deliverable context.
2. Add current static-site release listing and exact owner-scoped deletion through the Agent capability catalog.
3. Keep Cloud Worker execution explicit and remove the retired local-budget fallback path.

## v1.0.80

1. Dispatch Native Agent Product reads through the existing direct read-only path instead of extension preparation.
2. Persist user-visible assistant text deltas for live durable conversation progress without exposing provider reasoning.

## v1.0.79

1. Keep model profiles on the four current role-specific defaults and remove the superseded generic default field.
2. Remove retired capability aliases and stale Agent configuration fields.

## v1.0.78

1. Add exact update and delete operations for active structured memory facts.
2. Remove superseded Knowledge-memory CRUD, capability aliases, and legacy parameter fallbacks.
3. Keep the Agent capability catalog aligned with the current Message Server product actions.

## v1.0.74

1. Generate a concise first-turn conversation title with the configured tool model and fall back to the first user sentence.
2. Persist generated titles atomically for durable conversations without overwriting user-assigned titles.

## v1.0.73

1. Return absolute public URLs for generated static sites.
2. Prefix all bundled Skill identifiers with `dirextalk-`.

## v1.0.72

1. Allow long-running static-site publication to commit with the renewed current turn lease.

## v1.0.71

1. Establish the independent Agent Core runtime, durable conversations, Tasks, schedules, Knowledge and long-term memory.
2. Add pinned MCP and Skills lifecycle management, four default built-in Skills, and isolated three-slot local execution.
3. Add managed Node/npm MCP installation with exact versions, disabled lifecycle scripts, fixed quotas, and redacted public receipts.
4. Add durable Cloud Worker, AWS and Execution V2 boundaries without sharing Agent credentials or state with Message Server.
5. Add single-file static-site publication and progress-aware long-running Native Agent turns.
6. Add opt-in structured memory controls with durable fact and interaction records while retaining semantic retrieval.
7. Keep the image labels and all three binary versions aligned, and promote `latest` only after the matching GitHub Release succeeds.
