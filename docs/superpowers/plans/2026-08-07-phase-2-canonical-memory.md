# Phase 2: Automatic Canonical Memory Implementation Plan

## Goal

Move the Product Agent's useful automatic-memory behavior into Agent Core
without importing its file-backed authority or allowing model output to mutate
memory directly.

## Status at 2026-08-07

- Slice 2A complete: strict candidate schema, deterministic policy, and
  reconciler.
- Slice 2B complete: canonical PostgreSQL slots, immutable revisions,
  tombstones, provenance, and idempotent revision fencing.
- Slice 2C complete: atomic turn/task creation, pinned tool-free extraction,
  cross-attempt completion replay, secret-free receipts, canonical writes,
  Knowledge auto-index requests, and an opt-in composition gate.
- Slice 2D remains: canonical-only recall and owner correction/deletion APIs.

## Slice 2A: Domain policy and reconciler

- Add a versioned extraction envelope and strict bounded parser.
- Treat every model candidate as untrusted input.
- Validate operation, canonical key, scope, type, sensitivity, confidence,
  importance, and exact evidence.
- Reject credential-like secrets, unsupported sensitive candidates, transient
  locations, malformed keys/scopes, low-value candidates, and model `noop`.
- Derive `create`, `update`, `delete`, or `noop` from canonical state rather
  than trusting the model's requested operation.
- Add focused parser, privacy, grounding, deduplication, update, delete, and
  correction tests.

## Slice 2B: Durable canonical state

- Add additive PostgreSQL tables for canonical slots, immutable revisions,
  reconcile attempts, and source-turn provenance.
- Keep `(scope, canonical_key)` unique for active canonical identity.
- Require idempotency and expected revision for mutation.
- Preserve deleted slots as tombstones and never revive them accidentally.
- Expose list/get/correct/delete through the existing Knowledge/Memory owner
  surface rather than a parallel public authority.

## Slice 2C: Background extraction and indexing

- Add a durable `memory_reconcile` Core task referencing a completed turn.
- Resolve the accepted turn and model profile from Agent-owned state.
- Ask the model for the versioned candidate schema without tools.
- Run deterministic policy and reconciliation after model extraction.
- Submit only accepted current revisions to the existing Knowledge indexer.
- Make extraction/index failure non-blocking for the already completed chat,
  while retaining a retryable task and stable terminal classification.

## Slice 2D: Recall and user control

- Recall only active promoted canonical revisions.
- Inject bounded recalled memory as untrusted transient context.
- Ensure recall never becomes a durable conversation message.
- Add correction/deletion acceptance tests and retry/restart duplicate tests.

## Verification

- Focused domain tests on every candidate decision.
- PostgreSQL 18 migration and reconciliation integration tests.
- Existing Knowledge auto-index and semantic search tests.
- Conversation test proving recalled memory remains transient.
- Linux build/CI evidence for the background task handler.

Image generation remains outside this phase and branch.
