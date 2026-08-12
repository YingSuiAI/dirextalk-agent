---
name: dirextalk-review-code
description: Review code changes for correctness, security, reliability, maintainability, and missing tests. Use for diffs, pull requests, patches, migrations, APIs, and deployment scripts.
---

# Review Code

## Workflow

1. Establish the requested behavior, trust boundaries, and affected callers before judging the diff.
2. Trace changed data and control flow through persistence, retries, cancellation, and recovery.
3. Look for concrete defects: incorrect state transitions, authorization gaps, data loss, races, unsafe defaults, contract drift, and resource leaks.
4. Check whether tests exercise the real failing boundary and meaningful negative cases.
5. Report findings by severity with a precise location, impact, and smallest coherent fix.
6. If no actionable defect is found, say so and list only material residual risks or test gaps.

## Guardrails

- Prioritize correctness findings over style preferences.
- Do not claim a path is safe without following its callers and persisted state.
- Do not expose secrets or private data from fixtures, logs, or configuration.
- Avoid proposing compatibility shims when the current contract intentionally replaces an old design.
