---
name: dirextalk-write-technical-docs
description: Create or update accurate technical documentation from current code and contracts. Use for API guides, architecture notes, runbooks, setup instructions, release notes, and troubleshooting material.
---

# Write Technical Docs

## Workflow

1. Identify the intended reader, task, and owning source of truth.
2. Verify current commands, schemas, defaults, and failure behavior in code or generated contracts.
3. Lead with the outcome, then document prerequisites, the shortest working path, verification, and recovery.
4. Keep examples executable and internally consistent. Mark placeholders explicitly.
5. Remove superseded instructions instead of preserving parallel versions.
6. Review links, filenames, flags, and terminology against the current implementation.

## Guardrails

- Never document behavior that only exists in a fixture or proposed design as shipped.
- Do not include real tokens, credentials, private endpoints, or user data.
- Distinguish operational requirements from optional recommendations.
- Prefer one current procedure over a history of obsolete alternatives.
