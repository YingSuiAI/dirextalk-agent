# Dirextalk Agent release notes

## Unreleased

## v1.0.76

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
