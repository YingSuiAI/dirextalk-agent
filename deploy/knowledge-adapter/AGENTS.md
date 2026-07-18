# Dirextalk Knowledge Adapter

This Agent release subtree owns the sealed, single-host Knowledge runtime adapter and its
fixed installer. It does not own Agent task orchestration, ProductCore/Matrix
semantics, cloud provisioning, or user-interface policy.

## Security contract

- Keep the adapter on its fixed Unix socket and Qdrant on verified TLS at
  `127.0.0.1:6333`. Do not add a listening adapter TCP port, caller-selected
  endpoint, URL, path, model, backend, header, or command.
- Keep Python production startup isolated with `python3.12 -I -S -B`, a sealed
  dependency directory, and CPUExecutionProvider only.
- Treat document text, queries, vectors, the Qdrant API key, and persisted
  databases as secrets. Never log, commit, or place them in test snapshots.
- Installer entrypoints and filesystem locations are fixed. External programs
  may be invoked only through the reviewed fixed runner; never invoke a shell.
- Archive extraction must reject absolute paths, traversal, links, devices,
  duplicate entries, oversized content, and unexpected model/Qdrant members.

## Development

Protect protocol authorization/idempotency, persistence, archive extraction,
and fixed service rendering with boundary tests. Use fake embedding/Qdrant and
temporary roots in the fast suite. The release-golden lane is the only test
that loads the real pinned model; it must never download it.

Before committing, run:

```text
make verify
git diff --check
```
