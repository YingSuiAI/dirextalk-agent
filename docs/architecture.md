# Architecture

`dirextalk-agent` is a reusable, single-tenant service. Its Agent-owned PostgreSQL database is the durable source of truth. In Dirextalk it reuses the existing PostgreSQL 18 server/container but has a separate database, role, migration ledger, and backup/restore boundary from Message Server. Other projects may point it at their own PostgreSQL 18 service. The public boundary is TLS gRPC; caller services authenticate with pairwise service keys, while high-risk cloud transitions require a separately verified device approval.

The control process contains the Eino runtime, task scheduler, typed AWS provider, reconciliation loops, and gRPC services. It runs non-root and cannot execute user shell commands. Privileged installation is delegated to an exclusive Cloud Worker VM with a deployment-scoped identity.

The first release does not integrate Connect or vNext Run. Matrix, ProductCore, Flutter navigation, and Dirextalk-specific user identity remain integration concerns outside this repository.

## P0 durable boundary

The TLS gRPC interceptor authenticates a pairwise credential and replaces raw authorization metadata with a typed caller principal. Mutation handlers derive their idempotency namespace from that principal; owner IDs remain protocol-neutral project data rather than authentication material.

PostgreSQL owns immutable instance metadata, migration checksums, credentials, tasks, steps, dependencies, attempts, leases, idempotency snapshots, events, and Outbox rows. Entity mutation, response snapshot, event, and Outbox payload commit in one transaction. Events are projections of facts, not an in-memory ordering source. Restart recovery reconstructs services from PostgreSQL and resumes from the caller's durable event cursor without repurchasing or duplicating work.

Task cancellation and failed-step termination fence every nonterminal Step/Attempt before returning. A Worker with root inside its exclusive VM can therefore neither extend an old lease nor submit a late checkpoint/result after cancellation. The P0 Worker RPC remains unavailable; this kernel is the persistence boundary that P2 enrollment and execution will use.

Server shutdown first reports `NOT_SERVING`, waits for active streams within a bounded grace period, then force-stops them when the deadline expires. Database DSNs and private key material enter only through protected mounted files. Generated caller credentials leave only in an X25519 recipient envelope; plaintext credential material is neither logged nor stored.
