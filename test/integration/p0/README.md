# P0 PostgreSQL/gRPC integration tests

This opt-in lane exercises the first public persistence and authorization
boundary against a real PostgreSQL server. It covers:

- migration ownership fencing through the immutable `agent_instance_id`;
- TLS gRPC task create, idempotent replay, conflicting replay, read/list,
  stale-revision rejection, cancel, and cancel replay;
- durable event cursor resume through `WatchEvents(after_seq)`; and
- missing, unknown, under-scoped, correctly scoped, and revoked Service Keys.

The tests are skipped unless `AGENT_TEST_POSTGRES_DSN` is set. Point it at a
disposable database in the existing workspace PostgreSQL 18 service whose role may create and drop schemas and create the
objects defined by the repository migrations. Each test creates a uniquely
named `dtx_agent_p0_*` schema, sets it as that pool's `search_path`, and drops it
with `CASCADE` during cleanup. The DSN is never printed by the test helpers.
Do not start a separate Agent PostgreSQL container and do not point this lane at
the Message Server production database; create a sibling test database/role in
the same PostgreSQL 18 server/container.

PowerShell example:

```powershell
$env:AGENT_TEST_POSTGRES_DSN = 'postgres://agent_test:REDACTED@127.0.0.1:5432/agent_test?sslmode=disable'
go test ./test/integration/p0 -count=1
```

The gRPC server uses the production TLS and authorization wiring with an
ephemeral self-signed certificate generated in `t.TempDir()`. Test Service Key
material is synthetic and exists only for the lifetime of the isolated schema.
