# Core Knowledge semantic backend

The production `KnowledgeVectorStore` lives in `internal/store/postgres` and
uses the pgvector extension through its official pgx adapter. Vectors share the
same Agent-owned PostgreSQL backup, deprovision and authorization boundary as
Knowledge metadata. Staged generations are promoted atomically, and searches
always apply the exact source/revision/generation allow-list supplied by Core
Knowledge.

`MemoryStore` is the deterministic fake used by local tests. Both stores
enforce the same source/revision allow-list and point-ID derivation.
