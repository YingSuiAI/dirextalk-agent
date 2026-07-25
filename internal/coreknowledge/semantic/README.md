# Core Knowledge semantic backend

`QdrantStore` uses Qdrant's versioned REST contract (`/collections/...` and
`/points/...`) through a narrow typed client rather than importing a generated
Qdrant SDK. This keeps the Agent binary's dependency surface small while the
constructor pins the endpoint, collection, and vector dimension. The request
shapes mirror Qdrant's documented collection, upsert, delete, and search
operations; response decoding is bounded and validates the fields consumed by
Core Knowledge.

`MemoryStore` is the deterministic fake used by local acceptance tests. Both
stores enforce the same source/revision allow-list and point-ID derivation.
