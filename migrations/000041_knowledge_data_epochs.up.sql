ALTER TABLE knowledge_configs
    ADD COLUMN data_epoch bigint NOT NULL DEFAULT 1 CHECK (data_epoch > 0),
    ADD COLUMN backend_generation_digest text
        CHECK (backend_generation_digest IS NULL OR
               backend_generation_digest ~ '^sha256:[a-f0-9]{64}$');

ALTER TABLE managed_knowledge_lifecycle_operations
    ADD COLUMN execution_data_epoch bigint CHECK (execution_data_epoch IS NULL OR execution_data_epoch > 0),
    ADD COLUMN execution_catalog_digest text
        CHECK (execution_catalog_digest IS NULL OR execution_catalog_digest ~ '^sha256:[a-f0-9]{64}$'),
    ADD COLUMN target_generation_digest text
        CHECK (target_generation_digest IS NULL OR target_generation_digest ~ '^sha256:[a-f0-9]{64}$'),
    ADD CONSTRAINT managed_knowledge_lifecycle_data_fence_check
        CHECK (
            (execution_fenced_at IS NULL AND execution_data_epoch IS NULL AND
             execution_catalog_digest IS NULL AND target_generation_digest IS NULL)
            OR
            (execution_fenced_at IS NOT NULL AND execution_data_epoch IS NOT NULL AND
             ((action IN ('backup','upgrade') AND execution_catalog_digest IS NOT NULL
               AND target_generation_digest IS NULL)
              OR
              (action IN ('restore','rollback') AND execution_catalog_digest IS NULL
               AND target_generation_digest IS NOT NULL)
              OR
              (action IN ('stop','destroy') AND execution_catalog_digest IS NULL
               AND target_generation_digest IS NULL)))
        );

CREATE TABLE knowledge_data_snapshot_sources (
    snapshot_operation_id uuid NOT NULL
        REFERENCES managed_knowledge_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('attachment','memory')),
    status text NOT NULL CHECK (status IN ('uploading','ready','deleting','deleted','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
    content_sha256 text NOT NULL
        CHECK (content_sha256 = '' OR content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    backend_point_id uuid,
    indexed_segment_count integer NOT NULL CHECK (indexed_segment_count BETWEEN 0 AND 32769),
    error_code text NOT NULL CHECK (error_code IN ('','ingest_failed','backend_unavailable','invalid_content')),
    chunk_count integer NOT NULL CHECK (chunk_count >= 0),
    source_revision bigint NOT NULL CHECK (source_revision > 0),
    source_created_at timestamptz NOT NULL,
    source_updated_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_snapshot_uploads (
    snapshot_operation_id uuid NOT NULL,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('receiving','committed','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    declared_size_bytes bigint NOT NULL CHECK (declared_size_bytes BETWEEN 1 AND 67108864),
    received_size_bytes bigint NOT NULL
        CHECK (received_size_bytes >= 0 AND received_size_bytes <= declared_size_bytes),
    next_chunk_ordinal integer NOT NULL CHECK (next_chunk_ordinal >= 0),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    upload_revision bigint NOT NULL CHECK (upload_revision > 0),
    upload_created_at timestamptz NOT NULL,
    upload_updated_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, upload_id),
    FOREIGN KEY (snapshot_operation_id, source_id)
        REFERENCES knowledge_data_snapshot_sources(snapshot_operation_id, source_id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_snapshot_chunks (
    snapshot_operation_id uuid NOT NULL,
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal >= 0),
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    chunk_created_at timestamptz NOT NULL,
    PRIMARY KEY (snapshot_operation_id, upload_id, chunk_ordinal),
    UNIQUE (snapshot_operation_id, upload_id, offset_bytes),
    FOREIGN KEY (snapshot_operation_id, upload_id)
        REFERENCES knowledge_data_snapshot_uploads(snapshot_operation_id, upload_id) ON DELETE RESTRICT,
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE TABLE knowledge_data_generations (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    backend_generation_digest text NOT NULL
        CHECK (backend_generation_digest ~ '^sha256:[a-f0-9]{64}$'),
    catalog_digest text NOT NULL CHECK (catalog_digest ~ '^sha256:[a-f0-9]{64}$'),
    data_epoch bigint NOT NULL CHECK (data_epoch > 0),
    snapshot_operation_id uuid NOT NULL UNIQUE
        REFERENCES managed_knowledge_lifecycle_operations(operation_id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, backend_generation_digest),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id) ON DELETE RESTRICT
);

CREATE INDEX knowledge_data_generations_latest_idx
    ON knowledge_data_generations
       (agent_instance_id, owner_id, binding_id, created_at DESC, snapshot_operation_id DESC);
