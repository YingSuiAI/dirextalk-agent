-- Knowledge control facts are owner-scoped metadata. Attachment bytes live in
-- the typed BlobStager (the production implementation uses the Foundation's
-- encrypted/versioned object path); vectors and query text are never stored in
-- PostgreSQL.
CREATE TABLE knowledge_configs (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 255),
    binding_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    managed_service_id uuid NOT NULL,
    recipe_digest text NOT NULL CHECK (recipe_digest ~ '^sha256:[a-f0-9]{64}$'),
    embedding_profile_id text NOT NULL CHECK (length(embedding_profile_id) BETWEEN 1 AND 128),
    enabled boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id),
    UNIQUE (agent_instance_id, owner_id, deployment_id, managed_service_id)
);

CREATE INDEX knowledge_configs_owner_idx
    ON knowledge_configs (agent_instance_id, owner_id, updated_at DESC, binding_id);

CREATE TABLE knowledge_sources (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('attachment','memory')),
    status text NOT NULL CHECK (status IN ('uploading','ready','deleting','deleted','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    title text NOT NULL CHECK (length(title) BETWEEN 1 AND 255),
    size_bytes bigint NOT NULL CHECK (size_bytes BETWEEN 1 AND 67108864),
    content_sha256 text NOT NULL DEFAULT '' CHECK (content_sha256 = '' OR content_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    backend_point_id uuid,
    indexed_segment_count integer NOT NULL DEFAULT 0 CHECK (indexed_segment_count BETWEEN 0 AND 32769),
    error_code text NOT NULL DEFAULT '' CHECK (error_code IN ('','ingest_failed','backend_unavailable','invalid_content')),
    chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count >= 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id)
        REFERENCES knowledge_configs(agent_instance_id, owner_id, binding_id)
        ON DELETE RESTRICT,
    CHECK ((status = 'ready' AND content_sha256 <> '' AND backend_point_id IS NOT NULL AND indexed_segment_count > 0) OR status <> 'ready')
);

CREATE INDEX knowledge_sources_list_idx
    ON knowledge_sources (agent_instance_id, owner_id, binding_id, source_id)
    WHERE status <> 'deleted';

CREATE TABLE knowledge_uploads (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    source_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('receiving','committed','failed')),
    media_type text NOT NULL CHECK (length(media_type) BETWEEN 1 AND 128),
    declared_size_bytes bigint NOT NULL CHECK (declared_size_bytes BETWEEN 1 AND 67108864),
    received_size_bytes bigint NOT NULL DEFAULT 0 CHECK (received_size_bytes >= 0 AND received_size_bytes <= declared_size_bytes),
    next_chunk_ordinal integer NOT NULL DEFAULT 0 CHECK (next_chunk_ordinal >= 0),
    binding_revision bigint NOT NULL CHECK (binding_revision > 0),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, upload_id),
    UNIQUE (agent_instance_id, owner_id, binding_id, source_id),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id, source_id)
        REFERENCES knowledge_sources(agent_instance_id, owner_id, binding_id, source_id)
        ON DELETE RESTRICT,
    CHECK (status <> 'committed' OR received_size_bytes = declared_size_bytes)
);

CREATE TABLE knowledge_upload_chunks (
    agent_instance_id uuid NOT NULL,
    owner_id text NOT NULL,
    binding_id uuid NOT NULL,
    upload_id uuid NOT NULL,
    chunk_ordinal integer NOT NULL CHECK (chunk_ordinal >= 0),
    offset_bytes bigint NOT NULL CHECK (offset_bytes >= 0),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 262144),
    chunk_sha256 text NOT NULL CHECK (chunk_sha256 ~ '^sha256:[a-f0-9]{64}$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (agent_instance_id, owner_id, binding_id, upload_id, chunk_ordinal),
    UNIQUE (agent_instance_id, owner_id, binding_id, upload_id, offset_bytes),
    FOREIGN KEY (agent_instance_id, owner_id, binding_id, upload_id)
        REFERENCES knowledge_uploads(agent_instance_id, owner_id, binding_id, upload_id)
        ON DELETE RESTRICT
);
