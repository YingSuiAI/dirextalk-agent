CREATE TABLE worker_release_catalog (
    publication_digest text PRIMARY KEY CHECK (publication_digest ~ '^sha256:[0-9a-f]{64}$'),
    agent_instance_id uuid NOT NULL REFERENCES agent_instance_metadata(agent_instance_id),
    account_id text NOT NULL CHECK (account_id ~ '^[0-9]{12}$'),
    region text NOT NULL CHECK (region ~ '^[a-z]{2}(-gov)?-[a-z]+-[0-9]+$'),
    architecture text NOT NULL CHECK (architecture IN ('amd64', 'arm64')),
    image_id text NOT NULL CHECK (image_id ~ '^ami-[0-9a-f]{8,17}$'),
    image_digest text NOT NULL CHECK (image_digest ~ '^sha256:[0-9a-f]{64}$'),
    root_snapshot_id text NOT NULL CHECK (root_snapshot_id ~ '^snap-[0-9a-f]{8,17}$'),
    release_manifest_digest text NOT NULL CHECK (release_manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_rootfs_digest text NOT NULL CHECK (worker_rootfs_digest ~ '^sha256:[0-9a-f]{64}$'),
    worker_binary_digest text NOT NULL CHECK (worker_binary_digest ~ '^sha256:[0-9a-f]{64}$'),
    publication_json jsonb NOT NULL,
    observed_at timestamptz NOT NULL,
    active boolean NOT NULL DEFAULT true,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE UNIQUE INDEX worker_release_catalog_active_scope_idx
    ON worker_release_catalog (agent_instance_id, account_id, region, architecture)
    WHERE active;

CREATE INDEX worker_release_catalog_image_idx
    ON worker_release_catalog (account_id, region, image_id);
