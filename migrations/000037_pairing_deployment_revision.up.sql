ALTER TABLE pairing_sessions
    ADD COLUMN deployment_revision bigint NOT NULL DEFAULT 1 CHECK (deployment_revision > 0);
