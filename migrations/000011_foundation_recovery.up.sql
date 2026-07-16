ALTER TABLE aws_foundation_operations
    ADD COLUMN expected_session_revision bigint;

-- Every Foundation intent is written only after the corresponding identity
-- preview has been persisted. Recover the exact uploaded-session revision for
-- databases that already applied 000008; never guess a revision.
UPDATE aws_foundation_operations AS operation
SET expected_session_revision = preview.session_revision
FROM aws_identity_previews AS preview
WHERE preview.bootstrap_session_id = operation.bootstrap_session_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM aws_foundation_operations
        WHERE expected_session_revision IS NULL
    ) THEN
        RAISE EXCEPTION 'cannot safely bind an existing Foundation operation to its bootstrap session revision';
    END IF;
END $$;

ALTER TABLE aws_foundation_operations
    ALTER COLUMN expected_session_revision SET NOT NULL,
    ADD CONSTRAINT aws_foundation_operations_session_revision_positive
        CHECK (expected_session_revision > 0);
