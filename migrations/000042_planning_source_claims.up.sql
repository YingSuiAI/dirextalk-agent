ALTER TABLE planning_official_source_evidence
    ADD COLUMN source_claim jsonb;

ALTER TABLE planning_official_source_evidence
    ADD CONSTRAINT planning_official_source_evidence_source_claim_object
    CHECK (source_claim IS NULL OR jsonb_typeof(source_claim) = 'object');
