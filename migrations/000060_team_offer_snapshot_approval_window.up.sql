ALTER TABLE team_offer_snapshots
    DROP CONSTRAINT team_offer_snapshots_check;

ALTER TABLE team_offer_snapshots
    ADD CONSTRAINT team_offer_snapshots_validity_window_check
    CHECK (
        valid_until > captured_at
        AND valid_until <= captured_at + interval '24 hours'
    );
