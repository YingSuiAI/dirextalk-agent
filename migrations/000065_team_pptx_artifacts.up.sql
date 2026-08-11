-- Permit a verified, macro-free PPTX retained by the Worker artifact scanner.
-- final.json remains the only result contract; PPTX is an additional file.
ALTER TABLE team_artifacts
    DROP CONSTRAINT team_artifacts_media_type_check;

ALTER TABLE team_artifacts
    ADD CONSTRAINT team_artifacts_media_type_check CHECK (
        media_type IN (
            'application/json',
            'text/plain; charset=utf-8',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        )
    );
