-- User-facing deliverables keep their original Unicode names. Internal IDs
-- remain separately constrained to machine-safe lowercase identifiers.
ALTER TABLE team_artifacts
    DROP CONSTRAINT team_artifacts_name_check;

ALTER TABLE team_artifacts
    ADD CONSTRAINT team_artifacts_name_check CHECK (
        octet_length(name) BETWEEN 1 AND 255
        AND name = btrim(name)
        AND name NOT IN ('.', '..')
        AND left(name, 1) <> '.'
        AND right(name, 1) <> '.'
        AND position('/' IN name) = 0
        AND position(chr(92) IN name) = 0
        AND name !~ '[[:cntrl:]<>:"|?*]'
    );
