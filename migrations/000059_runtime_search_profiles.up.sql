ALTER TABLE runtime_configs
    ADD COLUMN search_profile_id text,
    ADD COLUMN search_provider text,
    ADD COLUMN search_base_url text,
    ADD COLUMN search_secret_ref text,
    ADD COLUMN search_max_results integer,
    ADD COLUMN search_timeout_seconds integer,
    ADD CONSTRAINT runtime_configs_search_profile_complete CHECK (
        (
            search_profile_id IS NULL AND
            search_provider IS NULL AND
            search_base_url IS NULL AND
            search_secret_ref IS NULL AND
            search_max_results IS NULL AND
            search_timeout_seconds IS NULL
        ) OR (
            search_profile_id IS NOT NULL AND
            search_provider IS NOT NULL AND
            search_base_url IS NOT NULL AND
            search_secret_ref IS NOT NULL AND
            search_max_results IS NOT NULL AND
            search_timeout_seconds IS NOT NULL AND
            length(search_profile_id) BETWEEN 1 AND 128 AND
            length(search_provider) BETWEEN 1 AND 64 AND
            length(search_base_url) BETWEEN 1 AND 2048 AND
            length(search_secret_ref) BETWEEN 1 AND 512 AND
            search_max_results BETWEEN 1 AND 50 AND
            search_timeout_seconds BETWEEN 1 AND 60
        )
    );
