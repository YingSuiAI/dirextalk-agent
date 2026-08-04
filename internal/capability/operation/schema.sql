-- Agent operations 表
CREATE TABLE IF NOT EXISTS operations (
    id TEXT PRIMARY KEY,
    capability_id TEXT NOT NULL,
    operation_name TEXT NOT NULL,
    state TEXT NOT NULL,
    request_json BLOB NOT NULL,
    request_digest BLOB NOT NULL,
    result_json BLOB,
    error_code TEXT,
    error_message TEXT,
    expected_revision INTEGER DEFAULT 0,
    actual_revision INTEGER DEFAULT 0,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    owner_id TEXT NOT NULL,
    account_generation INTEGER NOT NULL,

    INDEX idx_state (state),
    INDEX idx_owner (owner_id),
    INDEX idx_created (created_at DESC)
);

-- Operation events 表
CREATE TABLE IF NOT EXISTS operation_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    event_json BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,

    FOREIGN KEY (operation_id) REFERENCES operations(id),
    INDEX idx_operation_sequence (operation_id, id)
);

-- Operation tombstones 表（压缩后的记录）
CREATE TABLE IF NOT EXISTS operation_tombstones (
    operation_id TEXT PRIMARY KEY,
    request_digest BLOB NOT NULL,
    terminal_state TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,

    INDEX idx_expires (expires_at)
);
