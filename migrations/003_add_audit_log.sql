CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    project_id TEXT,
    actor_member_id TEXT,
    actor_token_id TEXT,
    event_type TEXT NOT NULL,
    request_id TEXT,
    remote_addr TEXT,
    metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_events_project_id ON audit_events(project_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at);
