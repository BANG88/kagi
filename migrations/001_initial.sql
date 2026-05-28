-- schema_migrations is managed by sqlx

CREATE TABLE IF NOT EXISTS server_keys (
    server_key_id TEXT PRIMARY KEY,
    public_recipient TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    active INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id TEXT PRIMARY KEY,
    revision INTEGER NOT NULL DEFAULT 0,
    kagi_json TEXT,
    access_json TEXT,
    state_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_tokens (
    project_id TEXT NOT NULL,
    token_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    member_id TEXT,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT,
    PRIMARY KEY (project_id, token_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS project_files (
    project_id TEXT NOT NULL,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, path),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS join_requests (
    project_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    request_token_id TEXT NOT NULL,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, member_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS join_requests_pending_name_unique
    ON join_requests(project_id, normalized_name)
    WHERE status = 'pending';
