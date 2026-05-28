CREATE TABLE IF NOT EXISTS admin_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    capabilities_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS project_requests (
    project_id TEXT PRIMARY KEY,
    requester_member_id TEXT NOT NULL,
    requester_name TEXT NOT NULL,
    requester_recipient TEXT NOT NULL,
    claim_secret_hash TEXT NOT NULL,
    kagi_json TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_project_requests_status ON project_requests(status);

CREATE TABLE IF NOT EXISTS project_members (
    project_id TEXT NOT NULL,
    member_id TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    status TEXT NOT NULL,
    recipient TEXT,
    wrapped_project_token TEXT,
    claim_secret_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (project_id, member_id),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);
