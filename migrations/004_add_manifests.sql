CREATE TABLE IF NOT EXISTS manifests (
    project_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    manifest_hash TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, revision),
    FOREIGN KEY (project_id) REFERENCES projects(project_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_manifests_project_id ON manifests(project_id);
