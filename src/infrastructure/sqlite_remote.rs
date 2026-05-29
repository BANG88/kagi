use crate::domain::sync::project_state::ProjectFile;
use sha2::Digest;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Row, Sqlite};
use std::path::Path;
use std::time::Duration;

pub struct SqliteRemoteRepository {
    pool: Pool<Sqlite>,
}

pub struct PushProjectStateRequest<'a> {
    pub project_id: &'a str,
    pub base_revision: i64,
    pub kagi_json: &'a str,
    pub access_json: &'a str,
    pub files: &'a [ProjectFile],
    pub activate_tokens: &'a [String],
    pub revoke_tokens: &'a [String],
    pub accepted_joins: &'a [String],
    pub manifest_json: Option<&'a str>,
    pub manifest_signature: Option<&'a str>,
}

pub struct CreateProjectMemberRequest<'a> {
    pub project_id: &'a str,
    pub member_id: &'a str,
    pub name: &'a str,
    pub role: &'a str,
    pub status: &'a str,
    pub recipient: &'a str,
    pub claim_secret_hash: &'a str,
}

pub struct ApproveProjectRequest<'a> {
    pub project_id: &'a str,
    pub requester_member_id: &'a str,
    pub requester_name: &'a str,
    pub requester_recipient: &'a str,
    pub claim_secret_hash: &'a str,
    pub token_id: &'a str,
    pub token_hash: &'a str,
    pub caps_json: &'a str,
    pub wrapped_b64: &'a str,
}

impl SqliteRemoteRepository {
    pub async fn new_file(path: impl AsRef<Path>) -> Result<Self, sqlx::Error> {
        let opts = SqliteConnectOptions::new()
            .filename(path.as_ref())
            .create_if_missing(true);
        Self::connect_with(opts).await
    }

    async fn connect_with(opts: SqliteConnectOptions) -> Result<Self, sqlx::Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;

        sqlx::query("PRAGMA foreign_keys = ON;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA journal_mode = WAL;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA synchronous = FULL;")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA busy_timeout = 5000;")
            .execute(&pool)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;

        Ok(Self { pool })
    }

    pub async fn create_project(&self, project_id: &str) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO projects (project_id, revision, created_at, updated_at) VALUES (?, 0, ?, ?)"
        )
        .bind(project_id)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn create_token(
        &self,
        project_id: &str,
        token_id: &str,
        token_hash: &str,
        capabilities_json: &str,
        member_id: Option<&str>,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO project_tokens (project_id, token_id, token_hash, capabilities_json, member_id, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(project_id)
        .bind(token_id)
        .bind(token_hash)
        .bind(capabilities_json)
        .bind(member_id)
        .bind(status)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn authenticate_token(
        &self,
        project_id: &str,
        token_hash: &str,
    ) -> Result<Option<(String, Vec<String>, Option<String>)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT token_id, capabilities_json, member_id FROM project_tokens
             WHERE project_id = ? AND token_hash = ? AND status = 'active'",
        )
        .bind(project_id)
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let token_id: String = r.try_get("token_id").unwrap_or_default();
            let caps_json: String = r.try_get("capabilities_json").unwrap_or_default();
            let member_id: Option<String> = r.try_get("member_id").ok();
            let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
            (token_id, caps, member_id)
        }))
    }

    pub async fn push_project_state(
        &self,
        request: PushProjectStateRequest<'_>,
    ) -> Result<i64, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        let current_row = sqlx::query("SELECT revision FROM projects WHERE project_id = ?")
            .bind(request.project_id)
            .fetch_optional(&mut *tx)
            .await?;
        let current_revision = current_row
            .map(|r| r.try_get::<i64, _>("revision").unwrap_or(0))
            .unwrap_or(0);
        if current_revision != request.base_revision {
            return Err(sqlx::Error::RowNotFound);
        }

        sqlx::query("DELETE FROM project_files WHERE project_id = ?")
            .bind(request.project_id)
            .execute(&mut *tx)
            .await?;

        let now = time::OffsetDateTime::now_utc().to_string();
        for file in request.files {
            sqlx::query(
                "INSERT INTO project_files (project_id, path, content, sha256, updated_at) VALUES (?, ?, ?, ?, ?)"
            )
            .bind(request.project_id)
            .bind(&file.path)
            .bind(&file.content)
            .bind(&file.sha256)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }

        let new_revision = request.base_revision + 1;
        sqlx::query(
            "UPDATE projects SET revision = ?, kagi_json = ?, access_json = ?, updated_at = ? WHERE project_id = ?"
        )
        .bind(new_revision)
        .bind(request.kagi_json)
        .bind(request.access_json)
        .bind(&now)
        .bind(request.project_id)
        .execute(&mut *tx)
        .await?;

        for token_id in request.activate_tokens {
            sqlx::query(
                "UPDATE project_tokens SET status = 'active', activated_at = ? WHERE project_id = ? AND token_id = ? AND status = 'pending_activation'"
            )
            .bind(&now)
            .bind(request.project_id)
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        }

        for token_id in request.revoke_tokens {
            sqlx::query(
                "UPDATE project_tokens SET status = 'revoked', revoked_at = ? WHERE project_id = ? AND token_id = ?"
            )
            .bind(&now)
            .bind(request.project_id)
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        }

        for member_id in request.accepted_joins {
            sqlx::query(
                "UPDATE join_requests SET status = 'accepted', updated_at = ? WHERE project_id = ? AND member_id = ?"
            )
            .bind(&now)
            .bind(request.project_id)
            .bind(member_id)
            .execute(&mut *tx)
            .await?;
        }

        if let Some(manifest_json) = request.manifest_json {
            let manifest_hash = {
                let mut hasher = sha2::Sha256::new();
                hasher.update(manifest_json.as_bytes());
                hex::encode(hasher.finalize())
            };
            sqlx::query(
                "INSERT INTO manifests (project_id, revision, manifest_hash, manifest_json, manifest_signature, created_at) VALUES (?, ?, ?, ?, ?, ?)"
            )
            .bind(request.project_id)
            .bind(new_revision)
            .bind(&manifest_hash)
            .bind(manifest_json)
            .bind(request.manifest_signature)
            .bind(&now)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(new_revision)
    }

    pub async fn pull_project_state(
        &self,
        project_id: &str,
    ) -> Result<Option<(i64, Vec<ProjectFile>)>, sqlx::Error> {
        let revision_row = sqlx::query("SELECT revision FROM projects WHERE project_id = ?")
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await?;
        let revision = match revision_row {
            Some(r) => r.try_get::<i64, _>("revision")?,
            None => return Ok(None),
        };

        let file_rows =
            sqlx::query("SELECT path, content, sha256 FROM project_files WHERE project_id = ?")
                .bind(project_id)
                .fetch_all(&self.pool)
                .await?;

        let project_files = file_rows
            .into_iter()
            .map(|r| ProjectFile {
                path: r.try_get("path").unwrap_or_default(),
                content: r.try_get("content").unwrap_or_default(),
                sha256: r.try_get("sha256").ok(),
            })
            .collect();

        Ok(Some((revision, project_files)))
    }

    pub async fn get_manifest(
        &self,
        project_id: &str,
        revision: i64,
    ) -> Result<Option<(String, String, Option<String>)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT manifest_hash, manifest_json, manifest_signature FROM manifests WHERE project_id = ? AND revision = ?",
        )
        .bind(project_id)
        .bind(revision)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            (
                r.try_get("manifest_hash").unwrap_or_default(),
                r.try_get("manifest_json").unwrap_or_default(),
                r.try_get("manifest_signature").ok(),
            )
        }))
    }

    pub async fn list_join_requests(
        &self,
        project_id: &str,
    ) -> Result<Vec<(String, String, String, String)>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT member_id, name, recipient, created_at FROM join_requests
             WHERE project_id = ? AND status = 'pending'",
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get("member_id").unwrap_or_default(),
                    r.try_get("name").unwrap_or_default(),
                    r.try_get("recipient").unwrap_or_default(),
                    r.try_get("created_at").unwrap_or_default(),
                )
            })
            .collect())
    }

    pub async fn upsert_join_request(
        &self,
        project_id: &str,
        member_id: &str,
        request_token_id: &str,
        name: &str,
        normalized_name: &str,
        recipient: &str,
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO join_requests (project_id, member_id, request_token_id, name, normalized_name, recipient, status, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
             ON CONFLICT(project_id, member_id) DO UPDATE SET
             request_token_id = excluded.request_token_id,
             name = excluded.name,
             normalized_name = excluded.normalized_name,
             recipient = excluded.recipient,
             updated_at = excluded.updated_at
             WHERE join_requests.request_token_id = excluded.request_token_id"
        )
        .bind(project_id)
        .bind(member_id)
        .bind(request_token_id)
        .bind(name)
        .bind(normalized_name)
        .bind(recipient)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn revoke_tokens(
        &self,
        project_id: &str,
        token_ids: &[String],
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        for token_id in token_ids {
            sqlx::query(
                "UPDATE project_tokens SET status = 'revoked', revoked_at = ? WHERE project_id = ? AND token_id = ?"
            )
            .bind(&now)
            .bind(project_id)
            .bind(token_id)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub async fn list_project_tokens(
        &self,
        project_id: &str,
    ) -> Result<
        Vec<(
            String,
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            Option<String>,
        )>,
        sqlx::Error,
    > {
        let rows = sqlx::query(
            "SELECT token_id, capabilities_json, member_id, status, created_at, activated_at, revoked_at FROM project_tokens WHERE project_id = ? ORDER BY created_at DESC"
        )
        .bind(project_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get("token_id").unwrap_or_default(),
                    r.try_get("capabilities_json").unwrap_or_default(),
                    r.try_get("member_id").ok(),
                    r.try_get("status").unwrap_or_default(),
                    r.try_get("created_at").unwrap_or_default(),
                    r.try_get("activated_at").ok(),
                    r.try_get("revoked_at").ok(),
                )
            })
            .collect())
    }

    pub async fn get_project_meta(
        &self,
        project_id: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>, sqlx::Error> {
        let row = sqlx::query("SELECT kagi_json, access_json FROM projects WHERE project_id = ?")
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await?;

        match row {
            Some(r) => {
                let k = r.try_get::<Option<String>, _>("kagi_json")?;
                let a = r.try_get::<Option<String>, _>("access_json")?;
                Ok(Some((k, a)))
            }
            None => Ok(None),
        }
    }

    pub async fn has_admin_token(&self) -> Result<bool, sqlx::Error> {
        let row = sqlx::query("SELECT COUNT(*) as cnt FROM admin_tokens WHERE status = 'active'")
            .fetch_one(&self.pool)
            .await?;
        let count: i64 = row.try_get("cnt").unwrap_or(0);
        Ok(count > 0)
    }

    pub async fn create_admin_token(
        &self,
        token_id: &str,
        token_hash: &str,
        capabilities_json: &str,
        created_at: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO admin_tokens (token_id, token_hash, capabilities_json, status, created_at) VALUES (?, ?, ?, 'active', ?)"
        )
        .bind(token_id)
        .bind(token_hash)
        .bind(capabilities_json)
        .bind(created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn authenticate_admin_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<(String, Vec<String>)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT token_id, capabilities_json FROM admin_tokens WHERE token_hash = ? AND status = 'active'"
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            let token_id: String = r.try_get("token_id").unwrap_or_default();
            let caps_json: String = r.try_get("capabilities_json").unwrap_or_default();
            let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
            (token_id, caps)
        }))
    }

    pub async fn create_project_request(
        &self,
        project_id: &str,
        requester_member_id: &str,
        requester_name: &str,
        requester_recipient: &str,
        claim_secret_hash: &str,
        kagi_json: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO project_requests (project_id, requester_member_id, requester_name, requester_recipient, claim_secret_hash, kagi_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)"
        )
        .bind(project_id)
        .bind(requester_member_id)
        .bind(requester_name)
        .bind(requester_recipient)
        .bind(claim_secret_hash)
        .bind(kagi_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_project_requests(
        &self,
    ) -> Result<
        Vec<(
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        sqlx::Error,
    > {
        let rows = sqlx::query(
            "SELECT project_id, requester_member_id, requester_name, requester_recipient, claim_secret_hash, kagi_json, status FROM project_requests WHERE status = 'pending'"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get("project_id").unwrap_or_default(),
                    r.try_get("requester_member_id").unwrap_or_default(),
                    r.try_get("requester_name").unwrap_or_default(),
                    r.try_get("requester_recipient").unwrap_or_default(),
                    r.try_get("claim_secret_hash").unwrap_or_default(),
                    r.try_get("kagi_json").ok(),
                    r.try_get("status").unwrap_or_default(),
                )
            })
            .collect())
    }

    pub async fn get_project_request(
        &self,
        project_id: &str,
    ) -> Result<
        Option<(
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
        )>,
        sqlx::Error,
    > {
        let row = sqlx::query(
            "SELECT project_id, requester_member_id, requester_name, requester_recipient, claim_secret_hash, kagi_json, status FROM project_requests WHERE project_id = ?"
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| {
            (
                r.try_get("project_id").unwrap_or_default(),
                r.try_get("requester_member_id").unwrap_or_default(),
                r.try_get("requester_name").unwrap_or_default(),
                r.try_get("requester_recipient").unwrap_or_default(),
                r.try_get("claim_secret_hash").unwrap_or_default(),
                r.try_get("kagi_json").ok(),
                r.try_get("status").unwrap_or_default(),
            )
        }))
    }

    #[allow(dead_code)]
    pub async fn delete_project_request(&self, project_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM project_requests WHERE project_id = ?")
            .bind(project_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn create_project_member(
        &self,
        req: CreateProjectMemberRequest<'_>,
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO project_members (project_id, member_id, name, role, status, recipient, claim_secret_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(req.project_id)
        .bind(req.member_id)
        .bind(req.name)
        .bind(req.role)
        .bind(req.status)
        .bind(req.recipient)
        .bind(req.claim_secret_hash)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_project_member(
        &self,
        project_id: &str,
        member_id: &str,
    ) -> Result<Option<(String, String, String, String, String)>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT name, role, status, recipient, claim_secret_hash FROM project_members WHERE project_id = ? AND member_id = ?"
        )
        .bind(project_id)
        .bind(member_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| {
            let name: String = r.try_get("name").unwrap_or_default();
            let role: String = r.try_get("role").unwrap_or_default();
            let status: String = r.try_get("status").unwrap_or_default();
            let recipient: String = r.try_get("recipient").unwrap_or_default();
            let claim_secret_hash: String = r.try_get("claim_secret_hash").unwrap_or_default();
            (name, role, status, recipient, claim_secret_hash)
        }))
    }

    #[allow(dead_code)]
    pub async fn save_wrapped_project_token(
        &self,
        project_id: &str,
        member_id: &str,
        wrapped: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE project_members SET wrapped_project_token = ? WHERE project_id = ? AND member_id = ?"
        )
        .bind(wrapped)
        .bind(project_id)
        .bind(member_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_wrapped_project_token(
        &self,
        project_id: &str,
        member_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query(
            "SELECT wrapped_project_token FROM project_members WHERE project_id = ? AND member_id = ?"
        )
        .bind(project_id)
        .bind(member_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|r| r.try_get("wrapped_project_token").ok()))
    }

    pub async fn get_project_member_role(
        &self,
        project_id: &str,
        member_id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let row =
            sqlx::query("SELECT role FROM project_members WHERE project_id = ? AND member_id = ?")
                .bind(project_id)
                .bind(member_id)
                .fetch_optional(&self.pool)
                .await?;

        Ok(row.map(|r| r.try_get("role").unwrap_or_default()))
    }

    pub async fn approve_project_request_tx(
        &self,
        req: ApproveProjectRequest<'_>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        let now = time::OffsetDateTime::now_utc().to_string();

        sqlx::query(
            "INSERT INTO projects (project_id, revision, created_at, updated_at) VALUES (?, 0, ?, ?)"
        )
        .bind(req.project_id)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO project_members (project_id, member_id, name, role, status, recipient, claim_secret_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(req.project_id)
        .bind(req.requester_member_id)
        .bind(req.requester_name)
        .bind("admin")
        .bind("active")
        .bind(req.requester_recipient)
        .bind(req.claim_secret_hash)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO project_tokens (project_id, token_id, token_hash, capabilities_json, member_id, status, created_at) VALUES (?, ?, ?, ?, ?, 'active', ?)"
        )
        .bind(req.project_id)
        .bind(req.token_id)
        .bind(req.token_hash)
        .bind(req.caps_json)
        .bind(req.requester_member_id)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE project_members SET wrapped_project_token = ? WHERE project_id = ? AND member_id = ?"
        )
        .bind(req.wrapped_b64)
        .bind(req.project_id)
        .bind(req.requester_member_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query("DELETE FROM project_requests WHERE project_id = ?")
            .bind(req.project_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_project(&self, project_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM projects WHERE project_id = ?")
            .bind(project_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn list_projects(
        &self,
    ) -> Result<Vec<(String, i64, Option<String>, String)>, sqlx::Error> {
        let rows = sqlx::query("SELECT project_id, revision, kagi_json, created_at FROM projects")
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get("project_id").unwrap_or_default(),
                    r.try_get("revision").unwrap_or_default(),
                    r.try_get("kagi_json").ok(),
                    r.try_get("created_at").unwrap_or_default(),
                )
            })
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_audit_event(
        &self,
        event_id: &str,
        project_id: Option<&str>,
        actor_member_id: Option<&str>,
        actor_token_id: Option<&str>,
        event_type: &str,
        request_id: Option<&str>,
        remote_addr: Option<&str>,
        metadata_json: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let now = time::OffsetDateTime::now_utc().to_string();
        sqlx::query(
            "INSERT INTO audit_events (event_id, created_at, project_id, actor_member_id, actor_token_id, event_type, request_id, remote_addr, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(event_id)
        .bind(&now)
        .bind(project_id)
        .bind(actor_member_id)
        .bind(actor_token_id)
        .bind(event_type)
        .bind(request_id)
        .bind(remote_addr)
        .bind(metadata_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn list_audit_events(
        &self,
        project_id: Option<&str>,
        limit: i64,
    ) -> Result<
        Vec<(
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        )>,
        sqlx::Error,
    > {
        let rows = if let Some(pid) = project_id {
            sqlx::query("SELECT event_id, created_at, project_id, actor_member_id, actor_token_id, event_type, request_id, remote_addr, metadata_json FROM audit_events WHERE project_id = ? ORDER BY created_at DESC LIMIT ?")
                .bind(pid)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query("SELECT event_id, created_at, project_id, actor_member_id, actor_token_id, event_type, request_id, remote_addr, metadata_json FROM audit_events ORDER BY created_at DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.try_get("event_id").unwrap_or_default(),
                    r.try_get("created_at").unwrap_or_default(),
                    r.try_get("project_id").ok(),
                    r.try_get("actor_member_id").ok(),
                    r.try_get("actor_token_id").ok(),
                    r.try_get("event_type").unwrap_or_default(),
                    r.try_get("request_id").ok(),
                    r.try_get("remote_addr").ok(),
                    r.try_get("metadata_json").ok(),
                )
            })
            .collect())
    }

    pub async fn get_metrics(&self) -> Result<(i64, i64, i64, i64), sqlx::Error> {
        let projects: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects")
            .fetch_one(&self.pool)
            .await?;
        let tokens: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM project_tokens WHERE status != 'revoked'")
                .fetch_one(&self.pool)
                .await?;
        let admins: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM admin_tokens WHERE status = 'active'")
                .fetch_one(&self.pool)
                .await?;
        let db_size: i64 = sqlx::query_scalar(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((projects, tokens, admins, db_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sync::project_state::ProjectFile;

    async fn test_repo() -> SqliteRemoteRepository {
        let id = rand::random::<u64>();
        let path = std::env::temp_dir().join(format!("kagi_test_{}.db", id));
        SqliteRemoteRepository::new_file(path).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_project_and_pull() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        let result = repo.pull_project_state("kgp_test").await.unwrap();
        assert!(result.is_some());
        let (revision, files) = result.unwrap();
        assert_eq!(revision, 0);
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_create_project_duplicate_fails() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let err = repo.create_project("kgp_test").await.unwrap_err();
        assert!(
            err.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false)
        );
    }

    #[tokio::test]
    async fn test_authenticate_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_token(
            "kgp_test",
            "kgt_123",
            "hash_correct",
            "[\"pull\"]",
            Some("kgm_alice"),
            "active",
        )
        .await
        .unwrap();

        let found = repo
            .authenticate_token("kgp_test", "hash_correct")
            .await
            .unwrap();
        assert!(found.is_some());
        let (token_id, caps, member_id) = found.unwrap();
        assert_eq!(token_id, "kgt_123");
        assert_eq!(caps, vec!["pull"]);
        assert_eq!(member_id, Some("kgm_alice".to_string()));

        let not_found = repo
            .authenticate_token("kgp_test", "hash_wrong")
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_push_and_pull_project_state() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        let files = vec![ProjectFile {
            path: "dev.env".into(),
            content: "KEY=val".into(),
            sha256: Some("abc".into()),
        }];
        let new_rev = repo
            .push_project_state(PushProjectStateRequest {
                project_id: "kgp_test",
                base_revision: 0,
                kagi_json: "{}",
                access_json: "{}",
                files: &files,
                activate_tokens: &[],
                revoke_tokens: &[],
                accepted_joins: &[],
                manifest_json: None,
                manifest_signature: None,
            })
            .await
            .unwrap();
        assert_eq!(new_rev, 1);

        let result = repo.pull_project_state("kgp_test").await.unwrap();
        let (revision, pulled_files) = result.unwrap();
        assert_eq!(revision, 1);
        assert_eq!(pulled_files.len(), 1);
        assert_eq!(pulled_files[0].path, "dev.env");
        assert_eq!(pulled_files[0].content, "KEY=val");
        assert_eq!(pulled_files[0].sha256, Some("abc".to_string()));
    }

    #[tokio::test]
    async fn test_push_conflict() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        let err = repo
            .push_project_state(PushProjectStateRequest {
                project_id: "kgp_test",
                base_revision: 99,
                kagi_json: "{}",
                access_json: "{}",
                files: &[],
                activate_tokens: &[],
                revoke_tokens: &[],
                accepted_joins: &[],
                manifest_json: None,
                manifest_signature: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, sqlx::Error::RowNotFound));
    }

    #[tokio::test]
    async fn test_join_request_flow() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        repo.upsert_join_request("kgp_test", "kgm_bob", "kgt_req1", "Bob", "bob", "age1...")
            .await
            .unwrap();

        let pending = repo.list_join_requests("kgp_test").await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, "kgm_bob");
        assert_eq!(pending[0].1, "Bob");
        assert_eq!(pending[0].2, "age1...");
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_token(
            "kgp_test",
            "kgt_123",
            "hash_value",
            "[\"pull\"]",
            None,
            "active",
        )
        .await
        .unwrap();

        repo.revoke_tokens("kgp_test", &["kgt_123".into()])
            .await
            .unwrap();

        let found = repo
            .authenticate_token("kgp_test", "hash_value")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn test_get_project_meta() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        let files = vec![ProjectFile {
            path: "a".into(),
            content: "b".into(),
            sha256: None,
        }];
        repo.push_project_state(PushProjectStateRequest {
            project_id: "kgp_test",
            base_revision: 0,
            kagi_json: "{\"k\":1}",
            access_json: "{\"a\":2}",
            files: &files,
            activate_tokens: &[],
            revoke_tokens: &[],
            accepted_joins: &[],
            manifest_json: None,
            manifest_signature: None,
        })
        .await
        .unwrap();

        let meta = repo.get_project_meta("kgp_test").await.unwrap();
        assert!(meta.is_some());
        let (kagi_json, access_json) = meta.unwrap();
        assert_eq!(kagi_json, Some("{\"k\":1}".to_string()));
        assert_eq!(access_json, Some("{\"a\":2}".to_string()));
    }

    #[tokio::test]
    async fn test_admin_token_lifecycle() {
        let repo = test_repo().await;
        assert!(!repo.has_admin_token().await.unwrap());

        let created_at = time::OffsetDateTime::now_utc().to_string();
        repo.create_admin_token("kat_123", "hash_admin", "[\"admin\"]", &created_at)
            .await
            .unwrap();

        assert!(repo.has_admin_token().await.unwrap());

        let found = repo.authenticate_admin_token("hash_admin").await.unwrap();
        assert!(found.is_some());
        let (token_id, caps) = found.unwrap();
        assert_eq!(token_id, "kat_123");
        assert_eq!(caps, vec!["admin"]);
    }

    #[tokio::test]
    async fn test_authenticate_admin_token_wrong_hash() {
        let repo = test_repo().await;
        let created_at = time::OffsetDateTime::now_utc().to_string();
        repo.create_admin_token("kat_123", "hash_correct", "[\"admin\"]", &created_at)
            .await
            .unwrap();

        let not_found = repo.authenticate_admin_token("hash_wrong").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_project_request_lifecycle() {
        let repo = test_repo().await;
        repo.create_project_request(
            "kgp_req",
            "kgm_alice",
            "Alice",
            "age1...",
            "cs:test",
            Some("{\"key\":1}"),
        )
        .await
        .unwrap();

        let requests = repo.list_project_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let (project_id, member_id, name, recipient, _hash, kagi_json, status) = &requests[0];
        assert_eq!(project_id, "kgp_req");
        assert_eq!(member_id, "kgm_alice");
        assert_eq!(name, "Alice");
        assert_eq!(recipient, "age1...");
        assert_eq!(kagi_json.as_deref(), Some("{\"key\":1}"));
        assert_eq!(status, "pending");

        let single = repo.get_project_request("kgp_req").await.unwrap();
        assert!(single.is_some());
        let (project_id2, member_id2, name2, recipient2, _hash2, kagi_json2, status2) =
            single.unwrap();
        assert_eq!(project_id2, "kgp_req");
        assert_eq!(member_id2, "kgm_alice");
        assert_eq!(name2, "Alice");
        assert_eq!(recipient2, "age1...");
        assert_eq!(kagi_json2.as_deref(), Some("{\"key\":1}"));
        assert_eq!(status2, "pending");

        repo.delete_project_request("kgp_req").await.unwrap();
        let after_delete = repo.list_project_requests().await.unwrap();
        assert!(after_delete.is_empty());
    }

    #[tokio::test]
    async fn test_project_member_lifecycle() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        repo.create_project_member(CreateProjectMemberRequest {
            project_id: "kgp_test",
            member_id: "kgm_bob",
            name: "Bob",
            role: "admin",
            status: "active",
            recipient: "age1...",
            claim_secret_hash: "cs:test",
        })
        .await
        .unwrap();

        let role = repo
            .get_project_member_role("kgp_test", "kgm_bob")
            .await
            .unwrap();
        assert_eq!(role, Some("admin".to_string()));

        repo.delete_project("kgp_test").await.unwrap();

        let role_after = repo
            .get_project_member_role("kgp_test", "kgm_bob")
            .await
            .unwrap();
        assert!(role_after.is_none());
    }

    #[tokio::test]
    async fn test_list_projects() {
        let repo = test_repo().await;
        repo.create_project("kgp_a").await.unwrap();
        repo.create_project("kgp_b").await.unwrap();

        let projects = repo.list_projects().await.unwrap();
        assert_eq!(projects.len(), 2);
        let ids: Vec<String> = projects.iter().map(|p| p.0.clone()).collect();
        assert!(ids.contains(&"kgp_a".to_string()));
        assert!(ids.contains(&"kgp_b".to_string()));
    }

    #[tokio::test]
    async fn test_audit_event_lifecycle() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        repo.create_audit_event(
            "kae_1",
            Some("kgp_test"),
            Some("kgm_alice"),
            Some("kgt_123"),
            "push",
            Some("kgr_1"),
            Some("127.0.0.1"),
            Some("{\"revision\":1}"),
        )
        .await
        .unwrap();

        let events = repo.list_audit_events(Some("kgp_test"), 10).await.unwrap();
        assert_eq!(events.len(), 1);
        let (
            event_id,
            _created_at,
            project_id,
            actor_member_id,
            actor_token_id,
            event_type,
            request_id,
            remote_addr,
            metadata_json,
        ) = &events[0];
        assert_eq!(event_id, "kae_1");
        assert_eq!(project_id.as_deref(), Some("kgp_test"));
        assert_eq!(actor_member_id.as_deref(), Some("kgm_alice"));
        assert_eq!(actor_token_id.as_deref(), Some("kgt_123"));
        assert_eq!(event_type, "push");
        assert_eq!(request_id.as_deref(), Some("kgr_1"));
        assert_eq!(remote_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(metadata_json.as_deref(), Some("{\"revision\":1}"));
    }

    #[tokio::test]
    async fn test_audit_event_does_not_leak_sensitive_data() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        repo.create_audit_event(
            "kae_1",
            Some("kgp_test"),
            None,
            None,
            "project_request_created",
            Some("kgr_1"),
            Some("127.0.0.1"),
            Some("{\"requester_name\":\"Alice\"}"),
        )
        .await
        .unwrap();

        let events = repo.list_audit_events(Some("kgp_test"), 10).await.unwrap();
        assert_eq!(events.len(), 1);
        let metadata_json = &events[0].8;
        let meta = metadata_json.as_deref().unwrap_or("");
        assert!(!meta.contains("secret"));
        assert!(!meta.contains("token"));
        assert!(!meta.contains("claim_secret"));
    }

    #[tokio::test]
    async fn test_metrics() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let (projects, tokens, admins, db_size) = repo.get_metrics().await.unwrap();
        assert_eq!(projects, 1);
        assert_eq!(tokens, 0);
        assert_eq!(admins, 0);
        assert!(db_size > 0);
    }
}
