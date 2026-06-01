use crate::server::errors::ServerError;
use crate::server::state::AppState;
use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use kagi_sync::domain::envelope::{
    RequestEnvelope, RequestPlaintext, ResponseEnvelope, SuccessResponse, response_mac,
};
use kagi_sync::domain::project_state::{ProjectState, validate_file_path};
use kagi_sync::domain::project_token::{ProjectToken, base64_encode_url, normalize_member_name};
use kagi_sync::infrastructure::remote_envelope::{
    decrypt_request, encrypt_response, parse_recipient,
};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use time::OffsetDateTime;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(health_check_handler))
        .route("/v1/server-key", get(server_key_handler))
        .route("/v1/metrics", get(metrics_handler))
        .route("/v1/projects", post(create_project_handler))
        .route("/v1/projects/{project_id}/push", post(push_handler))
        .route("/v1/projects/{project_id}/pull", post(pull_handler))
        .route("/v1/projects/{project_id}/status", post(status_handler))
        .route("/v1/projects/{project_id}/join", post(join_handler))
        .route(
            "/v1/projects/{project_id}/tokens/issue",
            post(token_issue_handler),
        )
        .route(
            "/v1/projects/{project_id}/tokens/revoke",
            post(token_revoke_handler),
        )
        .route(
            "/v1/projects/{project_id}/tokens/list",
            post(token_list_handler),
        )
        .route("/v1/audit", post(audit_handler))
        .route(
            "/v1/projects/requests",
            post(create_project_request_handler),
        )
        .route(
            "/v1/projects/requests/list",
            post(list_project_requests_handler),
        )
        .route(
            "/v1/projects/requests/{project_id}/approve",
            post(approve_project_request_handler),
        )
        .route("/v1/projects/list", post(list_projects_handler))
        .route(
            "/v1/projects/{project_id}/delete",
            post(delete_project_handler),
        )
        .with_state(state)
}

async fn health_check_handler() -> impl IntoResponse {
    let logo = r#"
    .--.
   /    \
  |  ()  |
   \ || /
    \||/
     ||
     ||
    /  \
   '    '

Kagi - Secure secrets, shared simply.
"#;
    (StatusCode::OK, logo)
}

async fn server_key_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "version": 1,
        "server_key_id": state.server_key_id,
        "recipient": state.identity.to_public().to_string(),
        "fingerprint": state.fingerprint,
    }))
}

async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, ServerError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();
    if token.is_empty() {
        return Err(ServerError::AuthFailed);
    }
    let _ = require_admin_token(&state, token).await?;

    let (projects, tokens, admins, db_size) = state
        .repo
        .get_metrics()
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    Ok(Json(json!({
        "active_projects": projects,
        "active_tokens": tokens,
        "active_admins": admins,
        "db_size": db_size,
    })))
}

async fn create_project_handler(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects", "POST").await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let _ = require_admin_token(&state, token_str).await?;
    let remote_url = remote_url_from_plaintext(&plaintext, Some(token_str))?;

    let project_id = plaintext
        .project_id
        .clone()
        .unwrap_or_else(|| format!(r"kgp_{}", nanoid::nanoid!(12)));
    state.repo.create_project(&project_id).await.map_err(|e| {
        if e.as_database_error()
            .map(sqlx::error::DatabaseError::is_unique_violation)
            .unwrap_or(false)
        {
            ServerError::Conflict {
                code: "conflict".into(),
                message: "project already exists".into(),
                details: None,
            }
        } else {
            ServerError::Internal(e.to_string())
        }
    })?;

    let token = ProjectToken::generate(
        remote_url,
        project_id.clone(),
        state.fingerprint.clone(),
        vec!["pull".into(), "join".into(), "push".into(), "rotate".into()],
        None,
    );

    let token_hash = state.hash_token(&token.full_token);
    let caps_json = serde_json::to_string(&token.payload.capabilities)
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    state
        .repo
        .create_token(
            &project_id,
            &token.payload.token_id,
            &token_hash,
            &caps_json,
            None,
            "active",
        )
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let response_data = json!({
        "project_id": project_id,
        "revision": 0,
        "project_token": token.full_token,
    });

    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn create_project_request_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects/requests", "POST").await?;

    let project_id = plaintext
        .project_id
        .clone()
        .unwrap_or_else(|| format!(r"kgp_{}", nanoid::nanoid!(12)));
    let requester_member_id = plaintext
        .payload
        .get("requester_member_id")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest(
            "missing requester_member_id".into(),
        ))?;
    let requester_name = plaintext
        .payload
        .get("requester_name")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing requester_name".into()))?;
    let requester_recipient = plaintext
        .payload
        .get("requester_recipient")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest(
            "missing requester_recipient".into(),
        ))?;
    parse_recipient(requester_recipient)
        .map_err(|e| ServerError::BadEnvelope(format!("invalid requester_recipient: {e}")))?;
    let claim_secret_hash = plaintext
        .payload
        .get("claim_secret_hash")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing claim_secret_hash".into()))?;
    let kagi_json = plaintext.payload.get("kagi_json").and_then(|v| v.as_str());

    state
        .repo
        .create_project_request(
            &project_id,
            requester_member_id,
            requester_name,
            requester_recipient,
            claim_secret_hash,
            kagi_json,
        )
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map(sqlx::error::DatabaseError::is_unique_violation)
                .unwrap_or(false)
            {
                ServerError::Conflict {
                    code: "conflict".into(),
                    message: "project request already exists".into(),
                    details: None,
                }
            } else {
                ServerError::Internal(e.to_string())
            }
        })?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            None,
            "project_request_created",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"requester_name": requester_name}).to_string()),
        )
        .await;

    let response_data = json!({"project_id": project_id, "status": "pending"});
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn list_project_requests_handler(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects/requests/list", "POST").await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let _ = require_admin_token(&state, token_str).await?;

    let requests = state
        .repo
        .list_project_requests()
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let requests_json: Vec<serde_json::Value> = requests.into_iter().map(|(project_id, member_id, name, recipient, _claim_secret_hash, kagi_json, status)| {
        json!({"project_id": project_id, "requester_member_id": member_id, "requester_name": name, "requester_recipient": recipient, "kagi_json": kagi_json, "status": status})
    }).collect();

    let response_data = json!({"requests": requests_json});
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn approve_project_request_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/requests/{project_id}/approve"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let admin_token_id = require_admin_token(&state, token_str).await?;

    let request = state
        .repo
        .get_project_request(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .ok_or(ServerError::NotFound)?;

    let (
        _req_project_id,
        requester_member_id,
        requester_name,
        requester_recipient,
        claim_secret_hash,
        _kagi_json,
        _status,
    ) = request;

    let recipient = parse_recipient(&requester_recipient)
        .map_err(|e| ServerError::BadEnvelope(e.to_string()))?;
    let remote_url = remote_url_from_plaintext(&plaintext, Some(token_str))?;

    let token = ProjectToken::generate(
        remote_url,
        project_id.clone(),
        state.fingerprint.clone(),
        vec!["pull".into(), "join".into(), "push".into(), "rotate".into()],
        None,
    );

    let token_hash = state.hash_token(&token.full_token);
    let caps_json = serde_json::to_string(&token.payload.capabilities)
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let wrapped = kagi_sync::infrastructure::remote_envelope::encrypt_bytes(
        token.full_token.as_bytes(),
        &recipient,
    )
    .map_err(|e| ServerError::Internal(e.to_string()))?;
    let wrapped_b64 = base64_encode_url(&wrapped);

    state
        .repo
        .approve_project_request_tx(crate::sqlite_remote::ApproveProjectRequest {
            project_id: &project_id,
            requester_member_id: &requester_member_id,
            requester_name: &requester_name,
            requester_recipient: &requester_recipient,
            claim_secret_hash: &claim_secret_hash,
            token_id: &token.payload.token_id,
            token_hash: &token_hash,
            caps_json: &caps_json,
            wrapped_b64: &wrapped_b64,
        })
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map(sqlx::error::DatabaseError::is_unique_violation)
                .unwrap_or(false)
            {
                ServerError::Conflict {
                    code: "conflict".into(),
                    message: "project already exists".into(),
                    details: None,
                }
            } else {
                ServerError::Internal(e.to_string())
            }
        })?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&admin_token_id),
            "project_request_approved",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"requester_name": requester_name}).to_string()),
        )
        .await;

    let response_data = json!({
        "project_id": project_id,
        "status": "active",
    });
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn list_projects_handler(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects/list", "POST").await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let _ = require_admin_token(&state, token_str).await?;

    let projects = state
        .repo
        .list_projects()
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let projects_json: Vec<serde_json::Value> = projects.into_iter().map(|(project_id, revision, kagi_json, created_at)| {
        json!({"project_id": project_id, "revision": revision, "kagi_json": kagi_json, "created_at": created_at})
    }).collect();

    let response_data = json!({"projects": projects_json});
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn delete_project_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/delete"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let actor_token_id = require_project_or_admin_token(&state, &project_id, token_str).await?;

    state
        .repo
        .delete_project(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&actor_token_id),
            "project_deleted",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            None,
        )
        .await;

    let response_data = json!({"project_id": project_id, "status": "deleted"});
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn push_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/push"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, _) =
        require_project_capability(&state, &project_id, token_str, &["push"]).await?;
    ensure_request_id_once(&state, &project_id, &plaintext.request_id, "push").await?;

    let base_revision = plaintext
        .payload
        .get("base_revision")
        .and_then(serde_json::Value::as_i64)
        .ok_or(ServerError::InvalidRevision)?;
    let state_json = plaintext
        .payload
        .get("state")
        .ok_or(ServerError::InvalidProjectState("missing state".into()))?;
    let project_state: ProjectState = serde_json::from_value(state_json.clone())
        .map_err(|e| ServerError::InvalidProjectState(format!("{e}")))?;

    for file in &project_state.files {
        validate_file_path(&file.path)
            .map_err(|_e| ServerError::InvalidPath("invalid file path".into()))?;
    }

    // Storage limits: prevent a single project from filling the disk
    const MAX_PROJECT_FILES: usize = 1000;
    const MAX_PROJECT_TOTAL_BYTES: usize = 50 * 1024 * 1024;
    if project_state.files.len() > MAX_PROJECT_FILES {
        return Err(ServerError::PayloadTooLarge);
    }
    let total_incoming_size: usize = project_state.files.iter().map(|f| f.content.len()).sum();
    if total_incoming_size > MAX_PROJECT_TOTAL_BYTES {
        return Err(ServerError::PayloadTooLarge);
    }

    let activate: Vec<String> = plaintext
        .payload
        .get("activate_token_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let revoke: Vec<String> = plaintext
        .payload
        .get("revoke_token_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let accepted: Vec<String> = plaintext
        .payload
        .get("accepted_join_member_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let manifest_json = plaintext
        .payload
        .get("manifest")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing manifest".into()))?;
    let manifest_signature = plaintext
        .payload
        .get("manifest_signature")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing manifest_signature".into()))?;

    verify_pushed_manifest(
        &state,
        &project_id,
        base_revision,
        &project_state,
        manifest_json,
        manifest_signature,
    )
    .await?;

    let new_revision = state
        .repo
        .push_project_state(
            crate::sqlite_remote::PushProjectStateRequest {
                project_id: &project_id,
                base_revision,
                kagi_json: &project_state.kagi_json,
                access_json: &project_state.access_json,
                files: &project_state.files,
                activate_tokens: &activate,
                revoke_tokens: &revoke,
                accepted_joins: &accepted,
                manifest_json: Some(manifest_json),
                manifest_signature: Some(manifest_signature),
            },
        )
        .await
        .map_err(|e| {
        if matches!(e, sqlx::Error::RowNotFound) {
            ServerError::Conflict {
                code: "conflict".into(),
                message: "remote revision changed; run kagi remote pull first".into(),
                details: Some(json!({"remote_revision": base_revision + 1, "base_revision": base_revision})),
            }
        } else {
            ServerError::Internal(e.to_string())
        }
    })?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&token_id),
            "push",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"revision": new_revision}).to_string()),
        )
        .await;

    let response_data = json!({
        "revision": new_revision,
    });
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn pull_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/pull"),
        "POST",
    )
    .await?;

    if let Some(token_str) = plaintext.token.as_ref() {
        let (_, caps) =
            require_project_capability(&state, &project_id, token_str, &["pull"]).await?;

        let (revision, files) = state
            .repo
            .pull_project_state(&project_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::NotFound)?;

        let project_meta = state
            .repo
            .get_project_meta(&project_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;
        let (kagi_json, access_json) = project_meta
            .map(|(k, a)| {
                (
                    k.unwrap_or_else(|| "{}".to_string()),
                    a.unwrap_or_else(|| "{}".to_string()),
                )
            })
            .unwrap_or_else(|| ("{}".to_string(), "{}".to_string()));

        let manifest = state
            .repo
            .get_manifest(&project_id, revision)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;

        let mut response = json!({
            "revision": revision,
            "state": {
                "project_id": project_id,
                "revision": revision,
                "kagi_json": kagi_json,
                "access_json": access_json,
                "files": files,
            },
        });

        if let Some((manifest_hash, manifest_json, manifest_signature)) = manifest {
            response["manifest_hash"] = json!(manifest_hash);
            response["manifest"] = json!(manifest_json);
            if let Some(sig) = manifest_signature {
                response["manifest_signature"] = json!(sig);
            }
        }

        if caps.iter().any(|c| c == "push" || c == "rotate") {
            let join_requests = state
                .repo
                .list_join_requests(&project_id)
                .await
                .map_err(|e| ServerError::Internal(e.to_string()))?;
            let requests_json: Vec<serde_json::Value> = join_requests.into_iter().map(|(member_id, name, recipient, signing_public_key, created_at)| {
                json!({"member_id": member_id, "name": name, "recipient": recipient, "signing_public_key": signing_public_key, "created_at": created_at})
            }).collect();
            response["join_requests"] = json!(requests_json);
        }

        let _ = state
            .repo
            .create_audit_event(
                &format!(r"kae_{}", nanoid::nanoid!(12)),
                Some(&project_id),
                None,
                None,
                "pull",
                Some(&plaintext.request_id),
                Some(&addr.to_string()),
                Some(&json!({"revision": revision}).to_string()),
            )
            .await;

        encrypt_success_response(&state, &plaintext, &response_recipient, response)
    } else {
        let member_id = plaintext
            .payload
            .get("member_id")
            .and_then(|v| v.as_str())
            .ok_or(ServerError::BadRequest("missing member_id".into()))?;
        let claim_secret = plaintext
            .claim_secret
            .as_deref()
            .ok_or(ServerError::BadRequest("missing claim_secret".into()))?;

        let member = state
            .repo
            .get_project_member(&project_id, member_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::NotFound)?;

        let (_name, _role, status, recipient, claim_secret_hash) = member;
        if status != "active" {
            return Err(ServerError::Forbidden);
        }
        if response_recipient != recipient {
            return Err(ServerError::Forbidden);
        }
        let hash = crate::server::state::hash_claim_secret(claim_secret);
        if hash != claim_secret_hash {
            return Err(ServerError::Forbidden);
        }

        let wrapped = state
            .repo
            .get_wrapped_project_token(&project_id, member_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or(ServerError::Forbidden)?;

        let response = json!({
            "wrapped_project_token": wrapped,
        });

        let _ = state
            .repo
            .create_audit_event(
                &format!(r"kae_{}", nanoid::nanoid!(12)),
                Some(&project_id),
                Some(member_id),
                None,
                "tokenless_pull",
                Some(&plaintext.request_id),
                Some(&addr.to_string()),
                None,
            )
            .await;

        // Use claim_secret for MAC since token is None
        let mut plaintext_with_secret = plaintext.clone();
        plaintext_with_secret.claim_secret = Some(claim_secret.to_string());
        encrypt_success_response(
            &state,
            &plaintext_with_secret,
            &response_recipient,
            response,
        )
    }
}

async fn status_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/status"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_, caps) = require_project_capability(&state, &project_id, token_str, &["pull"]).await?;

    let local_revision = plaintext
        .payload
        .get("local_revision")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    let remote_revision = state
        .repo
        .pull_project_state(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?
        .map(|(rev, _)| rev)
        .unwrap_or(0);

    let state_str = if remote_revision == local_revision {
        "equal"
    } else if local_revision > remote_revision {
        "ahead"
    } else {
        "behind"
    };

    let mut response = json!({
        "remote_revision": remote_revision,
        "local_revision": local_revision,
        "state": state_str,
        "pending_join_count": 0,
    });

    if caps.iter().any(|c| c == "push" || c == "rotate") {
        let join_requests = state
            .repo
            .list_join_requests(&project_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?;
        let requests_json: Vec<serde_json::Value> = join_requests.into_iter().map(|(member_id, name, recipient, signing_public_key, created_at)| {
            json!({"member_id": member_id, "name": name, "recipient": recipient, "signing_public_key": signing_public_key, "created_at": created_at})
        }).collect();
        response["pending_join_count"] = json!(requests_json.len() as i64);
        response["join_requests"] = json!(requests_json);
    }

    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn join_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/join"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, _) =
        require_project_capability(&state, &project_id, token_str, &["join"]).await?;
    ensure_request_id_once(&state, &project_id, &plaintext.request_id, "join_request").await?;

    let join_req = plaintext
        .payload
        .get("join_request")
        .ok_or(ServerError::BadRequest("missing join_request".into()))?;
    let member_id = join_req
        .get("member_id")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing member_id".into()))?;
    let name = join_req
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing name".into()))?;
    let recipient = join_req
        .get("recipient")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing recipient".into()))?;
    parse_recipient(recipient)
        .map_err(|e| ServerError::BadEnvelope(format!("invalid recipient: {e}")))?;
    let signing_public_key = join_req
        .get("signing_public_key")
        .and_then(|v| v.as_str())
        .ok_or(ServerError::BadRequest("missing signing_public_key".into()))?;
    validate_signing_public_key(signing_public_key)?;
    let normalized = normalize_member_name(name);

    state
        .repo
        .upsert_join_request(crate::sqlite_remote::UpsertJoinRequest {
            project_id: &project_id,
            member_id,
            request_token_id: &token_id,
            name,
            normalized_name: &normalized,
            recipient,
            signing_public_key,
        })
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map(sqlx::error::DatabaseError::is_unique_violation)
                .unwrap_or(false)
            {
                ServerError::Conflict {
                    code: "conflict".into(),
                    message: "a pending member request with this name already exists".into(),
                    details: None,
                }
            } else {
                ServerError::Internal(e.to_string())
            }
        })?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&token_id),
            "join_request",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"member_id": member_id, "name": name}).to_string()),
        )
        .await;

    let response = json!({"member_id": member_id, "status": "pending"});
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn token_issue_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/tokens/issue"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, _) =
        require_project_capability(&state, &project_id, token_str, &["rotate"]).await?;
    ensure_request_id_once(&state, &project_id, &plaintext.request_id, "token_issued").await?;

    let capabilities: Vec<String> = plaintext
        .payload
        .get("capabilities")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(ServerError::BadRequest("missing capabilities".into()))?;
    let member_id = plaintext.payload.get("member_id").and_then(|v| v.as_str());
    let status = plaintext
        .payload
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("pending_activation");
    let remote_url = remote_url_from_plaintext(&plaintext, Some(token_str))?;

    let bootstrap_signer_public_key = match state
        .repo
        .pull_project_state(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?
    {
        Some((revision, _)) if revision > 0 => {
            let (_, manifest_json, _) = state
                .repo
                .get_manifest(&project_id, revision)
                .await
                .map_err(|e| ServerError::Internal(e.to_string()))?
                .ok_or_else(|| {
                    ServerError::Internal("project revision is missing manifest".into())
                })?;
            let manifest =
                serde_json::from_str::<kagi_sync::domain::manifest::ProjectStateManifest>(
                    &manifest_json,
                )
                .map_err(|e| ServerError::Internal(format!("invalid stored manifest: {e}")))?;
            Some(manifest.signer_public_key)
        }
        _ => None,
    };

    let token = ProjectToken::generate(
        remote_url,
        project_id.clone(),
        state.fingerprint.clone(),
        capabilities,
        bootstrap_signer_public_key,
    );

    let token_hash = state.hash_token(&token.full_token);
    let caps_json = serde_json::to_string(&token.payload.capabilities)
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    state
        .repo
        .create_token(
            &project_id,
            &token.payload.token_id,
            &token_hash,
            &caps_json,
            member_id,
            status,
        )
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let response = json!({
        "token_id": token.payload.token_id,
        "project_token": token.full_token,
        "status": status,
    });

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            None,
            "token_issued",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"token_id": token.payload.token_id}).to_string()),
        )
        .await;

    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn token_revoke_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/tokens/revoke"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, _) =
        require_project_capability(&state, &project_id, token_str, &["rotate"]).await?;

    let token_ids: Vec<String> = plaintext
        .payload
        .get("token_ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or(ServerError::BadRequest("missing token_ids".into()))?;

    state
        .repo
        .revoke_tokens(&project_id, &token_ids)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&token_id),
            "token_revoked",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"token_ids": token_ids}).to_string()),
        )
        .await;

    let response = json!({"revoked_token_ids": token_ids});
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn token_list_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{project_id}/tokens/list"),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, _) =
        require_project_capability(&state, &project_id, token_str, &["rotate", "admin"]).await?;

    let tokens = state
        .repo
        .list_project_tokens(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let token_list: Vec<serde_json::Value> = tokens
        .into_iter()
        .map(
            |(id, caps_json, member_id, status, created_at, activated_at, revoked_at)| {
                let caps: Vec<String> = serde_json::from_str(&caps_json).unwrap_or_default();
                json!({
                    "token_id": id,
                    "capabilities": caps,
                    "member_id": member_id,
                    "status": status,
                    "created_at": created_at,
                    "activated_at": activated_at,
                    "revoked_at": revoked_at,
                })
            },
        )
        .collect();

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            Some(&project_id),
            None,
            Some(&token_id),
            "token_listed",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"token_count": token_list.len()}).to_string()),
        )
        .await;

    let response = json!({"tokens": token_list});
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn audit_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/audit", "POST").await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, caps) = authenticate_admin(&state, token_str).await?;
    if !caps.iter().any(|c| c == "admin") {
        return Err(ServerError::Forbidden);
    }

    let project_id = plaintext.payload.get("project_id").and_then(|v| v.as_str());
    let limit = plaintext
        .payload
        .get("limit")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(50)
        .clamp(1, 500);

    let events = state
        .repo
        .list_audit_events(project_id, limit)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let event_list: Vec<serde_json::Value> = events
        .into_iter()
        .map(
            |(
                event_id,
                created_at,
                project_id,
                actor_member_id,
                actor_token_id,
                event_type,
                request_id,
                remote_addr,
                metadata_json,
            )| {
                json!({
                    "event_id": event_id,
                    "created_at": created_at,
                    "project_id": project_id,
                    "actor_member_id": actor_member_id,
                    "actor_token_id": actor_token_id,
                    "event_type": event_type,
                    "request_id": request_id,
                    "remote_addr": remote_addr,
                    "metadata_json": metadata_json,
                })
            },
        )
        .collect();

    let _ = state
        .repo
        .create_audit_event(
            &format!(r"kae_{}", nanoid::nanoid!(12)),
            project_id,
            None,
            Some(&token_id),
            "audit_queried",
            Some(&plaintext.request_id),
            Some(&addr.to_string()),
            Some(&json!({"event_count": event_list.len()}).to_string()),
        )
        .await;

    let response = json!({"events": event_list});
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn decrypt_and_verify_envelope(
    state: &AppState,
    envelope: RequestEnvelope,
    expected_path: &str,
    expected_method: &str,
) -> Result<(RequestPlaintext, String), ServerError> {
    if envelope.version != 1 {
        return Err(ServerError::BadEnvelope(
            "unsupported envelope version".into(),
        ));
    }
    if envelope.server_key_id != state.server_key_id {
        return Err(ServerError::ServerKeyMismatch);
    }

    let plaintext = decrypt_request(&envelope, &state.identity)
        .map_err(|e| ServerError::DecryptFailed(e.to_string()))?;

    if plaintext.request_id != envelope.request_id {
        return Err(ServerError::BadEnvelope("request_id mismatch".into()));
    }
    if plaintext.method != expected_method || plaintext.path != expected_path {
        return Err(ServerError::BadEnvelope("method/path mismatch".into()));
    }
    let bound_response_recipient = plaintext
        .payload
        .get("response_recipient")
        .and_then(|value| value.as_str())
        .ok_or_else(|| ServerError::BadEnvelope("missing bound response_recipient".into()))?;
    if bound_response_recipient != envelope.response_recipient {
        return Err(ServerError::BadEnvelope(
            "response_recipient mismatch".into(),
        ));
    }

    let issued = time::OffsetDateTime::parse(
        &plaintext.issued_at,
        &time::format_description::well_known::Rfc3339,
    )
    .map_err(|e| ServerError::BadEnvelope(format!("invalid issued_at: {e}")))?;
    let now = OffsetDateTime::now_utc();
    let diff = (now - issued).abs();
    if diff.whole_minutes() > 5 {
        return Err(ServerError::BadEnvelope("request expired".into()));
    }

    Ok((plaintext, envelope.response_recipient))
}

async fn authenticate(
    state: &AppState,
    project_id: &str,
    token_str: &str,
) -> Result<(String, Vec<String>, Option<String>), ServerError> {
    let token_hash = state.hash_token(token_str);
    let result = state
        .repo
        .authenticate_token(project_id, &token_hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    result.ok_or(ServerError::AuthFailed)
}

fn has_any_capability(caps: &[String], required: &[&str]) -> bool {
    caps.iter()
        .any(|cap| required.iter().any(|required| cap == required))
}

async fn require_admin_token(state: &AppState, token_str: &str) -> Result<String, ServerError> {
    let (token_id, caps) = authenticate_admin(state, token_str).await?;
    if !has_any_capability(&caps, &["admin"]) {
        return Err(ServerError::Forbidden);
    }
    Ok(token_id)
}

async fn require_project_capability(
    state: &AppState,
    project_id: &str,
    token_str: &str,
    capabilities: &[&str],
) -> Result<(String, Vec<String>), ServerError> {
    let (token_id, caps, _member_id) = authenticate(state, project_id, token_str).await?;
    if !has_any_capability(&caps, capabilities) {
        return Err(ServerError::Forbidden);
    }
    Ok((token_id, caps))
}

async fn require_project_or_admin_token(
    state: &AppState,
    project_id: &str,
    token_str: &str,
) -> Result<String, ServerError> {
    if let Ok(token_id) = require_admin_token(state, token_str).await {
        return Ok(token_id);
    }

    let (token_id, _caps, member_id) = authenticate(state, project_id, token_str).await?;
    let member_id = member_id.ok_or(ServerError::Forbidden)?;
    let role = state
        .repo
        .get_project_member_role(project_id, &member_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    if role.as_deref() != Some("admin") {
        return Err(ServerError::Forbidden);
    }
    Ok(token_id)
}

async fn ensure_request_id_once(
    state: &AppState,
    project_id: &str,
    request_id: &str,
    event_type: &str,
) -> Result<(), ServerError> {
    let seen = state
        .repo
        .request_id_seen(project_id, request_id, event_type)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    if seen {
        return Err(ServerError::Conflict {
            code: "duplicate_request".into(),
            message: "request_id already processed".into(),
            details: Some(
                json!({"project_id": project_id, "request_id": request_id, "event_type": event_type}),
            ),
        });
    }

    Ok(())
}

async fn authenticate_admin(
    state: &AppState,
    token_str: &str,
) -> Result<(String, Vec<String>), ServerError> {
    let token_hash = state.hash_token(token_str);
    let result = state
        .repo
        .authenticate_admin_token(&token_hash)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    result.ok_or(ServerError::AuthFailed)
}

fn encrypt_success_response(
    _state: &AppState,
    plaintext: &RequestPlaintext,
    response_recipient: &str,
    data: serde_json::Value,
) -> Result<axum::response::Response, ServerError> {
    let response = SuccessResponse {
        ok: true,
        request_id: plaintext.request_id.clone(),
        data,
    };
    let recipient =
        parse_recipient(response_recipient).map_err(|e| ServerError::BadEnvelope(e.to_string()))?;
    let ciphertext = encrypt_response(&response, &recipient)
        .map_err(|e| ServerError::Internal(e.to_string()))?;
    let ciphertext = base64_encode_url(&ciphertext);
    let mac_key = plaintext
        .token
        .as_deref()
        .or(plaintext.claim_secret.as_deref());
    let mac = mac_key.map(|key| response_mac(key, &plaintext.request_id, &ciphertext));

    let body = Json(ResponseEnvelope {
        version: 1,
        request_id: plaintext.request_id.clone(),
        mac,
        ciphertext,
    });
    Ok((StatusCode::OK, body).into_response())
}

fn remote_url_from_plaintext(
    plaintext: &RequestPlaintext,
    token_str: Option<&str>,
) -> Result<String, ServerError> {
    if let Some(remote) = plaintext
        .payload
        .get("remote")
        .and_then(|value| value.as_str())
        && !remote.trim().is_empty()
    {
        validate_remote_url(remote)?;
        return Ok(remote.to_string());
    }

    if let Some(token_str) = token_str
        && let Some(token) = ProjectToken::parse(token_str)
        && token.payload.remote != "admin"
        && !token.payload.remote.trim().is_empty()
    {
        validate_remote_url(&token.payload.remote)?;
        return Ok(token.payload.remote);
    }

    Err(ServerError::BadRequest("missing remote URL".into()))
}

fn validate_remote_url(remote: &str) -> Result<(), ServerError> {
    let url = url::Url::parse(remote)
        .map_err(|_| ServerError::BadRequest("invalid remote URL".into()))?;
    match url.scheme() {
        "http" | "https" => Ok(()),
        _ => Err(ServerError::BadRequest(
            "remote URL must use http or https".into(),
        )),
    }
}

fn validate_signing_public_key(signing_public_key: &str) -> Result<(), ServerError> {
    let bytes = {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD
            .decode(signing_public_key)
            .map_err(|e| ServerError::BadRequest(format!("invalid signing_public_key: {e}")))?
    };
    if bytes.len() != 32 {
        return Err(ServerError::BadRequest(
            "signing_public_key must be 32 bytes".into(),
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ServerError::BadRequest(format!("invalid signing_public_key: {e}")))?;
    Ok(())
}

async fn verify_pushed_manifest(
    state: &AppState,
    project_id: &str,
    base_revision: i64,
    project_state: &ProjectState,
    manifest_json: &str,
    manifest_signature: &str,
) -> Result<(), ServerError> {
    let manifest: kagi_sync::domain::manifest::ProjectStateManifest =
        serde_json::from_str(manifest_json)
            .map_err(|e| ServerError::InvalidProjectState(format!("invalid manifest: {e}")))?;
    let manifest_canonical = serde_json::to_string(&manifest)
        .map_err(|e| ServerError::InvalidProjectState(format!("invalid manifest: {e}")))?;
    if manifest_canonical != manifest_json {
        return Err(ServerError::InvalidProjectState(
            "manifest must use canonical JSON encoding".into(),
        ));
    }

    let expected_revision = base_revision + 1;
    if manifest.project_id != project_id {
        return Err(ServerError::InvalidProjectState(
            "manifest project_id mismatch".into(),
        ));
    }
    if manifest.revision != expected_revision {
        return Err(ServerError::InvalidProjectState(
            "manifest revision mismatch".into(),
        ));
    }

    let expected_previous_hash = if base_revision > 0 {
        let (previous_hash, _, _) = state
            .repo
            .get_manifest(project_id, base_revision)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .ok_or_else(|| ServerError::InvalidProjectState("previous manifest missing".into()))?;
        Some(previous_hash)
    } else {
        None
    };
    if manifest.previous_manifest_hash != expected_previous_hash {
        return Err(ServerError::InvalidProjectState(
            "manifest previous hash mismatch".into(),
        ));
    }

    if manifest.kagi_json_hash != kagi_sync::domain::manifest::hash_json(&project_state.kagi_json) {
        return Err(ServerError::InvalidProjectState(
            "manifest kagi_json hash mismatch".into(),
        ));
    }
    if manifest.access_json_hash
        != kagi_sync::domain::manifest::hash_json(&project_state.access_json)
    {
        return Err(ServerError::InvalidProjectState(
            "manifest access_json hash mismatch".into(),
        ));
    }

    let mut state_file_hashes = BTreeMap::new();
    for file in &project_state.files {
        let file_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(file.content.as_bytes());
            hex::encode(hasher.finalize())
        };
        if let Some(declared_hash) = file.sha256.as_deref()
            && declared_hash != file_hash
        {
            return Err(ServerError::InvalidProjectState(format!(
                "project file sha256 mismatch for {}",
                file.path
            )));
        }
        if state_file_hashes
            .insert(file.path.clone(), file_hash)
            .is_some()
        {
            return Err(ServerError::InvalidProjectState(format!(
                "duplicate project file path: {}",
                file.path
            )));
        }
    }

    let mut manifest_paths = BTreeSet::new();
    for manifest_file in &manifest.file_hashes {
        if !manifest_paths.insert(manifest_file.path.clone()) {
            return Err(ServerError::InvalidProjectState(format!(
                "duplicate manifest file path: {}",
                manifest_file.path
            )));
        }
        let state_hash = state_file_hashes.get(&manifest_file.path).ok_or_else(|| {
            ServerError::InvalidProjectState(format!(
                "manifest references missing file: {}",
                manifest_file.path
            ))
        })?;
        if manifest_file.sha256 != *state_hash {
            return Err(ServerError::InvalidProjectState(format!(
                "manifest file hash mismatch for {}",
                manifest_file.path
            )));
        }
    }
    let state_paths: BTreeSet<String> = state_file_hashes.keys().cloned().collect();
    if state_paths != manifest_paths {
        return Err(ServerError::InvalidProjectState(
            "manifest file set mismatch".into(),
        ));
    }

    let access: serde_json::Value = serde_json::from_str(&project_state.access_json)
        .map_err(|e| ServerError::InvalidProjectState(format!("invalid access_json: {e}")))?;
    let signer_public_key = access
        .get("members")
        .and_then(|members| members.as_array())
        .and_then(|members| {
            members.iter().find(|member| {
                member.get("member_id").and_then(|value| value.as_str())
                    == Some(manifest.signer_member_id.as_str())
            })
        })
        .and_then(|member| member.get("signing_public_key"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| {
            ServerError::InvalidProjectState("manifest signer is not in access_json".into())
        })?;
    if signer_public_key != manifest.signer_public_key {
        return Err(ServerError::InvalidProjectState(
            "manifest signer key mismatch".into(),
        ));
    }

    let signature_bytes = {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.decode(manifest_signature).map_err(|e| {
            ServerError::InvalidProjectState(format!("invalid manifest signature: {e}"))
        })?
    };
    if signature_bytes.len() != 64 {
        return Err(ServerError::InvalidProjectState(
            "manifest signature must be 64 bytes".into(),
        ));
    }
    let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)
        .map_err(|e| ServerError::InvalidProjectState(format!("invalid signature: {e}")))?;
    let public_key_bytes = {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.decode(&manifest.signer_public_key).map_err(|e| {
            ServerError::InvalidProjectState(format!("invalid signer public key: {e}"))
        })?
    };
    if public_key_bytes.len() != 32 {
        return Err(ServerError::InvalidProjectState(
            "signer public key must be 32 bytes".into(),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&public_key_bytes);
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key)
        .map_err(|e| ServerError::InvalidProjectState(format!("invalid signer key: {e}")))?;
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(manifest.compute_hash().as_bytes(), &signature)
        .map_err(|e| {
            ServerError::InvalidProjectState(format!("manifest signature verification failed: {e}"))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite_remote::SqliteRemoteRepository;
    use age::x25519;
    use kagi_sync::domain::envelope::verify_response_mac;
    use kagi_sync::infrastructure::remote_envelope::encrypt_request;

    fn test_state(repo: SqliteRemoteRepository) -> Arc<AppState> {
        let identity = x25519::Identity::generate();
        Arc::new(AppState {
            repo,
            identity: identity.clone(),
            server_key_id: "kgs_placeholder".into(),
            fingerprint: "fp_test".into(),
            token_pepper: vec![0u8; 32],
        })
    }

    fn dummy_addr() -> ConnectInfo<SocketAddr> {
        ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080)))
    }

    async fn test_repo() -> SqliteRemoteRepository {
        let id = rand::random::<u64>();
        let path = std::env::temp_dir().join(format!("kagi_route_test_{id}.db"));
        SqliteRemoteRepository::new_file(path).await.unwrap()
    }

    fn make_envelope(
        state: &AppState,
        plaintext: &RequestPlaintext,
        client_identity: &x25519::Identity,
    ) -> RequestEnvelope {
        let server_recipient = state.identity.to_public();
        let client_recipient = client_identity.to_public();
        encrypt_request(plaintext, &server_recipient, &client_recipient).unwrap()
    }

    fn plaintext_now(request_id: &str, path: &str, method: &str) -> RequestPlaintext {
        let issued_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        RequestPlaintext {
            version: 1,
            request_id: request_id.into(),
            issued_at,
            operation: "test".into(),
            method: method.into(),
            path: path.into(),
            project_id: None,
            token: None,
            claim_secret: None,
            payload: json!({}),
        }
    }

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[11u8; 32])
    }

    fn test_public_key_b64(signing_key: &ed25519_dalek::SigningKey) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        STANDARD.encode(signing_key.verifying_key().to_bytes())
    }

    fn sha256_hex(value: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn signed_project_state_fixture() -> (ProjectState, String, String) {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::Signer as _;

        let signing_key = test_signing_key();
        let signer_public_key = test_public_key_b64(&signing_key);
        let access_json = json!({
            "members": [{
                "member_id": "kgm_test",
                "signing_public_key": signer_public_key,
            }]
        })
        .to_string();
        let file_content = "encrypted-content";
        let file_hash = sha256_hex(file_content);
        let file_path = "secrets/api/development.enc";
        let project_state = ProjectState {
            project_id: "kgp_test".into(),
            revision: 0,
            kagi_json: "{}".into(),
            access_json: access_json.clone(),
            files: vec![kagi_sync::domain::project_state::ProjectFile {
                path: file_path.into(),
                content: file_content.into(),
                sha256: Some(file_hash.clone()),
            }],
        };
        let manifest = kagi_sync::domain::manifest::ProjectStateManifest {
            version: 1,
            project_id: "kgp_test".into(),
            revision: 1,
            previous_manifest_hash: None,
            kagi_json_hash: kagi_sync::domain::manifest::hash_json(&project_state.kagi_json),
            access_json_hash: kagi_sync::domain::manifest::hash_json(&access_json),
            file_hashes: vec![kagi_sync::domain::manifest::FileHash {
                path: file_path.into(),
                sha256: file_hash,
            }],
            timestamp: "2026-01-01T00:00:00Z".into(),
            signer_member_id: "kgm_test".into(),
            signer_public_key,
        };
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let signature = signing_key.sign(manifest.compute_hash().as_bytes());
        let signature_b64 = STANDARD.encode(signature.to_bytes());
        (project_state, manifest_json, signature_b64)
    }

    #[tokio::test]
    async fn test_verify_pushed_manifest_accepts_valid_manifest() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let (project_state, manifest_json, signature) = signed_project_state_fixture();

        verify_pushed_manifest(
            &state,
            "kgp_test",
            0,
            &project_state,
            &manifest_json,
            &signature,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_verify_pushed_manifest_rejects_tampered_file_content() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let (mut project_state, manifest_json, signature) = signed_project_state_fixture();
        project_state.files[0].content = "tampered".into();

        let err = verify_pushed_manifest(
            &state,
            "kgp_test",
            0,
            &project_state,
            &manifest_json,
            &signature,
        )
        .await
        .unwrap_err();

        assert!(matches!(err, ServerError::InvalidProjectState(_)));
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_valid() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let (decrypted, response_recipient) =
            decrypt_and_verify_envelope(&state, envelope, "/v1/projects/kgp_test/push", "POST")
                .await
                .unwrap();
        assert_eq!(decrypted.request_id, "kgr_1");
        assert!(!response_recipient.is_empty());
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_rejects_tampered_response_recipient() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        let mut envelope = make_envelope(&state, &plaintext, &client_identity);
        envelope.response_recipient = x25519::Identity::generate().to_public().to_string();

        let err =
            decrypt_and_verify_envelope(&state, envelope, "/v1/projects/kgp_test/push", "POST")
                .await
                .unwrap_err();
        assert!(matches!(err, ServerError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_version_mismatch() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/test", "POST");
        plaintext.payload = json!({"version": 2});
        let mut envelope = make_envelope(&state, &plaintext, &client_identity);
        envelope.version = 2;

        let err = decrypt_and_verify_envelope(&state, envelope, "/v1/test", "POST")
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_server_key_mismatch() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let plaintext = plaintext_now("kgr_1", "/v1/test", "POST");
        let mut envelope = make_envelope(&state, &plaintext, &client_identity);
        envelope.server_key_id = "wrong_key".into();

        let err = decrypt_and_verify_envelope(&state, envelope, "/v1/test", "POST")
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::ServerKeyMismatch));
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_path_mismatch() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let plaintext = plaintext_now("kgr_1", "/v1/test", "POST");
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = decrypt_and_verify_envelope(&state, envelope, "/v1/other", "POST")
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn test_decrypt_and_verify_envelope_expired() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/test", "POST");
        plaintext.issued_at = "2020-01-01T00:00:00Z".into();
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = decrypt_and_verify_envelope(&state, envelope, "/v1/test", "POST")
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn test_authenticate_valid_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();

        let state = test_state(repo);
        let token = "my_secret_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let (token_id, caps, _member_id) = authenticate(&state, "kgp_test", token).await.unwrap();
        assert_eq!(token_id, "kgt_123");
        assert_eq!(caps, vec!["pull"]);
    }

    #[tokio::test]
    async fn test_authenticate_invalid_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_token(
            "kgp_test",
            "kgt_123",
            "hash_val",
            "[\"pull\"]",
            None,
            "active",
        )
        .await
        .unwrap();

        let state = test_state(repo);
        let err = authenticate(&state, "kgp_test", "wrong_token")
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_encrypt_success_response() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/test", "POST");
        plaintext.token = Some("response-token".into());
        let response_recipient = client_identity.to_public().to_string();

        let resp = encrypt_success_response(
            &state,
            &plaintext,
            &response_recipient,
            json!({"revision": 42}),
        )
        .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let envelope: ResponseEnvelope = serde_json::from_slice(&body).unwrap();
        assert!(envelope.mac.is_some());
        assert!(kagi_sync::domain::envelope::verify_response_mac(
            "response-token",
            "kgr_1",
            &envelope.ciphertext,
            envelope.mac.as_deref().unwrap(),
        ));
    }

    #[tokio::test]
    async fn test_create_project_requires_admin_token() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects", "POST");
        plaintext.project_id = Some("kgp_new".into());
        plaintext.payload = json!({"remote": "http://127.0.0.1:13816"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = create_project_handler(State(state), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_create_project_uses_request_remote_in_token() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let admin_token = "admin_secret";
        let token_hash = state.hash_token(admin_token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects", "POST");
        plaintext.project_id = Some("kgp_new".into());
        plaintext.token = Some(admin_token.into());
        plaintext.payload = json!({"remote": "https://kagi.example.com"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = create_project_handler(State(state), Json(envelope))
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response_envelope: ResponseEnvelope = serde_json::from_slice(&body).unwrap();
        let ciphertext =
            kagi_sync::domain::project_token::base64_decode_url(&response_envelope.ciphertext)
                .unwrap();
        let decrypted = kagi_sync::infrastructure::remote_envelope::decrypt_response(
            &ciphertext,
            &client_identity,
        )
        .unwrap();
        let project_token = decrypted["data"]["project_token"].as_str().unwrap();
        let parsed = ProjectToken::parse(project_token).unwrap();
        assert_eq!(parsed.payload.remote, "https://kagi.example.com");
    }

    #[tokio::test]
    async fn test_authenticate_admin_valid_token() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let token = "admin_secret";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let (token_id, caps) = authenticate_admin(&state, token).await.unwrap();
        assert_eq!(token_id, "kat_123");
        assert_eq!(caps, vec!["admin"]);
    }

    #[tokio::test]
    async fn test_authenticate_admin_invalid_token() {
        let repo = test_repo().await;
        let state = test_state(repo);
        state
            .repo
            .create_admin_token("kat_123", "hash_val", "[\"admin\"]", "2026-01-01T00:00:00Z")
            .await
            .unwrap();

        let err = authenticate_admin(&state, "wrong_token").await.unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_handler_request_id_mismatch() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/requests", "POST");
        plaintext.request_id = "tampered".into();
        let mut envelope = make_envelope(&state, &plaintext, &client_identity);
        envelope.request_id = "kgr_1".into();

        let err = create_project_request_handler(State(state), dummy_addr(), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::BadEnvelope(_)));
    }

    #[tokio::test]
    async fn test_handler_push_missing_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_handler_push_invalid_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        plaintext.token = Some("wrong_token".into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_handler_push_wrong_capability() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_only_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"base_revision": 0, "state": {"project_id": "kgp_test", "revision": 1, "kagi_json": "{}", "access_json": "{}", "files": []}});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_push_cross_project_token() {
        let repo = test_repo().await;
        repo.create_project("kgp_a").await.unwrap();
        repo.create_project("kgp_b").await.unwrap();
        let state = test_state(repo);
        let token = "project_a_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_a",
                "kgt_123",
                &token_hash,
                "[\"push\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_b/push", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"base_revision": 0, "state": {"project_id": "kgp_b", "revision": 1, "kagi_json": "{}", "access_json": "{}", "files": []}});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_b".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_handler_push_exceeds_file_count_limit() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "push_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"push\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let files: Vec<_> = (0..1001)
            .map(|i| kagi_sync::domain::project_state::ProjectFile {
                path: format!("secrets/a{i}.enc"),
                content: "x".into(),
                sha256: None,
            })
            .collect();
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({
            "base_revision": 0,
            "state": {
                "project_id": "kgp_test",
                "revision": 1,
                "kagi_json": "{}",
                "access_json": "{}",
                "files": files
            }
        });
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::PayloadTooLarge));
    }

    #[tokio::test]
    async fn test_handler_push_exceeds_total_size_limit() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "push_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"push\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let files = vec![kagi_sync::domain::project_state::ProjectFile {
            path: "secrets/big.enc".into(),
            content: "x".repeat(50 * 1024 * 1024 + 1),
            sha256: None,
        }];
        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/push", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({
            "base_revision": 0,
            "state": {
                "project_id": "kgp_test",
                "revision": 1,
                "kagi_json": "{}",
                "access_json": "{}",
                "files": files
            }
        });
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::PayloadTooLarge));
    }

    #[tokio::test]
    async fn test_handler_pull_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/pull", "POST");
        plaintext.token = Some(token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = pull_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_pull_tokenless_claim_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);

        let client_identity = x25519::Identity::generate();
        let client_recipient = client_identity.to_public().to_string();
        let claim_secret = "secret_123";
        let claim_secret_hash = crate::server::state::hash_claim_secret(claim_secret);
        state
            .repo
            .create_project_member(crate::sqlite_remote::CreateProjectMemberRequest {
                project_id: "kgp_test",
                member_id: "kgm_alice",
                name: "Alice",
                role: "admin",
                status: "active",
                recipient: &client_recipient,
                claim_secret_hash: &claim_secret_hash,
            })
            .await
            .unwrap();

        let wrapped = b"wrapped_token_bytes";
        let wrapped_b64 = base64_encode_url(wrapped);
        state
            .repo
            .save_wrapped_project_token("kgp_test", "kgm_alice", &wrapped_b64)
            .await
            .unwrap();

        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/pull", "POST");
        plaintext.token = None;
        plaintext.claim_secret = Some(claim_secret.into());
        plaintext.payload = json!({"member_id": "kgm_alice"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = pull_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Verify response body contains MAC and wrapped token
        let body_bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let response_envelope: ResponseEnvelope = serde_json::from_slice(&body_bytes).unwrap();
        assert!(response_envelope.mac.is_some());
        assert!(!response_envelope.ciphertext.is_empty());

        // Verify MAC using claim_secret
        let mac = response_envelope.mac.unwrap();
        assert!(verify_response_mac(
            claim_secret,
            &response_envelope.request_id,
            &response_envelope.ciphertext,
            &mac
        ));
    }

    #[tokio::test]
    async fn test_handler_pull_tokenless_claim_wrong_secret_fails() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);

        let client_identity = x25519::Identity::generate();
        let client_recipient = client_identity.to_public().to_string();
        let claim_secret = "secret_123";
        let claim_secret_hash = crate::server::state::hash_claim_secret(claim_secret);
        state
            .repo
            .create_project_member(crate::sqlite_remote::CreateProjectMemberRequest {
                project_id: "kgp_test",
                member_id: "kgm_alice",
                name: "Alice",
                role: "admin",
                status: "active",
                recipient: &client_recipient,
                claim_secret_hash: &claim_secret_hash,
            })
            .await
            .unwrap();

        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/pull", "POST");
        plaintext.token = None;
        plaintext.claim_secret = Some("wrong_secret".into());
        plaintext.payload = json!({"member_id": "kgm_alice"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = pull_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_status_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/status", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"local_revision": 0});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = status_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_join_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "join_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"join\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let bob_identity = x25519::Identity::generate();
        let signing_public_key = test_public_key_b64(&test_signing_key());
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/join", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"join_request": {
            "member_id": "kgm_bob",
            "name": "Bob",
            "recipient": bob_identity.to_public().to_string(),
            "signing_public_key": signing_public_key.clone(),
        }});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = join_handler(
            State(state.clone()),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let requests = state.repo.list_join_requests("kgp_test").await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].3.as_deref(), Some(signing_public_key.as_str()));
    }

    #[tokio::test]
    async fn test_handler_token_issue_requires_rotate() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/tokens/issue", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"capabilities": ["pull"]});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = token_issue_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_token_revoke_requires_rotate() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/tokens/revoke", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"token_ids": ["kgt_123"]});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = token_revoke_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_create_project_request_success() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let client_identity = x25519::Identity::generate();
        let alice_recipient = client_identity.to_public().to_string();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/requests", "POST");
        plaintext.project_id = Some("kgp_new".into());
        plaintext.payload = json!({"requester_member_id": "kgm_alice", "requester_name": "Alice", "requester_recipient": alice_recipient, "claim_secret_hash": "cs:test"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = create_project_request_handler(State(state), dummy_addr(), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_list_project_requests_admin_success() {
        let repo = test_repo().await;
        repo.create_project_request("kgp_req", "kgm_alice", "Alice", "age1...", "cs:test", None)
            .await
            .unwrap();
        let state = test_state(repo);
        let admin_token = "admin_secret";
        let token_hash = state.hash_token(admin_token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/requests/list", "POST");
        plaintext.token = Some(admin_token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = list_project_requests_handler(State(state), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_list_project_requests_non_admin_fails() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let plain_token = "plain_token";
        let token_hash = state.hash_token(plain_token);
        state
            .repo
            .create_admin_token("kat_123", &token_hash, "[\"read\"]", "2026-01-01T00:00:00Z")
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/requests/list", "POST");
        plaintext.token = Some(plain_token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = list_project_requests_handler(State(state), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_approve_project_request_success() {
        let repo = test_repo().await;
        let alice_identity = x25519::Identity::generate();
        let alice_recipient = alice_identity.to_public().to_string();
        repo.create_project_request(
            "kgp_req",
            "kgm_alice",
            "Alice",
            &alice_recipient,
            "cs:test",
            None,
        )
        .await
        .unwrap();
        let state = test_state(repo);
        let admin_token = "admin_secret";
        let token_hash = state.hash_token(admin_token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/requests/kgp_req/approve", "POST");
        plaintext.token = Some(admin_token.into());
        plaintext.payload = json!({"remote": "https://kagi.example.com"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = approve_project_request_handler(
            State(state),
            AxumPath("kgp_req".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_list_projects_admin_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_a").await.unwrap();
        let state = test_state(repo);
        let admin_token = "admin_secret";
        let token_hash = state.hash_token(admin_token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/list", "POST");
        plaintext.token = Some(admin_token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = list_projects_handler(State(state), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_delete_project_admin_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let admin_token = "admin_secret";
        let token_hash = state.hash_token(admin_token);
        state
            .repo
            .create_admin_token(
                "kat_123",
                &token_hash,
                "[\"admin\"]",
                "2026-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/delete", "POST");
        plaintext.token = Some(admin_token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = delete_project_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_delete_project_project_admin_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_project_member(crate::sqlite_remote::CreateProjectMemberRequest {
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
        let state = test_state(repo);
        let token = "bob_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_bob",
                &token_hash,
                "[\"pull\"]",
                Some("kgm_bob"),
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/delete", "POST");
        plaintext.token = Some(token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = delete_project_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_delete_project_regular_member_fails() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_project_member(crate::sqlite_remote::CreateProjectMemberRequest {
            project_id: "kgp_test",
            member_id: "kgm_bob",
            name: "Bob",
            role: "member",
            status: "active",
            recipient: "age1...",
            claim_secret_hash: "cs:test",
        })
        .await
        .unwrap();
        let state = test_state(repo);
        let token = "bob_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_bob",
                &token_hash,
                "[\"pull\"]",
                Some("kgm_bob"),
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/delete", "POST");
        plaintext.token = Some(token.into());
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = delete_project_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_health_check() {
        let response = health_check_handler().await;
        let axum_response = response.into_response();
        assert_eq!(axum_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_server_key() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let response = server_key_handler(State(state)).await;
        let axum_response = response.into_response();
        assert_eq!(axum_response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_malformed_ciphertext() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let envelope = RequestEnvelope {
            version: 1,
            request_id: "kgr_1".into(),
            server_key_id: state.server_key_id.clone(),
            response_recipient: x25519::Identity::generate().to_public().to_string(),
            ciphertext: "not_valid_base64!!!".into(),
        };

        let err = push_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::DecryptFailed(_)));
    }

    #[tokio::test]
    async fn test_handler_token_list_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "rotate_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"rotate\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/tokens/list", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = token_list_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_token_list_requires_rotate() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        let state = test_state(repo);
        let token = "pull_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_token(
                "kgp_test",
                "kgt_123",
                &token_hash,
                "[\"pull\"]",
                None,
                "active",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/tokens/list", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = token_list_handler(
            State(state),
            AxumPath("kgp_test".into()),
            dummy_addr(),
            Json(envelope),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_audit_success() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let token = "admin_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_admin_token(
                "kgt_admin",
                &token_hash,
                "[\"admin\"]",
                "2024-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/audit", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"limit": 10});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = audit_handler(State(state), dummy_addr(), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_audit_requires_admin() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let token = "admin_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_admin_token(
                "kgt_admin",
                &token_hash,
                "[\"rotate\"]",
                "2024-01-01T00:00:00Z",
            )
            .await
            .unwrap();

        let client_identity = x25519::Identity::generate();
        let mut plaintext = plaintext_now("kgr_1", "/v1/audit", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"limit": 10});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = audit_handler(State(state), dummy_addr(), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::Forbidden));
    }

    #[tokio::test]
    async fn test_handler_metrics_no_auth() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let headers = axum::http::HeaderMap::new();
        let err = metrics_handler(State(state), headers).await.unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
    }

    #[tokio::test]
    async fn test_handler_metrics_with_admin_token() {
        let repo = test_repo().await;
        let state = test_state(repo);
        let token = "admin_token";
        let token_hash = state.hash_token(token);
        state
            .repo
            .create_admin_token(
                "kgt_admin",
                &token_hash,
                "[\"admin\"]",
                "2024-01-01T00:00:00Z",
            )
            .await
            .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        let resp = metrics_handler(State(state), headers).await.unwrap();
        let (parts, body) = resp.into_response().into_parts();
        assert_eq!(parts.status, 200);
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["active_projects"], 0);
        assert_eq!(json["active_tokens"], 0);
        assert_eq!(json["active_admins"], 1);
        assert!(json["db_size"].as_i64().unwrap() > 0);
    }
}
