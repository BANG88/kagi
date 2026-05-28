use crate::domain::sync::envelope::{
    RequestEnvelope, RequestPlaintext, ResponseEnvelope, SuccessResponse, response_mac,
};
use crate::domain::sync::project_state::{ProjectState, validate_file_path};
use crate::domain::sync::project_token::{ProjectToken, base64_encode_url, normalize_member_name};
use crate::infrastructure::remote_envelope::{decrypt_request, encrypt_response, parse_recipient};
use crate::server::errors::ServerError;
use crate::server::state::AppState;
use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;
use std::sync::Arc;
use time::OffsetDateTime;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(health_check_handler))
        .route("/v1/server-key", get(server_key_handler))
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

async fn create_project_handler(
    State(state): State<Arc<AppState>>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects", "POST").await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps) = authenticate_admin(&state, token_str).await?;
    if !caps.iter().any(|c| c == "admin") {
        return Err(ServerError::Forbidden);
    }
    let remote_url = remote_url_from_plaintext(&plaintext, Some(token_str))?;

    let project_id = plaintext
        .project_id
        .clone()
        .unwrap_or_else(|| format!("kgp_{}", nanoid::nanoid!(12)));
    state.repo.create_project(&project_id).await.map_err(|e| {
        if e.as_database_error()
            .map(|d| d.is_unique_violation())
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
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) =
        decrypt_and_verify_envelope(&state, envelope, "/v1/projects/requests", "POST").await?;

    let project_id = plaintext
        .project_id
        .clone()
        .unwrap_or_else(|| format!("kgp_{}", nanoid::nanoid!(12)));
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
        .map_err(|e| ServerError::BadEnvelope(format!("invalid requester_recipient: {}", e)))?;
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
                .map(|d| d.is_unique_violation())
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
    let (_token_id, caps) = authenticate_admin(&state, token_str).await?;
    if !caps.iter().any(|c| c == "admin") {
        return Err(ServerError::Forbidden);
    }

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
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/requests/{}/approve", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps) = authenticate_admin(&state, token_str).await?;
    if !caps.iter().any(|c| c == "admin") {
        return Err(ServerError::Forbidden);
    }

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
    );

    let token_hash = state.hash_token(&token.full_token);
    let caps_json = serde_json::to_string(&token.payload.capabilities)
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let wrapped = crate::infrastructure::remote_envelope::encrypt_bytes(
        token.full_token.as_bytes(),
        &recipient,
    )
    .map_err(|e| ServerError::Internal(e.to_string()))?;
    let wrapped_b64 = base64_encode_url(&wrapped);

    state
        .repo
        .approve_project_request_tx(
            crate::infrastructure::sqlite_remote::ApproveProjectRequest {
                project_id: &project_id,
                requester_member_id: &requester_member_id,
                requester_name: &requester_name,
                requester_recipient: &requester_recipient,
                claim_secret_hash: &claim_secret_hash,
                token_id: &token.payload.token_id,
                token_hash: &token_hash,
                caps_json: &caps_json,
                wrapped_b64: &wrapped_b64,
            },
        )
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map(|d| d.is_unique_violation())
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
    let (_token_id, caps) = authenticate_admin(&state, token_str).await?;
    if !caps.iter().any(|c| c == "admin") {
        return Err(ServerError::Forbidden);
    }

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
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/delete", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;

    let is_admin = if let Ok((_token_id, caps)) = authenticate_admin(&state, token_str).await {
        caps.iter().any(|c| c == "admin")
    } else {
        false
    };

    if !is_admin {
        let (_token_id, _caps, member_id) = authenticate(&state, &project_id, token_str).await?;
        if let Some(member_id) = member_id {
            let role = state
                .repo
                .get_project_member_role(&project_id, &member_id)
                .await
                .map_err(|e| ServerError::Internal(e.to_string()))?;
            if role.as_deref() != Some("admin") {
                return Err(ServerError::Forbidden);
            }
        } else {
            return Err(ServerError::Forbidden);
        }
    }

    state
        .repo
        .delete_project(&project_id)
        .await
        .map_err(|e| ServerError::Internal(e.to_string()))?;

    let response_data = json!({"project_id": project_id, "status": "deleted"});
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn push_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/push", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
    if !caps.iter().any(|c| c == "push") {
        return Err(ServerError::Forbidden);
    }

    let base_revision = plaintext
        .payload
        .get("base_revision")
        .and_then(|v| v.as_i64())
        .ok_or(ServerError::InvalidRevision)?;
    let state_json = plaintext
        .payload
        .get("state")
        .ok_or(ServerError::InvalidProjectState("missing state".into()))?;
    let project_state: ProjectState = serde_json::from_value(state_json.clone())
        .map_err(|e| ServerError::InvalidProjectState(format!("{}", e)))?;

    for file in &project_state.files {
        validate_file_path(&file.path)
            .map_err(|_e| ServerError::InvalidPath("invalid file path".into()))?;
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

    let new_revision = state
        .repo
        .push_project_state(
            crate::infrastructure::sqlite_remote::PushProjectStateRequest {
                project_id: &project_id,
                base_revision,
                kagi_json: &project_state.kagi_json,
                access_json: &project_state.access_json,
                files: &project_state.files,
                activate_tokens: &activate,
                revoke_tokens: &revoke,
                accepted_joins: &accepted,
            },
        )
        .await
        .map_err(|e| {
        if matches!(e, sqlx::Error::RowNotFound) {
            ServerError::Conflict {
                code: "conflict".into(),
                message: "remote revision changed; run kagi pull first".into(),
                details: Some(json!({"remote_revision": base_revision + 1, "base_revision": base_revision})),
            }
        } else {
            ServerError::Internal(e.to_string())
        }
    })?;

    let response_data = json!({
        "revision": new_revision,
    });
    encrypt_success_response(&state, &plaintext, &response_recipient, response_data)
}

async fn pull_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/pull", project_id),
        "POST",
    )
    .await?;

    if let Some(token_str) = plaintext.token.as_ref() {
        let (_token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
        if !caps.iter().any(|c| c == "pull") {
            return Err(ServerError::Forbidden);
        }

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

        if caps.iter().any(|c| c == "push" || c == "rotate") {
            let join_requests = state
                .repo
                .list_join_requests(&project_id)
                .await
                .map_err(|e| ServerError::Internal(e.to_string()))?;
            let requests_json: Vec<serde_json::Value> = join_requests.into_iter().map(|(member_id, name, recipient, created_at)| {
                json!({"member_id": member_id, "name": name, "recipient": recipient, "created_at": created_at})
            }).collect();
            response["join_requests"] = json!(requests_json);
        }

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
        &format!("/v1/projects/{}/status", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
    if !caps.iter().any(|c| c == "pull") {
        return Err(ServerError::Forbidden);
    }

    let local_revision = plaintext
        .payload
        .get("local_revision")
        .and_then(|v| v.as_i64())
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

    let join_count = if caps.iter().any(|c| c == "push" || c == "rotate") {
        state
            .repo
            .list_join_requests(&project_id)
            .await
            .map_err(|e| ServerError::Internal(e.to_string()))?
            .len() as i64
    } else {
        0
    };

    let response = json!({
        "remote_revision": remote_revision,
        "local_revision": local_revision,
        "state": state_str,
        "pending_join_count": join_count,
    });
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn join_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/join", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
    if !caps.iter().any(|c| c == "join") {
        return Err(ServerError::Forbidden);
    }

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
    let normalized = normalize_member_name(name);

    state
        .repo
        .upsert_join_request(
            &project_id,
            member_id,
            &token_id,
            name,
            &normalized,
            recipient,
        )
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map(|d| d.is_unique_violation())
                .unwrap_or(false)
            {
                ServerError::Conflict {
                    code: "conflict".into(),
                    message: "a pending join request with this name already exists".into(),
                    details: None,
                }
            } else {
                ServerError::Internal(e.to_string())
            }
        })?;

    let response = json!({"member_id": member_id, "status": "pending"});
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn token_issue_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/tokens/issue", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
    if !caps.iter().any(|c| c == "rotate") {
        return Err(ServerError::Forbidden);
    }

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

    let token = ProjectToken::generate(
        remote_url,
        project_id.clone(),
        state.fingerprint.clone(),
        capabilities,
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
    encrypt_success_response(&state, &plaintext, &response_recipient, response)
}

async fn token_revoke_handler(
    State(state): State<Arc<AppState>>,
    AxumPath(project_id): AxumPath<String>,
    Json(envelope): Json<RequestEnvelope>,
) -> Result<axum::response::Response, ServerError> {
    let (plaintext, response_recipient) = decrypt_and_verify_envelope(
        &state,
        envelope,
        &format!("/v1/projects/{}/tokens/revoke", project_id),
        "POST",
    )
    .await?;
    let token_str = plaintext.token.as_ref().ok_or(ServerError::AuthFailed)?;
    let (_token_id, caps, _member_id) = authenticate(&state, &project_id, token_str).await?;
    if !caps.iter().any(|c| c == "rotate") {
        return Err(ServerError::Forbidden);
    }

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

    let response = json!({"revoked_token_ids": token_ids});
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
    .map_err(|e| ServerError::BadEnvelope(format!("invalid issued_at: {}", e)))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::sync::envelope::verify_response_mac;
    use crate::infrastructure::remote_envelope::encrypt_request;
    use crate::infrastructure::sqlite_remote::SqliteRemoteRepository;
    use age::x25519;

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

    async fn test_repo() -> SqliteRemoteRepository {
        let id = rand::random::<u64>();
        let path = format!("/tmp/kagi_route_test_{}.db", id);
        SqliteRemoteRepository::new(&format!("sqlite:{}", path))
            .await
            .unwrap()
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
        assert!(crate::domain::sync::envelope::verify_response_mac(
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
            crate::domain::sync::project_token::base64_decode_url(&response_envelope.ciphertext)
                .unwrap();
        let decrypted =
            crate::infrastructure::remote_envelope::decrypt_response(&ciphertext, &client_identity)
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

        let err = create_project_request_handler(State(state), Json(envelope))
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

        let err = push_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let err = push_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let err = push_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let err = push_handler(State(state), AxumPath("kgp_b".into()), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::AuthFailed));
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

        let response = pull_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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
            .create_project_member(
                crate::infrastructure::sqlite_remote::CreateProjectMemberRequest {
                    project_id: "kgp_test",
                    member_id: "kgm_alice",
                    name: "Alice",
                    role: "admin",
                    status: "active",
                    recipient: &client_recipient,
                    claim_secret_hash: &claim_secret_hash,
                },
            )
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

        let response = pull_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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
            .create_project_member(
                crate::infrastructure::sqlite_remote::CreateProjectMemberRequest {
                    project_id: "kgp_test",
                    member_id: "kgm_alice",
                    name: "Alice",
                    role: "admin",
                    status: "active",
                    recipient: &client_recipient,
                    claim_secret_hash: &claim_secret_hash,
                },
            )
            .await
            .unwrap();

        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/pull", "POST");
        plaintext.token = None;
        plaintext.claim_secret = Some("wrong_secret".into());
        plaintext.payload = json!({"member_id": "kgm_alice"});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let err = pull_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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
        let mut plaintext = plaintext_now("kgr_1", "/v1/projects/kgp_test/join", "POST");
        plaintext.token = Some(token.into());
        plaintext.payload = json!({"join_request": {"member_id": "kgm_bob", "name": "Bob", "recipient": "age1..."}});
        let envelope = make_envelope(&state, &plaintext, &client_identity);

        let response = join_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
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

        let err = token_issue_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let err = token_revoke_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let response = create_project_request_handler(State(state), Json(envelope))
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

        let response =
            delete_project_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_delete_project_project_admin_success() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_project_member(
            crate::infrastructure::sqlite_remote::CreateProjectMemberRequest {
                project_id: "kgp_test",
                member_id: "kgm_bob",
                name: "Bob",
                role: "admin",
                status: "active",
                recipient: "age1...",
                claim_secret_hash: "cs:test",
            },
        )
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

        let response =
            delete_project_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
                .await
                .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_handler_delete_project_regular_member_fails() {
        let repo = test_repo().await;
        repo.create_project("kgp_test").await.unwrap();
        repo.create_project_member(
            crate::infrastructure::sqlite_remote::CreateProjectMemberRequest {
                project_id: "kgp_test",
                member_id: "kgm_bob",
                name: "Bob",
                role: "member",
                status: "active",
                recipient: "age1...",
                claim_secret_hash: "cs:test",
            },
        )
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

        let err = delete_project_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
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

        let err = push_handler(State(state), AxumPath("kgp_test".into()), Json(envelope))
            .await
            .unwrap_err();
        assert!(matches!(err, ServerError::DecryptFailed(_)));
    }
}
