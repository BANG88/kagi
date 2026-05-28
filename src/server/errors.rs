use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug)]
pub enum ServerError {
    BadRequest(String),
    BadEnvelope(String),
    DecryptFailed(String),
    AuthFailed,
    Forbidden,
    NotFound,
    Conflict {
        code: String,
        message: String,
        details: Option<serde_json::Value>,
    },
    InvalidPath(String),
    InvalidRevision,
    InvalidProjectState(String),
    ServerKeyMismatch,
    Internal(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, code, message, details): (
            StatusCode,
            &str,
            String,
            Option<serde_json::Value>,
        ) = match &self {
            ServerError::BadRequest(msg) => {
                (StatusCode::BAD_REQUEST, "bad_request", msg.clone(), None)
            }
            ServerError::BadEnvelope(msg) => {
                (StatusCode::BAD_REQUEST, "bad_envelope", msg.clone(), None)
            }
            ServerError::DecryptFailed(msg) => {
                (StatusCode::BAD_REQUEST, "decrypt_failed", msg.clone(), None)
            }
            ServerError::AuthFailed => (
                StatusCode::UNAUTHORIZED,
                "auth_failed",
                "authentication failed".into(),
                None,
            ),
            ServerError::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "insufficient capabilities".into(),
                None,
            ),
            ServerError::NotFound => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource not found".into(),
                None,
            ),
            ServerError::Conflict {
                code,
                message,
                details,
            } => {
                return (StatusCode::CONFLICT, Json(json!({"ok": false, "error": {"code": code, "message": message, "details": details}}))).into_response();
            }
            ServerError::InvalidPath(msg) => {
                (StatusCode::BAD_REQUEST, "invalid_path", msg.clone(), None)
            }
            ServerError::InvalidRevision => (
                StatusCode::BAD_REQUEST,
                "invalid_revision",
                "revision mismatch".into(),
                None,
            ),
            ServerError::InvalidProjectState(msg) => (
                StatusCode::BAD_REQUEST,
                "invalid_project_state",
                msg.clone(),
                None,
            ),
            ServerError::ServerKeyMismatch => (
                StatusCode::BAD_REQUEST,
                "server_key_mismatch",
                "unknown server key".into(),
                None,
            ),
            ServerError::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                msg.clone(),
                None,
            ),
        };

        let body = Json(json!({
            "ok": false,
            "error": { "code": code, "message": message, "details": details }
        }));
        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    fn status_of(err: ServerError) -> StatusCode {
        err.into_response().status()
    }

    #[test]
    fn test_bad_request_status() {
        assert_eq!(
            status_of(ServerError::BadRequest("x".into())),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn test_auth_failed_status() {
        assert_eq!(status_of(ServerError::AuthFailed), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_forbidden_status() {
        assert_eq!(status_of(ServerError::Forbidden), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_not_found_status() {
        assert_eq!(status_of(ServerError::NotFound), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_conflict_status() {
        let err = ServerError::Conflict {
            code: "c".into(),
            message: "m".into(),
            details: None,
        };
        assert_eq!(status_of(err), StatusCode::CONFLICT);
    }

    #[test]
    fn test_internal_status() {
        assert_eq!(
            status_of(ServerError::Internal("x".into())),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }
}
