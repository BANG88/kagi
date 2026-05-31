pub mod errors;
pub mod routes;
pub mod state;

use crate::server::state::AppState;
use std::net::SocketAddr;
use std::path::Path;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

pub async fn serve(
    bind: SocketAddr,
    db_path: &Path,
    key_file_path: &Path,
    max_body_size: usize,
) -> Result<(), anyhow::Error> {
    let state = AppState::new(db_path, key_file_path).await?;

    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(30)
        .finish()
        .unwrap();

    let app = routes::router(state.clone())
        .layer(GovernorLayer::new(governor_conf))
        .layer(RequestBodyLimitLayer::new(max_body_size))
        .layer(TraceLayer::new_for_http());

    tracing::info!("kagi: server key fingerprint {}", state.fingerprint);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    println!("kagi: server running on http://{addr}");
    tracing::info!("kagi: listening on http://{}", addr);

    if bind.ip().is_unspecified() || !bind.ip().is_loopback() {
        tracing::warn!(
            "kagi: server bound to public interface without HTTPS. Application-layer encryption protects payloads, but HTTPS is recommended for metadata safety."
        );
    }

    tracing::info!("kagi: server started successfully");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    async fn spawn_test_server(
        max_body_size: usize,
    ) -> (SocketAddr, tempfile::TempDir, tempfile::TempDir) {
        let db_dir = tempfile::TempDir::new().unwrap();
        let key_dir = tempfile::TempDir::new().unwrap();
        let db_path = db_dir.path().join("server.db");
        let key_path = key_dir.path().join("server.key");

        let state = AppState::new(&db_path, &key_path).await.unwrap();
        let governor_conf = GovernorConfigBuilder::default()
            .per_second(60)
            .burst_size(100)
            .finish()
            .unwrap();
        let app = routes::router(state)
            .layer(GovernorLayer::new(governor_conf))
            .layer(RequestBodyLimitLayer::new(max_body_size))
            .layer(TraceLayer::new_for_http());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        // Give server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, db_dir, key_dir)
    }

    async fn spawn_test_server_with_rate_limit(
        max_body_size: usize,
        per_second: u64,
        burst_size: u32,
    ) -> (SocketAddr, tempfile::TempDir, tempfile::TempDir) {
        let db_dir = tempfile::TempDir::new().unwrap();
        let key_dir = tempfile::TempDir::new().unwrap();
        let db_path = db_dir.path().join("server.db");
        let key_path = key_dir.path().join("server.key");

        let state = AppState::new(&db_path, &key_path).await.unwrap();
        let governor_conf = GovernorConfigBuilder::default()
            .per_second(per_second)
            .burst_size(burst_size)
            .finish()
            .unwrap();
        let app = routes::router(state)
            .layer(GovernorLayer::new(governor_conf))
            .layer(RequestBodyLimitLayer::new(max_body_size))
            .layer(TraceLayer::new_for_http());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, db_dir, key_dir)
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().no_proxy().build().unwrap()
    }

    #[tokio::test]
    async fn test_health_check_endpoint() {
        let (addr, _db_dir, _key_dir) = spawn_test_server(10 * 1024 * 1024).await;
        let client = test_http_client();
        let resp = client.get(format!("http://{addr}/")).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("Kagi"));
        assert!(body.contains("Secure secrets"));
    }

    #[tokio::test]
    async fn test_server_key_endpoint() {
        let (addr, _db_dir, _key_dir) = spawn_test_server(10 * 1024 * 1024).await;
        let client = test_http_client();
        let resp = client
            .get(format!("http://{addr}/v1/server-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["version"], 1);
        assert!(body["server_key_id"].as_str().unwrap().starts_with("kgs_"));
        assert!(body["recipient"].as_str().unwrap().starts_with("age1"));
        assert!(!body["fingerprint"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_oversized_request_body_rejected() {
        let (addr, _db_dir, _key_dir) = spawn_test_server(1024).await;
        let client = test_http_client();
        let large_body = serde_json::json!({"data": "x".repeat(2048) });
        let resp = client
            .post(format!("http://{addr}/v1/projects/kgp_test/push"))
            .json(&large_body)
            .send()
            .await
            .unwrap();
        // RequestBodyLimitLayer returns 413 Payload Too Large
        assert_eq!(resp.status(), 413);
    }

    #[tokio::test]
    async fn test_malformed_json_rejected() {
        let (addr, _db_dir, _key_dir) = spawn_test_server(10 * 1024 * 1024).await;
        let client = test_http_client();
        let resp = client
            .post(format!("http://{addr}/v1/projects/kgp_test/push"))
            .header("Content-Type", "application/json")
            .body("not valid json {")
            .send()
            .await
            .unwrap();
        // Axum's Json extractor returns 400 Bad Request for malformed JSON
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn test_encrypted_roundtrip_create_project_request() {
        use age::x25519;
        use kagi_sync::domain::envelope::{RequestPlaintext, ResponseEnvelope};
        use kagi_sync::infrastructure::remote_envelope::{decrypt_response, encrypt_request};
        use std::str::FromStr;
        use time::OffsetDateTime;

        let (addr, _db_dir, _key_dir) = spawn_test_server(10 * 1024 * 1024).await;
        let client = test_http_client();

        // 1. Fetch server key
        let server_key_resp = client
            .get(format!("http://{addr}/v1/server-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(server_key_resp.status(), 200);
        let server_key: serde_json::Value = server_key_resp.json().await.unwrap();
        let server_recipient_str = server_key["recipient"].as_str().unwrap();
        let server_recipient = x25519::Recipient::from_str(server_recipient_str).unwrap();

        // 2. Create client identity
        let client_identity = x25519::Identity::generate();
        let client_recipient = client_identity.to_public();

        // 3. Build plaintext
        let issued_at = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let alice_identity = x25519::Identity::generate();
        let alice_recipient = alice_identity.to_public().to_string();
        let plaintext = RequestPlaintext {
            version: 1,
            request_id: "kgr_test_1".into(),
            issued_at,
            operation: "create_project_request".into(),
            method: "POST".into(),
            path: "/v1/projects/requests".into(),
            project_id: Some("kgp_roundtrip".into()),
            token: None,
            claim_secret: None,
            payload: serde_json::json!({
                "requester_member_id": "kgm_alice",
                "requester_name": "Alice",
                "requester_recipient": alice_recipient,
                "claim_secret_hash": "cs:test",
            }),
        };

        // 4. Encrypt request
        let envelope = encrypt_request(&plaintext, &server_recipient, &client_recipient).unwrap();
        let server_key_id = server_key["server_key_id"].as_str().unwrap();
        let mut envelope = envelope;
        envelope.server_key_id = server_key_id.into();

        // 5. Send encrypted request
        let resp = client
            .post(format!("http://{addr}/v1/projects/requests"))
            .json(&envelope)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        // 6. Parse and decrypt response
        let response_envelope: ResponseEnvelope = resp.json().await.unwrap();
        assert_eq!(response_envelope.request_id, "kgr_test_1");

        let ciphertext =
            kagi_sync::domain::project_token::base64_decode_url(&response_envelope.ciphertext)
                .unwrap();
        let decrypted = decrypt_response(&ciphertext, &client_identity).unwrap();
        assert_eq!(decrypted["ok"], true);
        assert_eq!(decrypted["data"]["project_id"], "kgp_roundtrip");
        assert_eq!(decrypted["data"]["status"], "pending");
    }

    #[tokio::test]
    async fn test_rate_limit_rejects_excess_requests() {
        let (addr, _db_dir, _key_dir) =
            spawn_test_server_with_rate_limit(10 * 1024 * 1024, 1, 1).await;
        let client = test_http_client();

        // First request should succeed
        let resp1 = client
            .get(format!("http://{addr}/v1/server-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp1.status(), 200);

        // Immediate second request should be rate limited (429)
        let resp2 = client
            .get(format!("http://{addr}/v1/server-key"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp2.status(), 429);
    }

    #[tokio::test]
    async fn test_metrics_endpoint_requires_auth() {
        let (addr, _db_dir, _key_dir) = spawn_test_server(10 * 1024 * 1024).await;
        let client = test_http_client();
        // No auth header -> should fail
        let resp = client
            .get(format!("http://{addr}/v1/metrics"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401);
    }
}
