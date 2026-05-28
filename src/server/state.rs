use crate::domain::sync::project_token::{ProjectToken, base64_encode_url};
use crate::infrastructure::sqlite_remote::SqliteRemoteRepository;
use age::secrecy::ExposeSecret;
use age::x25519;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

pub type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServerKeyFile {
    pub version: u8,
    pub server_key_id: String,
    pub age_identity: String,
    pub token_pepper: String,
    pub created_at: String,
}

pub struct AppState {
    pub repo: SqliteRemoteRepository,
    pub identity: x25519::Identity,
    pub server_key_id: String,
    pub fingerprint: String,
    pub token_pepper: Vec<u8>,
}

impl AppState {
    pub async fn new(db_path: &Path, key_file_path: &Path) -> Result<Arc<Self>, anyhow::Error> {
        let db_path = if db_path.is_absolute() {
            db_path.to_path_buf()
        } else {
            std::env::current_dir()?.join(db_path)
        };
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let repo = SqliteRemoteRepository::new_file(&db_path).await?;

        let key_file = if key_file_path.exists() {
            let content = fs::read_to_string(key_file_path)?;
            serde_json::from_str::<ServerKeyFile>(&content)?
        } else {
            let identity = x25519::Identity::generate();
            let pepper: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
            let server_key_id = format!("kgs_{}", nanoid::nanoid!(12));
            let key_file = ServerKeyFile {
                version: 1,
                server_key_id: server_key_id.clone(),
                age_identity: identity.to_string().expose_secret().to_string(),
                token_pepper: base64_encode_url(&pepper),
                created_at: time::OffsetDateTime::now_utc().to_string(),
            };
            if let Some(parent) = key_file_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(key_file_path, serde_json::to_string_pretty(&key_file)?)?;
            tracing::info!(
                "kagi: generated new server key file at {}",
                key_file_path.display()
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(key_file_path, fs::Permissions::from_mode(0o600))?;
            }
            key_file
        };

        let identity = x25519::Identity::from_str(&key_file.age_identity)
            .map_err(|e| anyhow::anyhow!("invalid server identity: {}", e))?;
        let fingerprint = key_file.server_key_id.clone();
        let token_pepper = base64_decode_url(&key_file.token_pepper)
            .map_err(|e| anyhow::anyhow!("invalid token pepper: {}", e))?;

        let has_admin = repo
            .has_admin_token()
            .await
            .map_err(|e| anyhow::anyhow!("failed to check admin token: {}", e))?;
        if !has_admin {
            let admin_token = ProjectToken::generate_admin_token(fingerprint.clone());
            let token_hash = {
                let mut mac =
                    HmacSha256::new_from_slice(&token_pepper).expect("HMAC key size valid");
                mac.update(admin_token.full_token.as_bytes());
                let result = mac.finalize();
                let hash = result.into_bytes();
                format!("kh1:{}", base64_encode_url(&hash))
            };
            let caps_json = serde_json::to_string(&admin_token.payload.capabilities)
                .map_err(|e| anyhow::anyhow!("failed to serialize capabilities: {}", e))?;
            let now = time::OffsetDateTime::now_utc().to_string();
            repo.create_admin_token(&admin_token.payload.token_id, &token_hash, &caps_json, &now)
                .await
                .map_err(|e| anyhow::anyhow!("failed to store admin token: {}", e))?;
            println!("kagi: generated admin token: {}", admin_token.full_token);
            println!("kagi: store this in KAGI_ADMIN_TOKEN env var for admin operations");
        }

        Ok(Arc::new(Self {
            repo,
            identity,
            server_key_id: key_file.server_key_id,
            fingerprint,
            token_pepper,
        }))
    }

    pub fn hash_token(&self, full_token: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.token_pepper).expect("HMAC key size valid");
        mac.update(full_token.as_bytes());
        let result = mac.finalize();
        let hash = result.into_bytes();
        format!("kh1:{}", base64_encode_url(&hash))
    }
}

pub fn hash_claim_secret(claim_secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(claim_secret.as_bytes());
    format!("cs:{}", base64_encode_url(&hasher.finalize()))
}

fn base64_decode_url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::sqlite_remote::SqliteRemoteRepository;

    async fn test_repo() -> SqliteRemoteRepository {
        let id = rand::random::<u64>();
        let path = std::env::temp_dir().join(format!("kagi_state_test_{}.db", id));
        SqliteRemoteRepository::new_file(path).await.unwrap()
    }

    #[tokio::test]
    async fn test_hash_token_deterministic() {
        let repo = test_repo().await;
        let pepper = vec![
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 8u8, 9u8, 10u8, 11u8, 12u8, 13u8, 14u8, 15u8, 16u8,
            17u8, 18u8, 19u8, 20u8, 21u8, 22u8, 23u8, 24u8, 25u8, 26u8, 27u8, 28u8, 29u8, 30u8,
            31u8, 32u8,
        ];
        let state = AppState {
            repo,
            identity: x25519::Identity::generate(),
            server_key_id: "kgs_test".into(),
            fingerprint: "fp_test".into(),
            token_pepper: pepper.clone(),
        };

        let hash1 = state.hash_token("my_secret_token");
        let hash2 = state.hash_token("my_secret_token");
        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("kh1:"));

        let hash3 = state.hash_token("different_token");
        assert_ne!(hash1, hash3);
    }

    #[tokio::test]
    async fn test_hash_token_different_pepper() {
        let repo1 = test_repo().await;
        let repo2 = test_repo().await;
        let pepper1 = vec![0u8; 32];
        let state1 = AppState {
            repo: repo1,
            identity: x25519::Identity::generate(),
            server_key_id: "kgs_test".into(),
            fingerprint: "fp_test".into(),
            token_pepper: pepper1,
        };

        let pepper2 = vec![1u8; 32];
        let state2 = AppState {
            repo: repo2,
            identity: x25519::Identity::generate(),
            server_key_id: "kgs_test".into(),
            fingerprint: "fp_test".into(),
            token_pepper: pepper2,
        };

        let hash1 = state1.hash_token("same_token");
        let hash2 = state2.hash_token("same_token");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_base64_decode_url_roundtrip() {
        let data = b"hello world";
        let encoded = base64_encode_url(data);
        let decoded = base64_decode_url(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_decode_url_invalid() {
        assert!(base64_decode_url("!!!").is_err());
    }
}
