use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenPayload {
    pub version: u8,
    pub remote: String,
    pub project_id: String,
    pub token_id: String,
    pub server_fingerprint: String,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_signer_public_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProjectToken {
    pub payload: TokenPayload,
    #[allow(dead_code)]
    pub full_token: String,
}

impl ProjectToken {
    pub fn parse(token: &str) -> Option<Self> {
        let prefix = if token.starts_with("kagi_proj_v1_") {
            "kagi_proj_v1_"
        } else if token.starts_with("kagi_admin_v1_") {
            "kagi_admin_v1_"
        } else {
            return None;
        };
        let rest = &token[prefix.len()..];
        let (payload_b64, secret_b64) = rest.split_once('.')?;
        let payload_json = base64_decode_url(payload_b64).ok()?;
        let payload: TokenPayload = serde_json::from_slice(&payload_json).ok()?;
        if payload.version != 1 {
            return None;
        }
        let secret = base64_decode_url(secret_b64).ok()?;
        if secret.len() != 32 {
            return None;
        }
        Some(Self {
            payload,
            full_token: token.to_string(),
        })
    }

    #[cfg(feature = "server")]
    pub fn generate(
        remote: String,
        project_id: String,
        server_fingerprint: String,
        capabilities: Vec<String>,
        bootstrap_signer_public_key: Option<String>,
    ) -> Self {
        let token_id = format!("kgt_{}", nanoid::nanoid!(12));
        let payload = TokenPayload {
            version: 1,
            remote,
            project_id: project_id.clone(),
            token_id: token_id.clone(),
            server_fingerprint: server_fingerprint.clone(),
            capabilities,
            bootstrap_signer_public_key,
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = base64_encode_url(&payload_json);
        let secret_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let secret = base64_encode_url(&secret_bytes);
        let full_token = format!("kagi_proj_v1_{payload_b64}.{secret}");
        Self {
            payload,
            full_token,
        }
    }

    #[cfg(feature = "server")]
    pub fn generate_admin_token(server_fingerprint: String) -> Self {
        let token_id = format!("kat_{}", nanoid::nanoid!(12));
        let payload = TokenPayload {
            version: 1,
            remote: "admin".into(),
            project_id: "admin".into(),
            token_id: token_id.clone(),
            server_fingerprint: server_fingerprint.clone(),
            capabilities: vec!["admin".into()],
            bootstrap_signer_public_key: None,
        };
        let payload_json = serde_json::to_vec(&payload).unwrap();
        let payload_b64 = base64_encode_url(&payload_json);
        let secret_bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let secret = base64_encode_url(&secret_bytes);
        let full_token = format!("kagi_admin_v1_{payload_b64}.{secret}");
        Self {
            payload,
            full_token,
        }
    }
}

#[cfg(feature = "server")]
pub fn base64_encode_url(input: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(input)
}

pub fn base64_decode_url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.decode(input)
}

#[cfg(feature = "server")]
pub fn normalize_member_name(name: &str) -> String {
    let trimmed = name.trim();
    let collapsed = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "server")]
    fn test_generate_and_parse_roundtrip() {
        let token = ProjectToken::generate(
            "http://localhost:13816".into(),
            "kgp_test123".into(),
            "kgs_fp123".into(),
            vec!["pull".into(), "push".into()],
            Some("signer_public_key".into()),
        );
        assert!(token.full_token.starts_with("kagi_proj_v1_"));
        assert!(token.payload.token_id.starts_with("kgt_"));

        let parsed = ProjectToken::parse(&token.full_token).unwrap();
        assert_eq!(parsed.payload.remote, token.payload.remote);
        assert_eq!(parsed.payload.project_id, token.payload.project_id);
        assert_eq!(parsed.payload.token_id, token.payload.token_id);
        assert_eq!(
            parsed.payload.server_fingerprint,
            token.payload.server_fingerprint
        );
        assert_eq!(parsed.payload.capabilities, token.payload.capabilities);
        assert_eq!(
            parsed.payload.bootstrap_signer_public_key,
            token.payload.bootstrap_signer_public_key
        );
        assert_eq!(parsed.full_token, token.full_token);
    }

    #[test]
    fn test_parse_invalid_prefix() {
        assert!(ProjectToken::parse("not_a_kagi_token").is_none());
    }

    #[test]
    fn test_parse_missing_dot() {
        assert!(ProjectToken::parse("kagi_proj_v1_abc").is_none());
    }

    #[test]
    fn test_parse_bad_base64_payload() {
        assert!(ProjectToken::parse("kagi_proj_v1_!!!.validb64").is_none());
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_parse_rejects_bad_secret() {
        let token = ProjectToken::generate(
            "http://localhost:13816".into(),
            "kgp_test123".into(),
            "kgs_fp123".into(),
            vec!["pull".into()],
            None,
        );
        let (prefix_and_payload, _) = token.full_token.rsplit_once('.').unwrap();

        assert!(ProjectToken::parse(&format!("{prefix_and_payload}.!!!")).is_none());
        assert!(
            ProjectToken::parse(&format!(
                "{}.{}",
                prefix_and_payload,
                base64_encode_url(b"short")
            ))
            .is_none()
        );
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_normalize_member_name() {
        assert_eq!(normalize_member_name("  Alice  Smith  "), "alice smith");
        assert_eq!(normalize_member_name("BOB"), "bob");
        assert_eq!(normalize_member_name("carol\tdan"), "carol dan");
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_generate_admin_token() {
        let token = ProjectToken::generate_admin_token("kgs_fp_admin".into());
        assert!(token.full_token.starts_with("kagi_admin_v1_"));
        assert!(token.payload.token_id.starts_with("kat_"));
        assert_eq!(token.payload.remote, "admin");
        assert_eq!(token.payload.project_id, "admin");
        assert_eq!(token.payload.server_fingerprint, "kgs_fp_admin");
        assert_eq!(token.payload.capabilities, vec!["admin"]);
    }

    #[test]
    #[cfg(feature = "server")]
    fn test_parse_admin_token_roundtrip() {
        let token = ProjectToken::generate_admin_token("kgs_fp_admin".into());
        let parsed = ProjectToken::parse(&token.full_token).unwrap();
        assert_eq!(parsed.payload.remote, token.payload.remote);
        assert_eq!(parsed.payload.project_id, token.payload.project_id);
        assert_eq!(parsed.payload.token_id, token.payload.token_id);
        assert_eq!(
            parsed.payload.server_fingerprint,
            token.payload.server_fingerprint
        );
        assert_eq!(parsed.payload.capabilities, token.payload.capabilities);
        assert_eq!(parsed.full_token, token.full_token);
    }
}
