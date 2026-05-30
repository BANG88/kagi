use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Service not found: {0}")]
    ServiceNotFound(String),
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("Invalid project key")]
    InvalidProjectKey,
    #[error("Encrypt failed: {0}")]
    EncryptFailed(String),
    #[error("Decrypt failed: {0}")]
    DecryptFailed(String),
    #[error("Store corrupted: {0}")]
    StoreCorrupted(String),
    #[error("Project token unavailable: {0}")]
    ProjectTokenUnavailable(String),
    #[error("Remote rejected request ({code}): {message}")]
    RemoteRejected { code: String, message: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
