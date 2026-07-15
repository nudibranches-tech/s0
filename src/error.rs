//! Gateway-internal error type. Mapped to `s3s::S3Error` at the protocol edge.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("policy engine error: {0}")]
    Pdp(String),

    #[error("bundle error: {0}")]
    Bundle(String),

    #[error("credential store error: {0}")]
    Credentials(String),

    #[error("sts error: {0}")]
    Sts(String),

    #[error("backend proxy error: {0}")]
    Backend(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, GatewayError>;
