// ABOUTME: Error types for the divine-invite-faucet service
// ABOUTME: Maps internal errors to HTTP status codes for API responses

use fastly::http::StatusCode;
use std::fmt;

/// Unified error type for the invite faucet
#[derive(Debug)]
pub enum FaucetError {
    /// Authentication required but missing
    AuthRequired(String),
    /// Authentication provided but invalid
    AuthInvalid(String),
    /// Authenticated but not authorized (e.g. not an admin)
    Forbidden(String),
    /// Resource not found
    NotFound(String),
    /// Malformed or invalid request
    BadRequest(String),
    /// Resource already exists or conflict
    Conflict(String),
    /// KV store or backend error
    StorageError(String),
    /// Internal server error
    Internal(String),
}

impl FaucetError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            FaucetError::AuthRequired(_) => StatusCode::UNAUTHORIZED,
            FaucetError::AuthInvalid(_) => StatusCode::UNAUTHORIZED,
            FaucetError::Forbidden(_) => StatusCode::FORBIDDEN,
            FaucetError::NotFound(_) => StatusCode::NOT_FOUND,
            FaucetError::BadRequest(_) => StatusCode::BAD_REQUEST,
            FaucetError::Conflict(_) => StatusCode::CONFLICT,
            FaucetError::StorageError(_) => StatusCode::BAD_GATEWAY,
            FaucetError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            FaucetError::AuthRequired(msg) => msg,
            FaucetError::AuthInvalid(msg) => msg,
            FaucetError::Forbidden(msg) => msg,
            FaucetError::NotFound(msg) => msg,
            FaucetError::BadRequest(msg) => msg,
            FaucetError::Conflict(msg) => msg,
            FaucetError::StorageError(msg) => msg,
            FaucetError::Internal(msg) => msg,
        }
    }
}

impl fmt::Display for FaucetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for FaucetError {}

/// Result type alias for faucet operations
pub type Result<T> = std::result::Result<T, FaucetError>;
