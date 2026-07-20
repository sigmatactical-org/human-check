//! [`HumanCheckError`].

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HumanCheckError {
    #[error("human verification is required")]
    Missing,
    #[error("human verification failed")]
    Rejected,
    #[error("human verification misconfigured: {0}")]
    Config(String),
    #[error(transparent)]
    Altcha(#[from] altcha::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
