//! Axum glue for the human-check challenge endpoint.
//!
//! Route the handler at `GET /human-check/challenge` with the shared
//! [`HumanCheck`] provided via an [`Extension`] layer.

use axum::{
    extract::Extension,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};

use crate::HumanCheck;

/// `GET /human-check/challenge` — fresh signed PoW challenge (JSON).
pub async fn challenge(Extension(check): Extension<HumanCheck>) -> Response {
    if !check.is_enabled() {
        return (StatusCode::NOT_FOUND, "human check disabled").into_response();
    }
    match check.issue_challenge() {
        Ok(challenge) => Json(challenge).into_response(),
        Err(err) => {
            tracing::error!(?err, "failed to issue human-check challenge");
            (StatusCode::INTERNAL_SERVER_ERROR, "challenge unavailable").into_response()
        }
    }
}
