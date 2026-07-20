//! Self-hosted proof-of-work human verification for public forms.
//!
//! Wraps the OSS [`altcha`](https://altcha.org) PoW protocol: the browser widget
//! solves a short challenge before submit; the server verifies cryptographically
//! with no third-party API calls.

#![forbid(unsafe_code)]

mod altcha_payload;
mod human_check;
mod human_check_error;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "warp")]
pub mod warp;

pub use human_check::HumanCheck;
pub use human_check_error::HumanCheckError;

/// User-facing message when verification fails on form submit.
#[must_use]
pub fn rejection_message(error: &HumanCheckError) -> String {
    match error {
        HumanCheckError::Missing => {
            "Please wait for verification to finish, then try again.".into()
        }
        HumanCheckError::Rejected | HumanCheckError::Altcha(_) | HumanCheckError::Json(_) => {
            "Human verification failed. Please try again.".into()
        }
        HumanCheckError::Config(_) => "Human verification is temporarily unavailable.".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_messages_are_user_safe() {
        assert!(rejection_message(&HumanCheckError::Missing).contains("wait"));
        assert!(rejection_message(&HumanCheckError::Rejected).contains("failed"));
        assert!(
            rejection_message(&HumanCheckError::Config("x".into())).contains("unavailable")
        );
    }
}
