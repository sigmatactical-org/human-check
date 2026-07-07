//! Self-hosted proof-of-work human verification for public forms.
//!
//! Wraps the OSS [`altcha`](https://altcha.org) PoW protocol: the browser widget
//! solves a short challenge before submit; the server verifies cryptographically
//! with no third-party API calls.

use std::time::{SystemTime, UNIX_EPOCH};

use altcha::{
    Challenge, CreateChallengeOptions, Payload, ServerSignaturePayload, VerifySolutionOptions,
    create_challenge, verify_server_signature, verify_solution,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::Rng;
use thiserror::Error;

const DEFAULT_ALGORITHM: &str = "PBKDF2/SHA-256";
const DEFAULT_COST: u32 = 5_000;
const TEST_COST: u32 = 1_000;
const DEFAULT_TTL_SECS: u64 = 600;
const MIN_SECRET_LEN: usize = 32;

/// Configuration loaded from environment (see [`HumanCheck::from_env`]).
#[derive(Clone, Debug)]
pub struct HumanCheck {
    enabled: bool,
    hmac_secret: String,
    key_secret: String,
    cost: u32,
    ttl_secs: u64,
}

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

/// Result of verifying a widget payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub verified: bool,
    pub expired: bool,
}

impl HumanCheck {
    /// Load settings from the environment.
    ///
    /// | Variable | Purpose |
    /// | --- | --- |
    /// | `HUMAN_CHECK_DISABLED` | When `true`, verification is skipped |
    /// | `HUMAN_CHECK_HMAC_SECRET` | HMAC secret (≥32 chars) when enabled |
    /// | `HUMAN_CHECK_KEY_SECRET` | Key signature secret (≥32 chars) when enabled |
    /// | `HUMAN_CHECK_COST` | PoW cost (default `5000`) |
    /// | `HUMAN_CHECK_TTL_SECS` | Challenge lifetime in seconds (default `600`) |
    #[must_use]
    pub fn from_env() -> Self {
        if env_truthy("HUMAN_CHECK_DISABLED") {
            return Self::disabled();
        }
        let hmac_secret = std::env::var("HUMAN_CHECK_HMAC_SECRET").unwrap_or_default();
        let key_secret = std::env::var("HUMAN_CHECK_KEY_SECRET").unwrap_or_default();
        if hmac_secret.len() < MIN_SECRET_LEN || key_secret.len() < MIN_SECRET_LEN {
            return Self::disabled();
        }
        Self {
            enabled: true,
            hmac_secret,
            key_secret,
            cost: std::env::var("HUMAN_CHECK_COST")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_COST),
            ttl_secs: std::env::var("HUMAN_CHECK_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_TTL_SECS),
        }
    }

    /// Explicit configuration for tests.
    #[must_use]
    pub fn enabled_for_tests(hmac_secret: &str, key_secret: &str) -> Self {
        Self {
            enabled: true,
            hmac_secret: hmac_secret.to_string(),
            key_secret: key_secret.to_string(),
            cost: TEST_COST,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            hmac_secret: String::new(),
            key_secret: String::new(),
            cost: DEFAULT_COST,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Issue a fresh signed challenge (JSON-serializable [`Challenge`]).
    pub fn issue_challenge(&self) -> Result<Challenge, HumanCheckError> {
        if !self.enabled {
            return Err(HumanCheckError::Config("human check is disabled".into()));
        }
        let expires_at = unix_now().saturating_add(self.ttl_secs);
        let counter = rand::rng().random_range(5_000..=10_000);
        create_challenge(CreateChallengeOptions {
            algorithm: DEFAULT_ALGORITHM.to_string(),
            cost: self.cost,
            counter: Some(counter),
            expires_at: Some(expires_at),
            hmac_signature_secret: Some(self.hmac_secret.clone()),
            hmac_key_signature_secret: Some(self.key_secret.clone()),
            ..Default::default()
        })
        .map_err(HumanCheckError::from)
    }

    /// Verify the Base64-encoded `altcha` form field from the widget.
    pub fn verify_payload(&self, payload_b64: &str) -> Result<VerifyOutcome, HumanCheckError> {
        if !self.enabled {
            return Ok(VerifyOutcome {
                verified: true,
                expired: false,
            });
        }
        let trimmed = payload_b64.trim();
        if trimmed.is_empty() {
            return Err(HumanCheckError::Missing);
        }
        let bytes = BASE64
            .decode(trimmed)
            .map_err(|_| HumanCheckError::Rejected)?;
        let outcome = match serde_json::from_slice::<AltchaPayload>(&bytes)? {
            AltchaPayload::Client(payload) => verify_client_payload(self, &payload)?,
            AltchaPayload::ServerSignature(payload) => {
                let result = verify_server_signature(&payload, &self.hmac_secret)
                    .map_err(HumanCheckError::from)?;
                VerifyOutcome {
                    verified: result.verified,
                    expired: result.expired,
                }
            }
        };
        if !outcome.verified {
            return Err(HumanCheckError::Rejected);
        }
        Ok(outcome)
    }

    /// Verify when enabled; no-op when disabled.
    pub fn verify_payload_or_skip(&self, payload_b64: &str) -> Result<(), HumanCheckError> {
        self.verify_payload(payload_b64).map(|_| ())
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum AltchaPayload {
    ServerSignature(ServerSignaturePayload),
    Client(Payload),
}

fn verify_client_payload(
    check: &HumanCheck,
    payload: &Payload,
) -> Result<VerifyOutcome, HumanCheckError> {
    let result = verify_solution(VerifySolutionOptions {
        hmac_key_signature_secret: Some(check.key_secret.clone()),
        ..VerifySolutionOptions::new(&payload.challenge, &payload.solution, &check.hmac_secret)
    })?;
    Ok(VerifyOutcome {
        verified: result.verified,
        expired: result.expired,
    })
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use altcha::{SolveChallengeOptions, solve_challenge};

    use super::*;

    const HMAC: &str = "test-hmac-secret-at-least-32-characters";
    const KEY: &str = "test-key-secret-at-least-32-characters!!";

    #[test]
    fn disabled_skips_verification() {
        let check = HumanCheck::disabled();
        assert!(!check.is_enabled());
        check
            .verify_payload_or_skip("")
            .expect("skip when disabled");
    }

    #[test]
    fn roundtrip_client_payload() {
        let check = HumanCheck::enabled_for_tests(HMAC, KEY);
        let challenge = check.issue_challenge().expect("challenge");
        let solution = solve_challenge(SolveChallengeOptions::new(&challenge))
            .expect("solve")
            .expect("solution found");
        let payload = Payload {
            challenge,
            solution,
        };
        let encoded = BASE64.encode(serde_json::to_vec(&payload).expect("json"));
        check.verify_payload(&encoded).expect("verified");
    }

    #[test]
    fn rejects_empty_payload_when_enabled() {
        let check = HumanCheck::enabled_for_tests(HMAC, KEY);
        assert!(matches!(
            check.verify_payload(""),
            Err(HumanCheckError::Missing)
        ));
    }

    #[test]
    fn from_env_disabled_flag() {
        temp_env::with_vars([("HUMAN_CHECK_DISABLED", Some("true"))], || {
            assert!(!HumanCheck::from_env().is_enabled());
        });
    }
}
