//! [`HumanCheck`].

use std::time::{SystemTime, UNIX_EPOCH};

use altcha::{
    Challenge, CreateChallengeOptions, Payload, VerifySolutionOptions, create_challenge,
    verify_server_signature, verify_solution,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rand::RngExt;

use crate::HumanCheckError;
use crate::altcha_payload::AltchaPayload;

const DEFAULT_ALGORITHM: &str = "PBKDF2/SHA-256";
const DEFAULT_COST: u32 = 5_000;
#[cfg(test)]
// Kept low so the roundtrip test's solve time (which iterates up to the random
// counter, running PBKDF2 per attempt) stays far below the solver's 90s timeout
// regardless of the drawn counter — otherwise the test flakes under load.
const TEST_COST: u32 = 10;
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
    ///
    /// Call this once while starting up and let the error stop the process.
    /// There are only two safe outcomes for bot protection on a public form:
    /// configured, or switched off on purpose. Quietly settling for "off"
    /// because a secret is missing leaves the form open with nothing in the logs
    /// to say so, which is how an unprotected form survives a deploy.
    ///
    /// # Errors
    ///
    /// [`HumanCheckError::Config`] when the check is not explicitly disabled and
    /// either secret is absent or shorter than 32 characters.
    pub fn from_env() -> Result<Self, HumanCheckError> {
        if env_truthy("HUMAN_CHECK_DISABLED") {
            tracing::warn!(
                "human check disabled by HUMAN_CHECK_DISABLED; public forms accept submissions \
                 without verification"
            );
            return Ok(Self::disabled());
        }
        let hmac_secret = std::env::var("HUMAN_CHECK_HMAC_SECRET").unwrap_or_default();
        let key_secret = std::env::var("HUMAN_CHECK_KEY_SECRET").unwrap_or_default();
        if let Some(problem) = secret_problem("HUMAN_CHECK_HMAC_SECRET", &hmac_secret)
            .or_else(|| secret_problem("HUMAN_CHECK_KEY_SECRET", &key_secret))
        {
            return Err(HumanCheckError::Config(format!(
                "{problem}; set both secrets or set HUMAN_CHECK_DISABLED=true to accept \
                 unverified submissions"
            )));
        }
        Ok(Self {
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
        })
    }

    /// Explicit configuration for tests.
    #[cfg(test)]
    #[must_use]
    fn enabled_for_tests(hmac_secret: &str, key_secret: &str) -> Self {
        Self {
            enabled: true,
            hmac_secret: hmac_secret.to_string(),
            key_secret: key_secret.to_string(),
            cost: TEST_COST,
            ttl_secs: DEFAULT_TTL_SECS,
        }
    }

    /// A check that accepts every submission, for tests and for callers that
    /// have already decided to run a form unverified. Production code should go
    /// through [`from_env`](Self::from_env) so the choice comes from the
    /// environment and gets logged.
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

    /// Whether submissions are verified; templates use this to decide if the
    /// widget belongs on the form.
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
    ///
    /// A no-op when the check is disabled, which [`from_env`](Self::from_env)
    /// only allows as a deliberate choice.
    ///
    /// # Errors
    ///
    /// [`HumanCheckError::Missing`] for an empty field (the widget had not
    /// finished), [`HumanCheckError::Rejected`] for a payload that does not
    /// verify. Pass either to [`crate::rejection_message`] for wording safe to
    /// show a visitor.
    pub fn verify_payload(&self, payload_b64: &str) -> Result<(), HumanCheckError> {
        if !self.enabled {
            return Ok(());
        }
        let trimmed = payload_b64.trim();
        if trimmed.is_empty() {
            return Err(HumanCheckError::Missing);
        }
        let bytes = BASE64
            .decode(trimmed)
            .map_err(|_| HumanCheckError::Rejected)?;
        let verified = match serde_json::from_slice::<AltchaPayload>(&bytes)? {
            AltchaPayload::Client(payload) => verify_client_payload(self, &payload)?,
            AltchaPayload::ServerSignature(payload) => {
                verify_server_signature(&payload, &self.hmac_secret)
                    .map_err(HumanCheckError::from)?
                    .verified
            }
        };
        if !verified {
            return Err(HumanCheckError::Rejected);
        }
        Ok(())
    }
}

/// What is wrong with `value` as a secret, or `None` when it is usable.
fn secret_problem(name: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(format!("{name} is not set"));
    }
    if value.len() < MIN_SECRET_LEN {
        return Some(format!(
            "{name} is {} characters; at least {MIN_SECRET_LEN} are required",
            value.len()
        ));
    }
    None
}

fn verify_client_payload(check: &HumanCheck, payload: &Payload) -> Result<bool, HumanCheckError> {
    let result = verify_solution(VerifySolutionOptions {
        hmac_key_signature_secret: Some(check.key_secret.clone()),
        ..VerifySolutionOptions::new(&payload.challenge, &payload.solution, &check.hmac_secret)
    })?;
    Ok(result.verified)
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

    /// Every `from_env` case has to run with the whole variable set controlled,
    /// or a secret left in the developer's shell decides the outcome.
    fn with_env(vars: [(&str, Option<&str>); 3], assert: impl FnOnce()) {
        temp_env::with_vars(vars, assert);
    }

    #[test]
    fn disabled_skips_verification() {
        let check = HumanCheck::disabled();
        assert!(!check.is_enabled());
        check.verify_payload("").expect("skip when disabled");
    }

    #[test]
    fn from_env_refuses_to_start_without_secrets() {
        with_env(
            [
                ("HUMAN_CHECK_DISABLED", None),
                ("HUMAN_CHECK_HMAC_SECRET", None),
                ("HUMAN_CHECK_KEY_SECRET", None),
            ],
            || {
                let err = HumanCheck::from_env()
                    .expect_err("an unconfigured public form must not come up unprotected");
                let HumanCheckError::Config(message) = err else {
                    panic!("expected a configuration error");
                };
                assert!(message.contains("HUMAN_CHECK_HMAC_SECRET"), "{message}");
                assert!(message.contains("HUMAN_CHECK_DISABLED"), "{message}");
            },
        );
    }

    #[test]
    fn from_env_refuses_a_too_short_secret() {
        with_env(
            [
                ("HUMAN_CHECK_DISABLED", None),
                ("HUMAN_CHECK_HMAC_SECRET", Some(HMAC)),
                ("HUMAN_CHECK_KEY_SECRET", Some("too-short")),
            ],
            || {
                let err = HumanCheck::from_env().expect_err("a 9-character secret is not a secret");
                assert!(
                    matches!(&err, HumanCheckError::Config(m) if m.contains("HUMAN_CHECK_KEY_SECRET")),
                    "got {err:?}"
                );
            },
        );
    }

    #[test]
    fn from_env_enables_with_both_secrets() {
        with_env(
            [
                ("HUMAN_CHECK_DISABLED", None),
                ("HUMAN_CHECK_HMAC_SECRET", Some(HMAC)),
                ("HUMAN_CHECK_KEY_SECRET", Some(KEY)),
            ],
            || {
                let check = HumanCheck::from_env().expect("both secrets present");
                assert!(check.is_enabled());
            },
        );
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
        with_env(
            [
                ("HUMAN_CHECK_DISABLED", Some("true")),
                ("HUMAN_CHECK_HMAC_SECRET", None),
                ("HUMAN_CHECK_KEY_SECRET", None),
            ],
            || {
                let check = HumanCheck::from_env().expect("explicitly disabled is allowed");
                assert!(!check.is_enabled());
            },
        );
    }
}
