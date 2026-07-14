//! [`VerifyOutcome`].

#[allow(unused_imports)]
use super::*;

/// Result of verifying a widget payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub verified: bool,
    pub expired: bool,
}
