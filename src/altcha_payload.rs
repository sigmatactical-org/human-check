//! [`AltchaPayload`].

#[allow(unused_imports)]
use super::*;
use altcha::{Payload, ServerSignaturePayload};

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum AltchaPayload {
    ServerSignature(ServerSignaturePayload),
    Client(Payload),
}
