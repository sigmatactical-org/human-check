//! [`AltchaPayload`].

use altcha::{Payload, ServerSignaturePayload};

#[derive(serde::Deserialize)]
#[serde(untagged)]
pub(crate) enum AltchaPayload {
    ServerSignature(ServerSignaturePayload),
    Client(Payload),
}
