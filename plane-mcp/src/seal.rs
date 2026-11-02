// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEALED `requestState`: busbar's own ask state, minted and opened by the door over the host's

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use busbar_contract::redacted::constant_time_eq;

use crate::ask::{AskState, Rejected};

/// The signature length the host's `sign` answers.
pub const SIGNATURE_LEN: usize = 64;

/// The sealed form of `state`, signed by `sign`; `None` when it cannot be signed.
pub fn seal_state(
    state: &AskState,
    sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Option<String> {
    let payload = serde_json::to_vec(state).ok()?;
    let signature = sign(&payload).filter(|signature| signature.len() == SIGNATURE_LEN)?;
    Some(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

/// The state `blob` seals, its signature re-made by `sign` and compared in constant time.
pub fn unseal_state(
    blob: &str,
    sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>,
) -> Result<AskState, Rejected> {
    let (payload, signature) = blob.split_once('.').ok_or(Rejected::Malformed)?;
    let payload = strict(payload).ok_or(Rejected::Malformed)?;
    let presented = strict(signature).ok_or(Rejected::Malformed)?;
    let made = sign(&payload).ok_or(Rejected::BadSignature)?;
    if presented.len() != SIGNATURE_LEN || !constant_time_eq(&presented, &made) {
        return Err(Rejected::BadSignature);
    }
    serde_json::from_slice(&payload).map_err(|_| Rejected::Malformed)
}

/// THE PLANE'S SEAL OVER `data`: the host's signature of it, `base64url`, unpadded; `None` when it
pub fn seal_bytes(data: &[u8], sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>) -> Option<String> {
    Some(URL_SAFE_NO_PAD.encode(sign(data).filter(|signature| signature.len() == SIGNATURE_LEN)?))
}

/// Whether `presented` is the seal over `data` ([`seal_bytes`]): the signature re-made by `sign` and
pub fn opens(data: &[u8], presented: &str, sign: &mut dyn FnMut(&[u8]) -> Option<Vec<u8>>) -> bool {
    let (Some(presented), Some(made)) = (strict(presented), sign(data)) else {
        return false;
    };
    presented.len() == SIGNATURE_LEN && constant_time_eq(&presented, &made)
}

/// `text` decoded as unpadded base64url, and only when it is that value's one spelling.
fn strict(text: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(text).ok()?;
    (URL_SAFE_NO_PAD.encode(&bytes) == text).then_some(bytes)
}

#[cfg(test)]
#[path = "tests/seal_tests.rs"]
mod tests;
