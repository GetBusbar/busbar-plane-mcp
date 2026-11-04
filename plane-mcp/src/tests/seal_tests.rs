// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed form: it round-trips, and any change to it is refused.

use super::*;

/// A deterministic stand-in for the host's signature: the payload's SHA-256 digest encoded as 64 hexadecimal bytes.
fn sign(payload: &[u8]) -> Option<Vec<u8>> {
    let hex = busbar_contract::redacted::sha256_hex(payload);
    Some(hex.as_bytes()[..SIGNATURE_LEN].to_vec())
}

fn state() -> AskState {
    AskState {
        principal: "k".into(),
        method: "prompts/get".into(),
        capability: "bank_transfer".into(),
        args_digest: "d".into(),
        generation: 3,
        round: 0,
        nonce: "n1".into(),
        issued_at: 100,
        ttl_secs: 300,
        roots_epoch: None,
        upstream: None,
        answers: None,
    }
}

#[test]
fn a_sealed_state_opens_to_itself() {
    let blob = seal_state(&state(), &mut sign).expect("sealed");
    assert_eq!(unseal_state(&blob, &mut sign), Ok(state()));
}

#[test]
fn a_tampered_or_foreign_state_is_refused() {
    let blob = seal_state(&state(), &mut sign).expect("sealed");
    assert_eq!(
        unseal_state(&format!("{blob}-TAMPERED"), &mut sign),
        Err(Rejected::Malformed)
    );
    let (payload, sig) = blob.split_once('.').unwrap();
    let mut other = state();
    other.principal = "someone-else".into();
    let forged = format!(
        "{}.{sig}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&other).unwrap())
    );
    assert_eq!(
        unseal_state(&forged, &mut sign),
        Err(Rejected::BadSignature)
    );
    assert_eq!(unseal_state(payload, &mut sign), Err(Rejected::Malformed));
    assert_eq!(
        unseal_state(&blob, &mut |_| None),
        Err(Rejected::BadSignature)
    );
    assert_eq!(seal_state(&state(), &mut |_| None), None);
}

#[path = "reported_seals.rs"]
mod reported;

#[test]
fn audit_short_signature_never_invokes_host_signer() {
    let mut calls = 0;
    let mut signer = |_: &[u8]| {
        calls += 1;
        Some(vec![0; SIGNATURE_LEN])
    };
    assert!(!opens(b"payload", "YQ", &mut signer));
    assert_eq!(
        unseal_state("e30.YQ", &mut signer),
        Err(Rejected::BadSignature)
    );
    assert_eq!(calls, 0);
}
