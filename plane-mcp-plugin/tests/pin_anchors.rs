// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checks declared peer-key pins and client-identity trust anchors as the host reads MCP registrations.

use std::sync::Arc;

use busbar_contract::abi::mechanism::rendering;
use busbar_contract::plane::TrustRole;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};

/// The registration key the http need reaches each server at.
const MEMBER_TARGET: &str = "settings.*.url";
/// The registration key the http need names busbar's client identity at.
const CLIENT_IDENTITY_FROM: &str = "settings.*.client_identity";
/// The explicit structured TLS selector; the legacy identity remains its sibling.
const TLS_FROM: &str = "settings.*.tls";

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    let row = LinkedRow::of_loaded(loaded_door()).expect("the linked door states its Statement");
    load_linked(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),

            conns: ConnTable::Probe,
        },
    )
    .expect("the linked door loads")
}

/// RED on a plane whose far-end pins are not peer-key pins: the host would seal no pin, and an
#[test]
fn tls_roots_pin_peer_keys_and_local_program_has_its_own_launch_root() {
    let d = Dispatcher::new(DispatchConfig::default());
    let served = linked(&d).served();
    let pin = served
        .trust_keys
        .iter()
        .find(|k| matches!(k.role, TrustRole::Pin))
        .expect("the plane declares a pin key");
    let roots: Vec<&str> = pin
        .mechanisms
        .iter()
        .filter(|m| m.root)
        .map(|m| m.token)
        .collect();
    assert_eq!(roots, ["cert_spki", "mtls", "local_program"]);
    let unsupported = pin
        .mechanisms
        .iter()
        .find(|m| m.token == "pinned_pubkey")
        .expect("the refused mechanism remains named for config diagnostics");
    assert!(!unsupported.root && !unsupported.peer_key);
    let program = pin
        .mechanisms
        .iter()
        .find(|m| m.token == "local_program")
        .unwrap();
    assert!(
        program.root && !program.peer_key,
        "a local launch is not a TLS key"
    );
    let peer: Vec<&str> = pin
        .mechanisms
        .iter()
        .filter(|m| m.peer_key)
        .map(|m| m.token)
        .collect();
    assert_eq!(
        peer,
        ["cert_spki", "mtls"],
        "the far end's key is sealed and enforced under `cert_spki` and `mtls`"
    );
}

/// RED on a plane whose http need names no `trust_from`: an `mtls` registration's client
#[test]
fn the_http_member_need_names_structured_tls_and_legacy_identity_secret_references() {
    let d = Dispatcher::new(DispatchConfig::default());
    let served = linked(&d).served();
    let at = served
        .need_targets
        .iter()
        .position(|t| *t == MEMBER_TARGET)
        .expect("a need reaches each registered server at its url");
    assert_eq!(served.need_trust[at], TLS_FROM);
    assert_eq!(
        busbar_contract::section::member_target(served.need_trust[at]),
        Some("tls"),
        "the host reads each member's TLS bundle and unchanged sibling identity"
    );
    for half in ["cert", "key"] {
        let path = format!("{CLIENT_IDENTITY_FROM}.{half}");
        assert!(
            served.secret_refs.iter().any(|r| *r == path),
            "`{path}` is a secret reference the kernel resolves at --validate and boot: {:?}",
            served.secret_refs
        );
    }

    assert!(
        served
            .secret_refs
            .iter()
            .all(|path| !path.starts_with(TLS_FROM)),
        "public CA certificates are not secret references"
    );

    let row = LinkedRow::of_loaded(loaded_door()).expect("the linked door states its Statement");
    let read = rendering::read(&row.statement).expect("the Statement renders");
    let need = read
        .needs
        .iter()
        .find(|n| n.target_from == MEMBER_TARGET)
        .expect("the rendering states the member need");
    assert_eq!(need.trust_from, TLS_FROM);
    for half in ["cert", "key"] {
        let path = format!("{CLIENT_IDENTITY_FROM}.{half}");
        assert!(read.secret_refs.contains(&path), "{:?}", read.secret_refs);
    }
}

/// This plugin's own door, named for the loader.
fn loaded_door() -> busbar_plugin_loader::dispatch::LoadedDoor {
    let door: busbar_contract::abi::mechanism::door::DoorFn = busbar_plane_mcp::door;
    busbar_plugin_loader::dispatch::LoadedDoor::from(door)
}
