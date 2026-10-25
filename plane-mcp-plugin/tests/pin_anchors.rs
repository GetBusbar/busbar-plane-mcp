// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN OPERATOR'S PIN IS ENFORCED, AS THE HOST READS THE PLANE (THE DESIGN: the host owns pins and
//! the connector enforces them).
//!
//! The host seals a registration's pin into its member route only where the plane declares the
//! pin's mechanism a pin of the FAR END'S KEY (`PinMechanismDecl::peer_key`; busbar's
//! `registration_anchors` keeps `pin.filter(|p| p.peer_key)`), and presents a client identity only
//! where the member-target need's `trust_from` names the registration key holding it. These tests
//! read both facts back the way the loader reads a linked row: the Statement's rendering and the
//! facts the bound plane is served by.

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

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    let row = LinkedRow::of_loaded(loaded_door()).expect("the linked door states its Statement");
    load_linked(
        &row,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            // Read for its facts only: bound as a probe.
            conns: ConnTable::Probe,
        },
    )
    .expect("the linked door loads")
}

/// RED on a plane whose far-end pins are not peer-key pins: the host would seal no pin, and an
/// operator's `cert_spki` or `mtls` key would be parsed and never compared with the far end's.
/// `pinned_pubkey` names a signed manifest's issuer key (predev's posture), a root that is not the
/// far end's key.
#[test]
fn every_far_end_pin_mechanism_is_a_peer_key_pin_the_host_seals() {
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
    assert_eq!(roots, ["pinned_pubkey", "cert_spki", "mtls"]);
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
/// certificate would never be resolved or presented.
#[test]
fn the_http_member_need_names_the_client_identity_and_its_secret_references() {
    let d = Dispatcher::new(DispatchConfig::default());
    let served = linked(&d).served();
    let at = served
        .need_targets
        .iter()
        .position(|t| *t == MEMBER_TARGET)
        .expect("a need reaches each registered server at its url");
    assert_eq!(served.need_trust[at], CLIENT_IDENTITY_FROM);
    assert_eq!(
        busbar_contract::section::member_target(served.need_trust[at]),
        Some("client_identity"),
        "the host reads the identity at the registration's own key"
    );
    for half in ["cert", "key"] {
        let path = format!("{CLIENT_IDENTITY_FROM}.{half}");
        assert!(
            served.secret_refs.iter().any(|r| *r == path),
            "`{path}` is a secret reference the kernel resolves at --validate and boot: {:?}",
            served.secret_refs
        );
    }

    // The Statement's rendering (what a dropped-in plane's signed manifest carries) states the same.
    let row = LinkedRow::of_loaded(loaded_door()).expect("the linked door states its Statement");
    let read = rendering::read(&row.statement).expect("the Statement renders");
    let need = read
        .needs
        .iter()
        .find(|n| n.target_from == MEMBER_TARGET)
        .expect("the rendering states the member need");
    assert_eq!(need.trust_from, CLIENT_IDENTITY_FROM);
    for half in ["cert", "key"] {
        let path = format!("{CLIENT_IDENTITY_FROM}.{half}");
        assert!(read.secret_refs.contains(&path), "{:?}", read.secret_refs);
    }
}

/// This plugin's own door, named for the loader.
fn loaded_door() -> busbar_plugin_loader::dispatch::LoadedDoor {
    // This crate's sealed door function (`&'static Door`), taken by the loader's safe conversion.
    let door: busbar_contract::abi::mechanism::door::DoorFn = busbar_plane_mcp::door;
    busbar_plugin_loader::dispatch::LoadedDoor::from(door)
}
