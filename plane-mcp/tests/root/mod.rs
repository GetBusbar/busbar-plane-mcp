// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP PLANE'S ROOT CELLS, stated by the plane (busbar #1006: every linked plane door
//! states its root cells; ARCHITECT ruling on #464, the composition root names no plane).
//!
//! This file is compiled by busbar's composition root, never by this repo: the root's `build.rs`
//! reads the path this crate's `build.rs` states under its `links` name
//! (`DEP_BUSBAR_DOOR_CELLS_<CRATE>_CELLS`) and includes it as a child of its `serve` module in its
//! test build only (`super::` is `root::serve`, `crate::` is the busbar binary). The plane's own
//! `cargo test` does not build it: there is no `main.rs` here, and the kernel and the loader are the
//! root's to link, never a plane's.
//!
//! What it states:
//! - [`COLUMNS`]: the plane's capability-equality columns (`qa/capability-equality.json` `planes`).
//! - [`NOT_APPLICABLE`]: the root-leg cells the ledger marks not applicable on those columns, each
//!   with the ledger's reason word for word. The root holds the two equal, both ways.
//! - [`secret_source_driven`]: the Statement names these cells drive through the root's
//!   secret-source scan. None today: the root's `secret_source.rs` drives this door itself.
//!
//! The plane's served root cells (the ledger's `root` evidence) are still the composition root's
//! files. They move here, with their ledger citations, once the root resolves a pinned door's cells
//! from this same `links` output.

use std::sync::Arc;

use busbar_contract::abi::mechanism::door::DoorFn;

use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{load_linked, Bind, LinkedRow, NoSink};

/// The config section this plane's door owns: how its linked door is found among the root's.
const SECTION: &str = "tools";

/// THIS PLANE'S CAPABILITY-EQUALITY COLUMNS (`qa/capability-equality.json`): the cells its root leg
/// answers for.
pub(crate) const COLUMNS: &[&str] = &["mcp-client", "mcp-server"];

/// `(capability, column, reason)`: the root-leg cells this plane is NOT owed, each the ledger's own
/// not-applicable cell with its reason, word for word. The composition root holds the two equal: a
/// plane opts out of nothing the ledger says it has, and the ledger excuses nothing the plane does
/// not state.
pub(crate) const NOT_APPLICABLE: &[(&str, &str, &str)] = &[
    (
        "breaker-fastfail",
        "mcp-server",
        "the front door is inbound; admission-before-dispatch has no upstream target on this role. The only outbound a call through it triggers is the mcp-client leg (an upstream's ask is relayed to the caller, Law 11), which is that cell's evidence.",
    ),
    (
        "breaker-trip",
        "mcp-server",
        "the front door is inbound; there is no upstream target whose availability could be recorded. An upstream's sampling/roots/elicitation ask is RELAYED to the caller (Law 11), never satisfied by a model leg busbar dials, so this role triggers no outbound of its own.",
    ),
    (
        "disposition",
        "mcp-server",
        "disposition classifies an upstream's ANSWER; the inbound role has no upstream answer to classify. Rendering a refusal to a caller is the response path, not disposition.",
    ),
    (
        "egress-auth",
        "mcp-server",
        "this role has no outbound of its own: an upstream's sampling/roots/elicitation ask is relayed to the caller (Law 11), never answered by a model leg busbar would credential; inbound caller authentication is the Auth plugin's subject, not egress.",
    ),
    (
        "failover-reroute",
        "mcp-server",
        "inbound role; there is no candidate set to walk. Failover for the work this role triggers belongs to the outbound mcp-client cell (an upstream's ask is relayed to the caller, Law 11, and dials nothing).",
    ),
    (
        "net-guard",
        "mcp-server",
        "the inbound listener derives no outbound destination of its own; the destinations its work triggers are the mcp-client cell's, and an upstream's ask is relayed to the caller (Law 11), so busbar dials no model for it.",
    ),
];

/// THE SECRET-SOURCE SCAN'S DRIVEN DOOR NAMES these cells contribute: none. The composition root's
/// `secret_source.rs` drives this door itself, so the scan already holds it to a driver.
pub(crate) fn secret_source_driven() -> Vec<String> {
    Vec::new()
}

/// THE MCP DOOR: of the root's linked plane doors, the one whose Statement declares
/// [`SECTION`] (found by binding each, once). `None` is a defect, never a skip.
fn linked_door() -> Option<DoorFn> {
    static DOOR: std::sync::OnceLock<Option<DoorFn>> = std::sync::OnceLock::new();
    *DOOR.get_or_init(|| {
        let dispatcher = Arc::new(crate::root::loader::dispatch::Dispatcher::new(
            crate::root::loader::dispatch::DispatchConfig::default(),
        ));
        crate::LINKED.plane_doors.iter().copied().find(|&door| {
            let Ok(row) = LinkedRow::of(door) else {
                return false;
            };
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("mcp-door-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: crate::root::loader::dispatch::ConnTable::Probe,
                },
            )
            .is_ok_and(|plane| plane.served().section == SECTION)
        })
    })
}

/// THE DOOR IS LINKED AND STATES ITSELF: the root links a plane door owning [`SECTION`], and its
/// Statement reads with a name. The cells above answer for that door, and no other.
#[test]
fn the_root_links_the_door_these_cells_answer_for() {
    let door = linked_door().expect("the root links a plane door owning the tools section");
    let row = LinkedRow::of(door).expect("the door states itself");
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement)
        .expect("its Statement reads");
    assert!(
        !statement.name.is_empty(),
        "the door owning `{SECTION}` states no name"
    );
}

/// THE COLUMNS ARE THIS PLANE'S, AND EVERY NOT-APPLICABLE CELL IS ON ONE OF THEM: a cell stated on
/// another plane's column, or a column stated twice, is a statement about the wrong door.
#[test]
fn the_not_applicable_cells_are_on_this_planes_columns() {
    assert!(
        !COLUMNS.is_empty(),
        "the plane states no capability-equality column"
    );
    let mut seen: Vec<&str> = Vec::new();
    for column in COLUMNS {
        assert!(!seen.contains(column), "column `{column}` is stated twice");
        seen.push(*column);
    }
    for (capability, column, reason) in NOT_APPLICABLE {
        assert!(
            COLUMNS.contains(column),
            "`{capability}` is excused on `{column}`, which is not this plane's column"
        );
        assert!(
            !reason.trim().is_empty(),
            "`{capability}` x `{column}` is excused with no reason"
        );
    }
    assert!(
        secret_source_driven().is_empty(),
        "the root's secret-source scan drives this door itself"
    );
}
