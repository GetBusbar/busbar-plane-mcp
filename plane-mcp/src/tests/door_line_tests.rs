// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The subscriptions kept on a carrier session (the stdio line carrier): bounded per caller as on
//! the HTTP carrier, and stepped under a standing and grants its caller's own units re-ask, never
//! the ones captured at open.

use serde_json::json;

use super::*;
use crate::subscribe::KEEPALIVE_NS;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}}
  }
}"#;

fn catalogue() -> Catalogue {
    Catalogue::build(
        1,
        &crate::statement::read_tools_section(SECTION).expect("the section reads"),
    )
}

/// A `toolsListChanged` subscription `owner` opened at `now_ns`.
fn opened(owner: &str, now_ns: u64) -> LineListen {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let listen = Listen::open(Some(&params), json!("sub"), now_ns, |_| false).expect("opened");
    LineListen {
        listen: Box::new(listen),
        opening_unit: 0,
        opening_ticket: Ticket::NONE,
        acknowledged: true,
        entitled: BTreeMap::new(),
        hidden: Default::default(),
        owner: owner.to_string(),
        standing: Standing::Live,
        confirmed_ns: now_ns,
        pinged_ns: now_ns,
        updates: Vec::new(),
    }
}

/// A unit of its caller re-asked at `now_ns`, its standing `standing` (as [`reconfirm`] moves it).
fn reconfirmed(kept: &mut LineListen, standing: Standing, now_ns: u64) {
    kept.entitled = BTreeMap::new();
    kept.standing = standing;
    kept.confirmed_ns = now_ns;
}

/// A LINE SUBSCRIPTION NO UNIT OF ITS CALLER RE-CONFIRMED ENDS. The kernel answers a caller's
/// standing and grants only on a unit in flight, and a line carrier's subscription outlives the
/// unit that opened it, so its caller's own lines (each a unit, the answer to busbar's `ping`
/// among them) are where they are re-asked. A caller whose identity was revoked sends none the
/// kernel admits: its stream ends with the identity refusal well inside the stream's bound,
/// never holding the grants captured at open for the whole of it.
#[test]
fn a_line_subscription_its_caller_never_reconfirms_ends_on_its_frame() {
    let cat = catalogue();
    let mut kept = opened("k", 1);
    assert!(
        matches!(kept.step_at(&cat, 1), ListenStep::Frames(_)),
        "the acknowledgement"
    );
    let later = 1 + 3 * KEEPALIVE_NS + 1;
    let step = kept.step_at(&cat, later);
    assert!(
        matches!(&step, ListenStep::End(frames)
            if frames[0]["error"]["data"]["reason"]
                == busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE),
        "a subscription its caller never re-confirmed ends with the identity refusal: {step:?}"
    );
}

/// ONE CALLER HOLDS AT MOST THE HTTP CARRIER'S COUNT OF LINE SUBSCRIPTIONS: the next is refused,
/// another caller is not.
#[test]
fn one_caller_holds_at_most_the_http_carriers_count_of_line_subscriptions() {
    let per_owner = crate::plane_door::door_listen::MAX_LISTENS_PER_OWNER;
    let mut held = BTreeMap::new();
    for n in 0..per_owner {
        held.insert((1, n.to_string()), opened("k", 1));
    }
    assert!(
        door_listen::quota_full(held.values().map(|l: &LineListen| &l.owner), "k"),
        "a caller at {per_owner} line subscriptions is refused its next"
    );
    assert!(
        !door_listen::quota_full(held.values().map(|l: &LineListen| &l.owner), "j"),
        "another caller is not at its bound"
    );
}

/// A UNIT OF ITS CALLER RE-ASKS: a re-confirmed subscription goes on past the window, one whose
/// caller's unit found it lapsed ends on its next frame, and busbar asks a quiet caller a `ping`
/// once the window to re-ask is due.
#[test]
fn a_unit_of_its_caller_reasks_the_standing_its_frames_are_stepped_under() {
    let cat = catalogue();
    let mut kept = opened("k", 1);
    assert!(matches!(kept.step_at(&cat, 1), ListenStep::Frames(_)));
    assert!(!kept.wants_ping(2), "nothing is due yet");
    assert!(kept.wants_ping(1 + KEEPALIVE_NS), "a quiet caller is asked");
    assert!(!kept.wants_ping(2 + KEEPALIVE_NS), "once");
    reconfirmed(&mut kept, Standing::Live, UNCONFIRMED_NS);
    let step = kept.step_at(&cat, UNCONFIRMED_NS + 2);
    assert!(
        !matches!(step, ListenStep::End(_)),
        "re-confirmed, it goes on: {step:?}"
    );
    let lapsed = Standing::Lapsed {
        message: "`k` is no longer live".to_string(),
        reason: busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE.to_string(),
    };
    reconfirmed(&mut kept, lapsed, UNCONFIRMED_NS + 3);
    let step = kept.step_at(&cat, UNCONFIRMED_NS + 4);
    assert!(
        matches!(&step, ListenStep::End(frames)
            if frames[0]["error"]["data"]["reason"]
                == busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE),
        "a lapsed caller's stream ends on its next frame: {step:?}"
    );
}

#[test]
fn a_cancellation_removes_only_its_own_subscription_on_its_carrier() {
    let plane = McpDoor::default();
    for (session, id) in [(1, json!("sub")), (1, json!(7)), (2, json!("sub"))] {
        plane
            .line_listens
            .insert((session, line::id_key(&id)), opened("k", 1));
    }
    let cancel =
        br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"sub"}}"#;
    let _arrival = arrive(&plane, 1, cancel);
    assert!(plane
        .line_listens
        .get(&(1, line::id_key(&json!("sub"))))
        .is_none());
    assert!(plane
        .line_listens
        .get(&(1, line::id_key(&json!(7))))
        .is_some());
    assert!(plane
        .line_listens
        .get(&(2, line::id_key(&json!("sub"))))
        .is_some());
}

#[test]
fn an_unwatched_resource_is_not_retained_by_a_line_subscription() {
    let plane = McpDoor::default();
    let key = (1, "s:sub".to_string());
    plane.line_listens.insert(key.clone(), opened("k", 1));
    announced(&plane, "fs", "file:///an-unwatched-secret-path");
    assert!(plane.line_listens.get(&key).unwrap().updates.is_empty());
}

fn host_check_unit() -> CallUnit {
    CallUnit {
        key: 1,
        held: None,
        disposition: crate::tool_arrival::Disposition::Notice {
            method: String::new(),
        },
        params: None,
        framing: None,
        param_fields: Vec::new(),
        ticket: None,
        issued: 0,
        entitled: BTreeMap::new(),
        member: None,
        attempt: 0,
        relay: None,
        pending: None,
        claim: None,
        verified: None,
        joined_fetch: None,
        program: None,
        program_list: None,
        readied: None,
        task: None,
        line: None,
        child_work: super::super::ChildWork::default(),
        session: None,
        negotiating: None,
    }
}

#[test]
fn an_unavailable_host_does_not_claim_the_callers_identity_was_revoked() {
    let plane = McpDoor::default();
    let result = door_listen::standing(&plane, Ticket::NONE, "caller", &mut host_check_unit());
    if let Standing::Lapsed { reason, .. } = result {
        assert_ne!(reason, busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE);
    }
}

#[test]
fn an_old_opening_ticket_cannot_remove_a_reused_units_provisional_subscription() {
    let plane = McpDoor::default();
    let mut listen = opened("caller", 1);
    listen.opening_unit = 7;
    listen.opening_ticket = Ticket {
        slot: 7,
        generation: 2,
    };
    listen.acknowledged = false;
    let key = (3, "s:sub".to_string());
    plane.line_listens.insert(key.clone(), listen);
    abandoned(
        &plane,
        Ticket {
            slot: 7,
            generation: 1,
        },
        7,
    );
    assert!(plane.line_listens.get(&key).is_some());
    abandoned(
        &plane,
        Ticket {
            slot: 7,
            generation: 2,
        },
        7,
    );
    assert!(plane.line_listens.get(&key).is_none());
}

#[path = "reported_line.rs"]
mod reported;
