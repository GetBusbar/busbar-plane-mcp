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
        &crate::door::read_tools_section(SECTION).expect("the section reads"),
    )
}

/// A `toolsListChanged` subscription `owner` opened at `now_ns`.
fn opened(owner: &str, now_ns: u64) -> LineListen {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let listen = Listen::open(Some(&params), json!("sub"), now_ns, |_| false).expect("opened");
    LineListen::opened(listen, BTreeMap::new(), owner, now_ns)
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
    let per_owner = crate::tool_door::door_listen::MAX_LISTENS_PER_OWNER;
    let mut held = BTreeMap::new();
    for n in 0..per_owner {
        held.insert((1, n.to_string()), opened("k", 1));
    }
    assert!(
        line_quota_full(&held, "k"),
        "a caller at {per_owner} line subscriptions is refused its next"
    );
    assert!(
        !line_quota_full(&held, "j"),
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
    assert!(kept.wants_ping(1 + RECONFIRM_NS), "a quiet caller is asked");
    assert!(!kept.wants_ping(2 + RECONFIRM_NS), "once");
    kept.reconfirm(BTreeMap::new(), Standing::Live, UNCONFIRMED_NS);
    let step = kept.step_at(&cat, UNCONFIRMED_NS + 2);
    assert!(
        !matches!(step, ListenStep::End(_)),
        "re-confirmed, it goes on: {step:?}"
    );
    let lapsed = Standing::Lapsed {
        message: "`k` is no longer live".to_string(),
        reason: busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE.to_string(),
    };
    kept.reconfirm(BTreeMap::new(), lapsed, UNCONFIRMED_NS + 3);
    let step = kept.step_at(&cat, UNCONFIRMED_NS + 4);
    assert!(
        matches!(&step, ListenStep::End(frames)
            if frames[0]["error"]["data"]["reason"]
                == busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE),
        "a lapsed caller's stream ends on its next frame: {step:?}"
    );
}
