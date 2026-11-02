// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

#[test]
fn retiring_one_host_closed_carrier_removes_all_of_its_line_state() {
    let plane = McpDoor::default();
    for session in [7, 8] {
        let revision = crate::revision::accept_offered("2025-06-18").unwrap();
        plane.line_revisions.insert(session, revision);
        let ask = LiveAsk::of(
            json!({"id":"call","params":{}}),
            Vec::new(),
            &json!({"requestState":"sealed","inputRequests":{"one":{"method":"roots/list"}}}),
            0,
        )
        .unwrap();
        plane.live_asks.insert((session, 1), ask);
        let listen = Listen::open(
            Some(&json!({"notifications":{"toolsListChanged":true}})),
            json!("sub"),
            1,
            |_| false,
        )
        .unwrap();
        plane.line_listens.insert(
            (session, "s:sub".to_string()),
            LineListen {
                listen: Box::new(listen),
                opening_unit: session,
                opening_ticket: Ticket::NONE,
                acknowledged: true,
                entitled: BTreeMap::new(),
                hidden: Default::default(),
                owner: format!("owner-{session}"),
                standing: Standing::Live,
                confirmed_ns: 1,
                pinged_ns: 1,
                updates: Vec::new(),
            },
        );
    }
    assert_eq!(known_sessions(&plane), vec![7, 8]);
    retire_session(&plane, 7);
    assert_eq!(known_sessions(&plane), vec![8]);
    assert!(plane.line_revisions.get(&7).is_none());
    assert!(plane.live_asks.get(&(7, 1)).is_none());
    assert!(plane.line_listens.get(&(7, "s:sub".to_string())).is_none());
    assert!(plane.live_asks.get(&(8, 1)).is_some());
    assert!(plane.line_listens.get(&(8, "s:sub".to_string())).is_some());
}
