// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use super::*;

#[test]
fn local_history_retains_only_existing_quota_bytes_and_releases_original_generation() {
    let bounds = crate::tool_sessions::Bounds {
        max_session_bytes: 256,
        ..Default::default()
    };
    let mut table = Sessions::new(bounds);
    let owner = owner_of("alice");
    let session = table
        .open([1; 16], owner.clone(), Revision::R2024_11_05, 0)
        .unwrap();
    let stream = table.open_stream(&session, &owner, 0).unwrap();
    for (index, argument) in ["<a>".repeat(5000), "x".repeat(512)]
        .into_iter()
        .enumerate()
    {
        let section = crate::statement::read_tools_section(br#"{"s":{"url":"https://mcp.example/s","pin":{"mechanism":"unpinned"},"prompts_allow":{"p":{"template":"{value}"}}}}"#).unwrap();
        let held = Arc::new(Held::of(1, section));
        let generation = Arc::downgrade(&held);
        let local = crate::local_renderer::Local::prompt(
            held.clone(),
            "s_p".to_string(),
            json!(index),
            Some(json!({"name":"s_p","arguments":{"value":argument}})),
            true,
        )
        .unwrap();
        drop(held);
        assert!(generation.upgrade().is_some());
        let retained = table.retained_event_fits(local.len());
        assert_eq!(retained, index == 0);
        let data = history_data(&table, Data::Local(local)).unwrap();
        assert_eq!(matches!(&data, Data::Text(_)), retained);
        if retained {
            assert!(
                generation.upgrade().is_none(),
                "ordinary replay bytes must not pin original input or generation"
            );
        }
        table.push_data(&session, &owner, stream, data, 0).unwrap();
        assert!(
            generation.upgrade().is_none(),
            "oversized local input is dropped by the existing trim"
        );
        let replay = table
            .replay(&session, &owner, &format!("{stream}-0"), 0)
            .unwrap();
        if retained {
            assert_eq!(replay.events.len(), 1);
            assert!(matches!(&replay.events[0].1, Data::Text(_)));
        } else {
            assert!(replay.events.is_empty());
            assert!(!replay.complete);
        }
    }
}
