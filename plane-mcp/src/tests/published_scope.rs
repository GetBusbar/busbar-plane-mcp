// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use serde_json::json;

fn unit() -> CallUnit {
    CallUnit {
        key: 1,
        held: None,
        disposition: Disposition::Notice {
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
        program_ready: None,
        task: None,
        line: None,
        child_work: ChildWork::default(),
        session: None,
        negotiating: None,
    }
}

/// The lower member-send fallback uses the canonical scope from the actual admission.
#[test]
fn a_member_send_fallback_uses_the_targets_canonical_default_scope() {
    let cfg = statement::test_support::read_tools_section(br#"{
        "source": {"url":"https://source.example", "pin":{"mechanism":"unpinned"}, "tools_allow": {
            "read_file":{"schema_hash":"sha256:aa", "publish_as":"source_reader"}}},
        "target": {"url":"https://target.example", "pin":{"mechanism":"unpinned"}, "aud":"https://target.example",
            "token_exchange":{"token_url":"https://as.example/token", "subject_token":{"env":"SUBJECT"}},
            "tools_allow":{"other":{"schema_hash":"sha256:bb", "publish_as":"target_other"}}}
    }"#).unwrap();
    let held = Held::of(1, cfg);
    let params = json!({"name":"source_reader", "arguments":{}});
    let Admission::Go(admitted) = crate::call::admit_trusted(
        &held.catalogue,
        &json!(1),
        Some(&params),
        &|_| None,
        &|_, _| true,
        &mut |_| crate::call::Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_NONE),
        &mut |_, _| crate::ask::AskDecision::Proceed,
    ) else {
        panic!("the configured source alias is admitted");
    };
    assert_eq!(admitted.entry.namespaced, "source_reader");
    assert!(held
        .catalogue
        .tool_on("target", &admitted.entry.tool)
        .is_none());
    assert!(
        matches!(twin_of(&held, Some(&params), "target"), Twin::Declined),
        "the served route still refuses a member without the approved twin"
    );
    let mut unit = unit();
    unit.entitled
        .insert(format!("{}:", statement::SCOPE_TOOL), true);
    let plane = McpDoor::default();
    assert!(matches!(
        send_to_member(
            &plane,
            Ticket::NONE,
            "caller",
            &mut unit,
            &held,
            "target",
            admitted
        ),
        Some(MemberSend::Step(Step::Write))
    ));
    let pending = unit
        .pending
        .as_ref()
        .expect("the real member send writes its outbound request");
    let scope = pending
        .fields
        .iter()
        .find(|(name, _)| name == busbar_contract::abi::auth::SCOPE_REQUEST_FIELD)
        .map(|(_, value)| value.as_str());
    assert_eq!(scope, Some("target_read_file"));
}

#[test]
fn failover_compares_against_the_selected_members_approved_schema() {
    let cfg = statement::test_support::read_tools_section(
        br#"{
        "primary": {"url":"https://primary.example", "pin":{"mechanism":"unpinned"},
            "tools_allow":{"read":{"schema_hash":"sha256:old"}}},
        "selected": {"url":"https://selected.example", "pin":{"mechanism":"unpinned"},
            "tools_allow":{"read":{"schema_hash":"sha256:new"}}},
        "matching": {"url":"https://matching.example", "pin":{"mechanism":"unpinned"},
            "tools_allow":{"read":{"schema_hash":"sha256:new"}}}
    }"#,
    )
    .unwrap();
    let mut held = Held::of(1, cfg);
    held.pools.insert(
        "pool".into(),
        statement::ToolPool {
            members: vec!["primary".into(), "selected".into(), "matching".into()],
            repeatable: vec![],
        },
    );
    let name = held
        .catalogue
        .tool_on("selected", "read")
        .unwrap()
        .namespaced
        .clone();
    let params = json!({"name":name,"arguments":{}});
    assert!(matches!(
        twin_of(&held, Some(&params), "primary"),
        Twin::Declined
    ));
    assert!(matches!(
        twin_of(&held, Some(&params), "matching"),
        Twin::Call(_)
    ));
}

#[test]
fn host_trust_state_sizes_are_bounded_before_allocation() {
    assert_eq!(trust_state_capacity(16_384, 128), Some((16_384, 128)));
    assert_eq!(trust_state_capacity(u64::MAX, 1), None);
    assert_eq!(trust_state_capacity(1, u64::MAX), None);
    assert_eq!(trust_state_capacity(16 * 1024 * 1024 + 1, 1), None);
    assert_eq!(trust_state_capacity(1, 65_537), None);
}

#[test]
fn hook_rewrite_replaces_parameter_mirror_from_the_held_schema() {
    let cfg = statement::test_support::read_tools_section(
        br#"{
        "source": {"url":"https://source.example", "pin":{"mechanism":"unpinned"},
            "tools_allow":{"read":{"schema_hash":"sha256:a", "publish_as":"reader",
                "input_schema":{"properties":{"path":{"type":"string","x-mcp-header":"Path"}}}}}}
    }"#,
    )
    .unwrap();
    let mut unit = unit();
    unit.held = Some(Arc::new(Held::of(1, cfg)));
    unit.param_fields = vec![("mcp-param-path".into(), "old".into())];
    apply_rewritten_params(
        &mut unit,
        json!({"name":"reader", "arguments":{"path":"new"}}),
    );
    assert_eq!(
        unit.param_fields,
        vec![(
            "mcp-param-path".into(),
            crate::client::jsonrpc::encode_sentinel("new")
        )]
    );
    apply_rewritten_params(&mut unit, json!({"name":"reader", "arguments":{}}));
    assert!(unit.param_fields.is_empty());
}

#[test]
fn child_work_transient_failures_are_not_spent_approvals() {
    assert_eq!(
        child_work_failure(ServiceError::Declined(Outcome::Refused)),
        Ok(false)
    );
    assert_eq!(
        child_work_failure(ServiceError::Unserved),
        Err(ServiceError::Unserved)
    );
    assert_eq!(
        child_work_failure(ServiceError::Broken),
        Err(ServiceError::Broken)
    );
    assert_eq!(
        child_work_failure(ServiceError::Declined(Outcome::Failed)),
        Err(ServiceError::Declined(Outcome::Failed))
    );
}

#[test]
fn nonce_capacity_refuses_new_approvals_without_forgetting_replays() {
    let spent = Keyed::new();
    spent.with_all(|seen| {
        for n in 0..MAX_SPENT_APPROVALS {
            seen.insert(n.to_string(), 100);
        }
    });
    assert!(!reserve_nonce(&spent, "new", 100, 10));
    assert!(!reserve_nonce(&spent, "0", 100, 10));
    assert!(reserve_nonce(&spent, "new", 200, 101));
    assert!(!reserve_nonce(&spent, "new", 200, 101));
}

#[test]
fn progress_collection_stops_at_the_delivery_limit() {
    let raw = (0..300).map(|n| format!("data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":1,\"progress\":{n}}}}}\n\n")).collect::<String>();
    let frames = crate::call::progress_frames_bounded(raw.as_bytes(), 256);
    assert_eq!(frames.len(), 256);
    assert_eq!(frames.last().unwrap()["params"]["progress"], 255);
    assert!(crate::call::progress_frames_bounded(raw.as_bytes(), 0).is_empty());
}

#[test]
fn measured_json_length_matches_escaped_wire_bytes() {
    let value = json!({"text":"quoted \" and newline\n and λ", "array":[1,true,null]});
    assert_eq!(
        crate::codec::json_len(&value),
        serde_json::to_vec(&value).unwrap().len()
    );
}

#[test]
fn hook_projection_uses_the_units_retained_generation() {
    let cfg = statement::test_support::read_tools_section(
        br#"{
        "source": {"url":"https://source.example", "pin":{"mechanism":"unpinned"},
            "tools_allow":{"read":{"schema_hash":"sha256:a", "publish_as":"reader"}}}
    }"#,
    )
    .unwrap();
    let plane = McpDoor::default();
    let mut held_unit = unit();
    held_unit.held = Some(Arc::new(Held::of(1, cfg)));
    plane.units.insert(1, held_unit);
    assert!(plane.current().is_none());
    assert_eq!(projection_entry(&plane, 1, "reader"), "source");
    assert!(projection_entry(&plane, 2, "reader").is_empty());
}

#[test]
fn local_line_revision_is_retained_across_carrier_reinitialization() {
    use crate::revision::Revision;
    for (before, after) in [
        (Revision::R2024_11_05, Revision::R2025_11_25),
        (Revision::R2025_11_25, Revision::R2024_11_05),
    ] {
        let plane = McpDoor::default();
        plane.line_revisions.insert(7, before);
        let arrival = door_line::arrive(
            &plane,
            7,
            br#"{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"s_p"}}"#,
        );
        assert!(arrival.unit.raised);
        let mut request = unit();
        request.session = Some(door_sessions::SessionUnit::Line);
        request.line = Some(arrival.unit);
        plane.line_revisions.insert(7, after);
        assert_eq!(local_revision(&request), before);
    }
}
