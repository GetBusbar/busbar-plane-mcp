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
        readied: None,
        task: None,
        line: None,
        child_work: ChildWork::default(),
        session: None,
        negotiating: None,
    }
}

/// This exercises the lower member-send fallback with an admission produced from the actual
/// source catalogue. Ordinary pool routing refuses a missing twin before reaching this boundary;
/// the fallback must preserve only its canonical default name, never the source alias.
#[test]
fn a_member_send_fallback_uses_the_targets_canonical_default_scope() {
    let cfg = statement::read_tools_section(br#"{
        "source": {"url":"https://source.example", "tools_allow": {
            "read_file":{"schema_hash":"sha256:aa", "publish_as":"source_reader"}}},
        "target": {"url":"https://target.example", "aud":"https://target.example",
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
    assert!(!scope.unwrap().contains("source_reader"));
    assert!(!scope.unwrap().contains("target_other"));
}
