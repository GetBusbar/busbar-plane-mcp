// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A subscription: the acknowledgement first and narrowed, a change only when what THIS caller can
//! see changed, the permission re-asked on every frame, a keepalive when quiet, and its bound.

use serde_json::json;

use super::*;

const SECTION: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}},
    "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}
  }
}"#;

const SECTION_MORE: &[u8] = br#"{
  "fs": {
    "url": "https://mcp.example/fs",
    "pin": {"mechanism": "unpinned"},
    "tools_allow": {"read_file": {"schema_hash": "sha256:aa"}, "stat": {"schema_hash": "sha256:cc"}},
    "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}
  }
}"#;

fn catalogue(generation: u64, section: &[u8]) -> Catalogue {
    Catalogue::build(
        generation,
        &crate::statement::test_support::read_tools_section(section).expect("the section reads"),
    )
}

fn everything(_: &str, _: &str) -> bool {
    true
}

#[test]
fn content_only_changes_use_full_visible_lists_and_ignore_unlisted_content() {
    let first = json!({"fs":{"url":"https://mcp.example/fs","pin":{"mechanism":"unpinned"},
        "tools_allow":{"t":{"description":"old","input_schema":{"type":"object"}}},
        "prompts_allow":{"p":{"description":"old","template":"body"}},
        "resources_allow":{"file:///r":{"name":"r","description":"old","text":"body"}},
        "resource_templates_allow":{"file:///{name}":{"description":"old","text":"body {name}"}}
    }});
    let build =
        |generation, value: &Value| catalogue(generation, &serde_json::to_vec(value).unwrap());
    for (kind, field) in [
        (0, "tools_allow"),
        (1, "prompts_allow"),
        (2, "resources_allow"),
        (2, "resource_templates_allow"),
    ] {
        let mut changed = first.clone();
        let entry = changed["fs"][field]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .next()
            .unwrap();
        entry["description"] = json!("new");
        let params = json!({"notifications":{"toolsListChanged":true,"promptsListChanged":true,"resourcesListChanged":true}});
        let mut listen = Listen::open(Some(&params), json!(1), 0, |_| false).unwrap();
        listen.step(&build(1, &first), &everything, &Standing::Live, &[], 1);
        let Step::Frames(frames) =
            listen.step(&build(2, &changed), &everything, &Standing::Live, &[], 2)
        else {
            panic!("visible description change must notify")
        };
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0]["method"], KINDS[kind].1);
    }
    let mut body_only = first.clone();
    body_only["fs"]["resources_allow"]["file:///r"]["text"] = json!("new body");
    assert_eq!(
        change_keys(&build(1, &first), &everything),
        change_keys(&build(2, &body_only), &everything)
    );
}

#[test]
fn a_hidden_tools_content_does_not_notify_but_visibility_changes_do() {
    let cat = catalogue(1, SECTION);
    let params = json!({"notifications":{"toolsListChanged":true}});
    let mut listen = Listen::open(Some(&params), json!(1), 0, |_| false).unwrap();
    listen.step_visible(&cat, &everything, &|_| true, &Standing::Live, &[], 1);
    assert_eq!(
        listen.step_visible(
            &catalogue(2, SECTION_MORE),
            &everything,
            &|_| true,
            &Standing::Live,
            &[],
            2
        ),
        Step::Quiet
    );
    let Step::Frames(frames) =
        listen.step_visible(&cat, &everything, &|_| false, &Standing::Live, &[], 3)
    else {
        panic!("revealing a tool changes the visible list")
    };
    assert_eq!(frames[0]["method"], "notifications/tools/list_changed");
}

#[test]
fn the_acknowledgement_is_first_and_carries_the_accepted_subset() {
    let params = json!({ "notifications": {
        "toolsListChanged": true,
        "resourceSubscriptions": ["file:///readme", "file:///hidden", "file:///readme"]
    }});
    let mut l =
        Listen::open(Some(&params), json!("sub"), 0, |u| u == "file:///readme").expect("opened");
    assert_eq!(
        l.accepted.resources,
        Some(vec!["file:///readme".to_string()])
    );
    let Step::Frames(frames) = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1)
    else {
        panic!("the acknowledgement is owed first");
    };
    assert_eq!(frames[0]["method"], ACKNOWLEDGED);
    assert_eq!(frames[0]["params"]["_meta"][SUBSCRIPTION_ID], "sub");
    assert_eq!(
        frames[0]["params"]["notifications"],
        json!({ "toolsListChanged": true, "resourceSubscriptions": ["file:///readme"] })
    );
}

#[test]
fn a_subscription_that_can_deliver_nothing_is_refused_and_too_many_uris_are_refused() {
    let nothing = json!({ "notifications": { "resourceSubscriptions": ["file:///hidden"] } });
    assert!(Listen::open(Some(&nothing), json!(1), 0, |_| false).is_err());
    let uris: Vec<String> = (0..=MAX_SUBSCRIBED_URIS)
        .map(|i| format!("file:///{i}"))
        .collect();
    let many = json!({ "notifications": { "resourceSubscriptions": uris } });
    let refused = Listen::open(Some(&many), json!(1), 0, |_| true).expect_err("too many");
    assert_eq!(refused["error"]["code"], crate::codec::CODE_INVALID_PARAMS);
}

#[test]
fn a_change_the_caller_can_see_notifies_and_one_it_cannot_does_not() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);

    let Step::Frames(frames) = l.step(
        &catalogue(2, SECTION_MORE),
        &everything,
        &Standing::Live,
        &[],
        2,
    ) else {
        panic!("a visible change notifies");
    };
    assert_eq!(frames[0]["method"], "notifications/tools/list_changed");

    let only_read = |kind: &str, name: &str| {
        kind != crate::statement::SCOPE_TOOL || name.ends_with("read_file")
    };
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &only_read, &Standing::Live, &[], 1);
    assert_eq!(
        l.step(
            &catalogue(2, SECTION_MORE),
            &only_read,
            &Standing::Live,
            &[],
            2
        ),
        Step::Quiet
    );
}

#[test]
fn a_lapsed_permission_ends_the_stream_on_that_frame_and_the_bound_ends_it_gracefully() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);
    let lapsed = Standing::Lapsed {
        message: "the key was revoked".to_string(),
        reason: "identity_not_live".to_string(),
    };
    let Step::End(frames) = l.step(&catalogue(1, SECTION), &everything, &lapsed, &[], 2) else {
        panic!("a lapsed permission ends the stream");
    };
    assert_eq!(frames[0]["error"]["data"]["reason"], "identity_not_live");
    assert_eq!(
        l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 3),
        Step::Closed
    );
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| false).expect("opened");
    let _ack = l.step(&catalogue(1, SECTION), &everything, &Standing::Live, &[], 1);
    assert_eq!(
        l.step(
            &catalogue(1, SECTION),
            &everything,
            &Standing::Live,
            &[],
            KEEPALIVE_NS + 1
        ),
        Step::Keepalive
    );
    let Step::End(frames) = l.step(
        &catalogue(1, SECTION),
        &everything,
        &Standing::Live,
        &[],
        MAX_LIFETIME_NS,
    ) else {
        panic!("the bound ends the stream");
    };
    assert_eq!(frames[0]["result"]["resultType"], "complete");
}

#[test]
fn an_upstream_announcement_reaches_only_a_subscriber_entitled_to_the_announcing_servers_resource()
{
    let params = json!({ "notifications": { "resourceSubscriptions": ["file:///readme"] } });
    let mut l = Listen::open(Some(&params), json!(1), 0, |_| true).expect("opened");
    let cat = catalogue(1, SECTION);
    let _ack = l.step(&cat, &everything, &Standing::Live, &[], 1);
    let other = [("db".to_string(), "file:///readme".to_string())];
    assert_eq!(
        l.step(&cat, &everything, &Standing::Live, &other, 2),
        Step::Quiet
    );
    let own = [("fs".to_string(), "file:///readme".to_string())];
    let Step::Frames(frames) = l.step(&cat, &everything, &Standing::Live, &own, 3) else {
        panic!("the announcing server's own resource is relayed");
    };
    assert_eq!(frames[0]["method"], "notifications/resources/updated");
}

/// CHOKE POINT J (OPEN-AND-TRUSTED): a subscription is a long-lived response, and it holds NO
/// principal it resolved at open. It is opened from the request alone (`Listen::open` takes no
/// identity), and every frame is judged under the permission the door re-asks that frame (the
/// kernel's live re-resolution, `ENTITLEMENT_STANDING`): the same open stream that wrote frames
/// while its principal stood ends on the first frame after it stops standing, with the identity
/// refusal, and writes nothing after.
#[test]
fn the_long_lived_response_holds_no_principal_it_resolved_at_open() {
    let params = json!({ "notifications": { "toolsListChanged": true } });
    let mut l = Listen::open(Some(&params), json!("sub"), 0, |_| false).expect("opened");
    let cat = catalogue(1, SECTION);
    assert!(matches!(
        l.step(&cat, &everything, &Standing::Live, &[], 1),
        Step::Frames(_)
    ));
    assert_eq!(
        l.step(
            &catalogue(2, SECTION_MORE),
            &everything,
            &Standing::Live,
            &[],
            2
        ),
        Step::Frames(vec![json!({
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
            "params": { "_meta": { SUBSCRIPTION_ID: "sub" } },
        })]),
        "while the principal stands, what changed is written"
    );
    let lapsed = Standing::Lapsed {
        message: "`agent` is no longer live".to_string(),
        reason: "identity_not_live".to_string(),
    };
    let Step::End(frames) = l.step(&catalogue(3, SECTION), &everything, &lapsed, &[], 3) else {
        panic!("the frame after the principal stopped standing ends the stream");
    };
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["id"], "sub");
    assert_eq!(frames[0]["error"]["data"]["reason"], "identity_not_live");
    assert_eq!(
        l.step(
            &catalogue(4, SECTION_MORE),
            &everything,
            &Standing::Live,
            &[],
            4
        ),
        Step::Closed,
        "an ended stream writes nothing more, whatever a later frame would say"
    );
}

/// A request naming more distinct uris than the ceiling is refused as soon as the distinct count
/// passes it, never after reading the rest of the array; duplicates are folded without a scan of
/// what was kept, so many copies of a few uris are accepted.
#[test]
fn the_distinct_uris_are_counted_through_a_set_and_the_ceiling_refuses_at_once() {
    let many: Vec<String> = (0..200).map(|n| format!("file:///r{n}")).collect();
    let params = json!({ "notifications": { "resourceSubscriptions": many } });
    let refused = Listen::open(Some(&params), json!("sub"), 0, |_| true).expect_err("over the cap");
    let message = refused["error"]["message"].as_str().expect("a sentence");
    assert!(
        message.contains(&format!(
            "names more than {MAX_SUBSCRIBED_URIS} distinct uris"
        )),
        "the refusal states what it knows (it stopped counting past the ceiling): {message}"
    );
    let copies: Vec<&str> = (0..100_000)
        .map(|n| ["file:///a", "file:///b", "file:///c"][n % 3])
        .collect();
    let params = json!({ "notifications": { "resourceSubscriptions": copies } });
    let l = Listen::open(Some(&params), json!("sub"), 0, |_| true).expect("duplicates fold");
    assert_eq!(l.accepted.resources.as_ref().map(Vec::len), Some(3));
}

#[test]
fn a_grant_change_notifies_without_a_catalogue_reload() {
    let cat = catalogue(1, SECTION);
    let params = json!({"notifications":{"toolsListChanged":true}});
    let mut listen = Listen::open(Some(&params), json!("role-change"), 0, |_| false).unwrap();
    assert!(matches!(
        listen.step(&cat, &everything, &Standing::Live, &[], 1),
        Step::Frames(_)
    ));
    let nothing = |_: &str, _: &str| false;
    let Step::Frames(frames) = listen.step(&cat, &nothing, &Standing::Live, &[], 2) else {
        panic!("the caller's visible list changed even though the catalogue generation did not");
    };
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0]["method"], "notifications/tools/list_changed");
    assert_eq!(
        listen.step(&cat, &nothing, &Standing::Live, &[], 3),
        Step::Quiet
    );
}

#[test]
fn a_tool_change_key_keeps_each_name_paired_with_its_schema() {
    let before = br#"{"fs":{"url":"https://mcp.example/fs","pin":{"mechanism":"unpinned"},"tools_allow":{"a":{"schema_hash":"sha256:aa"},"b":{"schema_hash":"sha256:bb"}}}}"#;
    let after = br#"{"fs":{"url":"https://mcp.example/fs","pin":{"mechanism":"unpinned"},"tools_allow":{"a":{"schema_hash":"sha256:bb"},"b":{"schema_hash":"sha256:aa"}}}}"#;
    assert_ne!(
        change_keys(&catalogue(1, before), &everything)[0],
        change_keys(&catalogue(2, after), &everything)[0]
    );
}

#[test]
fn malformed_notification_filter_reports_its_shape() {
    let params = json!({"notifications":{"toolsListChanged":true,"resourceSubscriptions":[3]}});
    let error = Listen::open(Some(&params), json!(1), 0, |_| true).unwrap_err();
    assert!(error["error"]["message"]
        .as_str()
        .unwrap()
        .contains("boolean list categories"));
}

/// The three keys of the complete rendered lists one caller can see.
#[must_use]
pub fn change_keys(catalogue: &Catalogue, admit: &impl Fn(&str, &str) -> bool) -> [u64; 3] {
    change_keys_visible(catalogue, admit, &|_| false)
}
