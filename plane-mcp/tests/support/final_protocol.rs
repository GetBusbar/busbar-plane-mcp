// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Protocol regressions through the actual plane door and connector seam.

use super::*;

const STATELESS: &str = "https://audit.example/stateless";
const SESSION: &str = "https://audit.example/session";

#[test]
fn an_uninspected_combinator_schema_never_reaches_the_normal_member_send() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let mut hostname = json!({"format":"hostname"});
    for _ in 0..8 {
        hostname = json!({"allOf":[hostname]});
    }
    let section = json!({"audit":{"url":STATELESS,"pin":{"mechanism":"unpinned"},"tools_allow":{"read_file":{"input_schema":{"type":"object","properties":{"target":hostname}}}}}}).to_string();
    let door = open_with(&section);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"audit_read_file","arguments":{"target":"169.254.169.254"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}).to_string();
    let fields = [
        ("mcp-protocol-version", "2026-07-28"),
        ("mcp-method", "tools/call"),
        ("mcp-name", "audit_read_file"),
    ];
    assert_eq!(
        door.arrive(30_500, "POST", "/mcp", body.as_bytes(), &fields)
            .outcome,
        Outcome::Ready
    );
    door.piece(30_500, &Given::attempt(ALICE, "audit"));
    let answer = door.pump(30_500, &Given::caller(ALICE, body.as_bytes()));
    assert!(!answer.far, "{}", answer.text());
    assert!(
        answer.text().contains("inspected partially"),
        "{}",
        answer.text()
    );
    assert!(seen()
        .iter()
        .all(|request| request.body["method"] != "tools/call"));
}

fn reload(door: &Door, generation: u64, section: &str) {
    use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
    use busbar_contract::abi::plane::PlaneRefreshOut;
    let input = RefreshIn {
        head: head::<RefreshIn>(life::REFRESH, Ticket::NONE),
        generation,
        settings: octets(section.as_bytes()),
        secrets: std::ptr::null(),
        secrets_len: 0,
    };
    let mut output: PlaneRefreshOut = z();
    output.head = out_head::<PlaneRefreshOut>();
    // SAFETY: The fixture owns this live door instance; the exact input/output frames and every borrowed buffer remain live throughout the synchronous call.
    let result = unsafe {
        lifecycle().refresh.unwrap()(
            door.instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
}

#[test]
fn description_only_reload_notifies_the_visible_lists_on_http_and_line() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let original = json!({"audit":{"url":STATELESS,"pin":{"mechanism":"unpinned"},
        "tools_allow":{"read_file":{"description":"old"}},
        "prompts_allow":{"p":{"description":"old","template":"prompt"}},
        "resources_allow":{"file:///r":{"description":"old","text":"resource"}}
    }});
    let listen = json!({"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{
        "notifications":{"toolsListChanged":true,"promptsListChanged":true,"resourcesListChanged":true},
        "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}
    }}).to_string();
    for line in [false, true] {
        *upstreams() = Some(Upstreams::default());
        EMITTED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        let door = open_with(&original.to_string());
        let acknowledged = if line {
            assert_eq!(
                door.line(30_520, 988, listen.as_bytes()).outcome,
                Outcome::Ready
            );
            door.piece(30_520, &Given::caller(ALICE, listen.as_bytes()))
        } else {
            let fields = [
                ("mcp-protocol-version", "2026-07-28"),
                ("mcp-method", "subscriptions/listen"),
            ];
            assert_eq!(
                door.arrive(30_520, "POST", "/mcp", listen.as_bytes(), &fields)
                    .outcome,
                Outcome::Ready
            );
            door.piece(30_520, &Given::stream_open(ALICE, 988))
        };
        assert!(
            acknowledged.text().contains("acknowledged"),
            "{}",
            acknowledged.text()
        );
        let mut changed = original.clone();
        changed["audit"]["tools_allow"]["read_file"]["description"] = json!("new");
        changed["audit"]["prompts_allow"]["p"]["description"] = json!("new");
        changed["audit"]["resources_allow"]["file:///r"]["description"] = json!("new");
        reload(&door, 2, &changed.to_string());
        let frames = if line {
            door.turn();
            EMITTED
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|(session, _)| *session == 988)
                .map(|(_, bytes)| String::from_utf8_lossy(bytes).into_owned())
                .collect::<String>()
        } else {
            door.piece(30_520, &Given::collect(ALICE, 988)).text()
        };
        for category in ["tools", "prompts", "resources"] {
            assert!(
                frames.contains(&format!("notifications/{category}/list_changed")),
                "{line}: {frames}"
            );
        }
    }
}
static WRONG_INITIALIZE_ID: AtomicBool = AtomicBool::new(false);
static LEGACY_CHANGED: AtomicBool = AtomicBool::new(false);

struct Flag(&'static AtomicBool);

impl Flag {
    fn set(flag: &'static AtomicBool) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self(flag)
    }
}

impl Drop for Flag {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

pub(super) fn legacy_changed() -> bool {
    LEGACY_CHANGED.load(Ordering::SeqCst)
}

pub(super) fn http_reply(url: &str, fields: &[(String, String)], body: &Value) -> Option<Reply> {
    if url != STATELESS && url != SESSION {
        return None;
    }
    let method = body["method"].as_str().unwrap_or("");
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    if method == "notifications/initialized" {
        return Some((202, Vec::new(), Vec::new()));
    }
    if url == SESSION
        && method != "initialize"
        && field_of(fields, "mcp-session-id") != Some("audit-session")
    {
        return Some((400, json_head(), Vec::new()));
    }
    let (id, result) = match method {
        "initialize" => (
            if WRONG_INITIALIZE_ID.load(Ordering::SeqCst) {
                json!("another-request")
            } else {
                id
            },
            json!({"protocolVersion":"2025-06-18", "capabilities":{}, "serverInfo":{"name":"fixture","version":"1"}}),
        ),
        "tools/list" => (
            id,
            json!({"tools":[{"name":"read_file","inputSchema":{"type":"object"}}]}),
        ),
        _ => return Some((404, Vec::new(), Vec::new())),
    };
    let mut bytes = sse_event(
        "message",
        &String::from_utf8(rpc_result(&id, result)).unwrap(),
    );
    if method != "initialize" || !WRONG_INITIALIZE_ID.load(Ordering::SeqCst) {
        bytes.extend(sse_event("message", r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"after result"}}"#));
        // A valid response to a different typed id must not replace this hop's response either.
        bytes.extend(sse_event(
            "message",
            r#"{"jsonrpc":"2.0","id":"unrelated","result":{}}"#,
        ));
    }
    let mut head = vec![("content-type".to_string(), "text/event-stream".to_string())];
    if method == "initialize" {
        head.push(("mcp-session-id".to_string(), "audit-session".to_string()));
    }
    Some((200, head, bytes))
}

fn section(url: &str) -> String {
    json!({"audit":{"url":url,"pin":{"mechanism":"unpinned"},"tools_allow":{"read_file":{}}}})
        .to_string()
}

#[test]
fn malformed_http_initialize_never_allocates_a_session_and_notifications_have_no_reply() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    let before = FILLS.load(Ordering::SeqCst);
    let cases = [
        (json!({"method":"initialize","id":1}), -32600),
        (
            json!({"jsonrpc":"1.0","method":"initialize","id":1}),
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":null}),
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":{}}),
            -32600,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":1,"params":[]}),
            -32602,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":1}}),
            -32602,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":1,"params":{"capabilities":false}}),
            -32602,
        ),
        (
            json!({"jsonrpc":"2.0","method":"initialize","id":1,"params":{"clientInfo":{"name":3}}}),
            -32602,
        ),
    ];
    for (offset, (body, code)) in cases.into_iter().enumerate() {
        let body = serde_json::to_vec(&body).unwrap();
        let unit = 30_000 + offset as u64;
        assert_eq!(
            door.arrive(unit, "POST", "/mcp", &body, &[]).outcome,
            Outcome::Ready
        );
        let answer = door.piece(unit, &Given::caller(ALICE, &body));
        assert_eq!(answer.status, 400, "{}", answer.text());
        assert_eq!(answer.json()["error"]["code"], code);
        assert!(answer.field("mcp-session-id").is_none());
    }
    let note = br#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#;
    assert_eq!(
        door.arrive(30_020, "POST", "/mcp", note, &[]).outcome,
        Outcome::Ready
    );
    let answer = door.piece(30_020, &Given::caller(ALICE, note));
    assert_eq!(answer.status, 202);
    assert!(answer.bytes.is_empty());
    assert_eq!(
        FILLS.load(Ordering::SeqCst),
        before,
        "refused openings and notifications allocate no session"
    );
    let unknown = br#"{"jsonrpc":"2.0","id":"unknown","method":"initialize","params":{"protocolVersion":"future","futureField":{"opaque":true}}}"#;
    assert_eq!(
        door.arrive(30_021, "POST", "/mcp", unknown, &[]).outcome,
        Outcome::Ready
    );
    let answer = door.piece(30_021, &Given::caller(ALICE, unknown));
    assert_eq!(answer.json()["result"]["protocolVersion"], "2025-11-25");
    assert!(answer.field("mcp-session-id").is_some());
    let session = answer.field("mcp-session-id").unwrap().to_string();
    let fields = [
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-11-25"),
    ];
    for (offset, body) in [
        br#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
    ]
    .into_iter()
    .enumerate()
    {
        let unit = 30_030 + offset as u64;
        assert_eq!(
            door.arrive(unit, "POST", "/mcp", body, &fields).outcome,
            Outcome::Ready
        );
        let refusal = door.piece(unit, &Given::caller(ALICE, body));
        assert_eq!(refusal.status, 400, "{}", refusal.text());
        assert!(refusal.json().get("error").is_some());
    }
    let malformed = br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#;
    assert_eq!(
        door.arrive(30_040, "POST", "/mcp", malformed, &fields)
            .outcome,
        Outcome::Ready
    );
    assert_eq!(
        door.piece(30_040, &Given::caller(BOB, malformed)).status,
        404,
        "session ownership is checked before its malformed message is answered"
    );
}

#[test]
fn line_housekeeping_validates_before_negotiating_and_stateless_initialize_stays_stateless() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let door = open();
    for (offset, body) in [
        br#"{"jsonrpc":"1.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":false}}"#,
        br#"{"jsonrpc":"2.0","id":1,"method":"ping","params":[]}"#,
    ].into_iter().enumerate() {
        let unit = 30_100 + offset as u64;
        assert_eq!(door.line(unit, 901, body).outcome, Outcome::Ready);
        let answer = door.piece(unit, &Given::caller(ALICE, body));
        assert!(answer.json().get("error").is_some(), "{}", answer.text());
    }
    assert_eq!(
        door.line(30_110, 901, LINE_LIST).outcome,
        Outcome::Refused,
        "bad initialize never changed the carrier revision"
    );
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2026-07-28"}}"#;
    assert_eq!(door.line(30_111, 902, body).outcome, Outcome::Ready);
    assert_eq!(
        door.piece(30_111, &Given::caller(ALICE, body)).json()["result"]["protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(door.line(30_112, 902, LINE_LIST).outcome, Outcome::Refused);
}

#[test]
fn sse_list_and_initialize_select_their_response_before_later_frames_and_keep_session_ids() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    WRONG_INITIALIZE_ID.store(false, Ordering::SeqCst);
    for (offset, url) in [STATELESS, SESSION].into_iter().enumerate() {
        *upstreams() = Some(Upstreams::default());
        let door = open_with(&section(url));
        for n in 0..2 {
            assert_eq!(
                view_of(&door.connect(30_200 + offset as u64 * 10 + n, "audit")),
                (Value::Null, json!(1))
            );
        }
        if url == SESSION {
            let ids: Vec<_> = seen()
                .into_iter()
                .filter(|request| {
                    request.url == SESSION
                        && request.body["method"] == "tools/list"
                        && field_of(&request.fields, "mcp-session-id").is_some()
                })
                .map(|request| request.body["id"].clone())
                .collect();
            assert_eq!(ids.len(), 2);
            assert_ne!(
                ids[0], ids[1],
                "the repeated fetch uses the remembered session's own id"
            );
        }
    }
}

#[test]
fn an_uncorrelated_initialize_offer_is_never_adopted() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let _wrong = Flag::set(&WRONG_INITIALIZE_ID);
    let door = open_with(&section(SESSION));
    let served = door.connect(30_250, "audit");
    assert!(view_of(&served).0.is_string());
    assert!(seen()
        .iter()
        .all(|request| request.body["method"] != "notifications/initialized"));
}

#[test]
fn a_legacy_list_change_invalidates_a_fresh_approval_before_the_next_call_is_sent() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    LEGACY_CHANGED.store(false, Ordering::SeqCst);
    let _book = BookOn::on();
    let door = open_with(LEGACY_SECTION);
    assert_eq!(
        view_of(&door.connect(30_300, "lg")),
        (Value::Null, json!(1))
    );
    let before = seen()
        .iter()
        .filter(|request| request.body["method"] == "tools/list")
        .count();
    let _changed = Flag::set(&LEGACY_CHANGED);
    let session = legacy_sessions()[0].clone();
    on_stream(&session, |stream| {
        stream.events.push_back(sse_event(
            "message",
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
        ))
    });
    door.turn();
    let (body, fields) = legacy_call(8, "after-change");
    assert_eq!(
        door.arrive(30_301, "POST", "/mcp", &body, &fields).outcome,
        Outcome::Ready
    );
    door.piece(30_301, &Given::attempt(ALICE, "lg"));
    let answer = door.pump(30_301, &Given::caller(ALICE, &body));
    assert!(
        !answer.far,
        "changed tool was sent before reapproval: {}",
        answer.text()
    );
    assert_eq!(answer.status, 403);
    assert!(
        seen()
            .iter()
            .filter(|request| request.body["method"] == "tools/list")
            .count()
            > before
    );
    assert!(seen()
        .iter()
        .all(|request| request.body["method"] != "tools/call"));
}
