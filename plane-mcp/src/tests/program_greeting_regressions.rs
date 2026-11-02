use super::*;
use crate::tool_program::{Exchanged, ProgramConn};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use busbar_contract::abi::host::conn::connector::{ReplyPiece, REPLY_BODY, REPLY_HEAD};
use busbar_contract::abi::sdk::conn::Replied;
use busbar_contract::abi::transport::FrameSpan;
use std::sync::Mutex;
use std::task::Poll;

#[derive(Default)]
struct Child {
    instance: u64,
    generation: u64,
    next: u64,
    streams: BTreeMap<u64, (bool, std::collections::VecDeque<Vec<u8>>, bool)>,
    received: Vec<Value>,
    hold_initialized: bool,
    fail_list: bool,
}

struct Conn(Mutex<Child>);

impl ProgramConn for Conn {
    fn establish(&self, _: Ticket, _: u32, _: u32, _: &str, _: u32) -> Poll<Result<u64, String>> {
        let mut c = self.0.lock().unwrap();
        c.next += 1;
        let id = c.next;
        c.streams.insert(id, (true, Default::default(), false));
        Poll::Ready(Ok(id))
    }
    fn read_reply(
        &self,
        _: Ticket,
        _: u32,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>> {
        let mut c = self.0.lock().unwrap();
        let generation = c.generation.max(1);
        let instance = c.instance.max(1);
        let (head, inbox, failed) = c.streams.get_mut(&stream).unwrap();
        let (kind, bytes) = if *head {
            *head = false;
            (
                REPLY_HEAD,
                format!("generation: {generation}\r\nprogram-instance: {instance}\r\nprogram-identity: {}\r\n", STANDARD.encode("/usr/bin/child")).into_bytes(),
            )
        } else if *failed {
            return Poll::Ready(Err("tools/list transport failed".into()));
        } else if let Some(bytes) = inbox.pop_front() {
            (REPLY_BODY, bytes)
        } else {
            return Poll::Pending;
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        *slot = ReplyPiece {
            kind,
            code: if kind == REPLY_HEAD { 200 } else { 0 },
            fields: if kind == REPLY_HEAD {
                FrameSpan {
                    offset: 0,
                    len: bytes.len() as u64,
                }
            } else {
                FrameSpan::default()
            },
            ..ReplyPiece::default()
        };
        Poll::Ready(Ok(Replied {
            piece: *slot,
            len: bytes.len(),
        }))
    }
    fn write(&self, _: Ticket, _: u32, stream: u64, bytes: &[u8]) -> Poll<Result<usize, String>> {
        let value: Value = serde_json::from_slice(bytes).unwrap();
        let mut c = self.0.lock().unwrap();
        let method = value["method"].as_str().unwrap_or("");
        if method == "notifications/initialized" && c.hold_initialized {
            return Poll::Pending;
        }
        c.received.push(value.clone());
        if let Some(id) = value.get("id") {
            let fail = c.fail_list && method == "tools/list";
            c.fail_list &= !fail;
            let (_, inbox, failed) = c.streams.get_mut(&stream).unwrap();
            *failed = fail;
            if !fail {
                inbox.push_back(serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":id,"result":if method=="initialize"{serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{}})}else{serde_json::json!({"tools":[]})}})).unwrap());
            }
        }
        Poll::Ready(Ok(bytes.len()))
    }
    fn close(&self, _: Ticket, _: u32, stream: u64) -> Poll<()> {
        self.0.lock().unwrap().streams.remove(&stream);
        Poll::Ready(())
    }
}

fn list_exchange(id: u64) -> ProgramExchange {
    ProgramExchange::new(
        "srv",
        crate::statement::NEED_PROGRAM,
        vec![(
            crate::client::jsonrpc::tools_list("", id, None).body,
            Some(id),
        )],
        true,
    )
}

fn drive(
    plane: &McpDoor,
    conn: &Conn,
    exchange: &mut ProgramExchange,
    slot: u32,
) -> Poll<Result<Exchanged, String>> {
    let def = serde_json::from_value(serde_json::json!({
        "transport":"stdio", "command":"/usr/bin/child", "pin":{"mechanism":"unpinned"}
    }))
    .unwrap();
    exchange_child_on(
        plane,
        conn,
        Ticket {
            slot,
            generation: 1,
        },
        0,
        "srv",
        &def,
        exchange,
    )
}

fn initializes(conn: &Conn) -> usize {
    conn.0
        .lock()
        .unwrap()
        .received
        .iter()
        .filter(|v| v["method"] == "initialize")
        .count()
}

#[test]
fn concurrent_exchanges_wait_for_one_generation_greeting() {
    let plane = McpDoor::default();
    let conn = Conn(Mutex::new(Child {
        hold_initialized: true,
        ..Default::default()
    }));
    let (mut first, mut second) = (list_exchange(7), list_exchange(8));
    assert!(drive(&plane, &conn, &mut first, 1).is_pending());
    assert!(drive(&plane, &conn, &mut second, 2).is_pending());
    assert_eq!(
        initializes(&conn),
        1,
        "the second lease must not initialize the live child again"
    );
    conn.0.lock().unwrap().hold_initialized = false;
    assert!(matches!(
        drive(&plane, &conn, &mut first, 1),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        drive(&plane, &conn, &mut second, 2),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(initializes(&conn), 1);
}

#[test]
fn a_later_list_failure_does_not_erase_a_completed_greeting() {
    let plane = McpDoor::default();
    let conn = Conn(Mutex::new(Child {
        fail_list: true,
        ..Default::default()
    }));
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(7), 1),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(8), 2),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(
        initializes(&conn),
        1,
        "the failed list did not un-initialize its child"
    );
}

#[test]
fn a_restarted_child_is_greeted_and_a_cancelled_owner_does_not_strand_waiters() {
    let plane = McpDoor::default();
    let conn = Conn(Mutex::new(Child {
        hold_initialized: true,
        ..Default::default()
    }));
    let (mut first, mut next) = (list_exchange(7), list_exchange(8));
    assert!(drive(&plane, &conn, &mut first, 1).is_pending());
    assert!(drive(&plane, &conn, &mut next, 2).is_pending());
    drop(first);
    conn.0.lock().unwrap().hold_initialized = false;
    assert!(matches!(
        drive(&plane, &conn, &mut next, 2),
        Poll::Ready(Ok(_))
    ));
    let greeted = initializes(&conn);
    conn.0.lock().unwrap().generation = 2;
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(9), 3),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(initializes(&conn), greeted + 1);
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(10), 4),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(initializes(&conn), greeted + 1);
}

#[test]
fn a_child_request_memo_keeps_identity_without_retaining_the_far_ends_large_id() {
    let plane = McpDoor::default();
    let def = serde_json::from_value(serde_json::json!({
        "transport":"stdio", "command":"/usr/bin/child", "pin":{"mechanism":"unpinned"}
    }))
    .unwrap();
    let peer = DoorPeer {
        plane: &plane,
        member: "srv",
        grants: Default::default(),
        def: &def,
    };
    let marker = "remote-large-id-canary";
    let id = Value::String(marker.repeat(100_000));
    let mut calls = 0;
    assert_eq!(
        peer.decide(1, &id, || {
            calls += 1;
            Some(7_u64.into())
        }),
        (Some(7_u64.into()), true)
    );
    assert_eq!(
        peer.decide(1, &id, || {
            calls += 1;
            None
        }),
        (Some(7_u64.into()), false)
    );
    assert_eq!(calls, 1);
    let retained = plane.answered.with_all(|m| {
        m.get(&())
            .unwrap()
            .by_key
            .keys()
            .any(|key| key.2.contains(marker))
    });
    assert!(
        !retained,
        "an answered request keeps its identity, not the untrusted id payload"
    );
    let other = Value::String(format!("{}!", id.as_str().unwrap()));
    assert_eq!(
        peer.decide(1, &other, || Some(8_u64.into())),
        (Some(8_u64.into()), true)
    );
    assert_eq!(
        peer.decide(2, &id, || None),
        (None, true),
        "generation remains part of identity"
    );
}

#[test]
fn exact_generations_and_stale_completions_do_not_regreet_the_latest_child() {
    let plane = McpDoor::default();
    let conn = Conn(Mutex::new(Child {
        generation: 7,
        hold_initialized: true,
        ..Default::default()
    }));
    let mut older = list_exchange(7);
    assert!(drive(&plane, &conn, &mut older, 1).is_pending());
    {
        let mut child = conn.0.lock().unwrap();
        child.instance = 2;
        child.generation = 3;
        child.hold_initialized = false;
    }
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(8), 2),
        Poll::Ready(Ok(_))
    ));
    let latest = plane.greeted.get(&"srv".to_string()).unwrap();
    assert_eq!(
        plane
            .program_versions
            .with_all(|all| all.get(&()).and_then(|v| v.observed("srv", latest))),
        Some(crate::program_trust::Observed {
            instance: 2,
            generation: 3
        })
    );
    assert!(matches!(
        drive(&plane, &conn, &mut older, 1),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(plane.greeted.get(&"srv".to_string()), Some(latest));
    let greeted = initializes(&conn);
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(9), 3),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(initializes(&conn), greeted);
    conn.0.lock().unwrap().generation = 7;
    assert!(matches!(
        drive(&plane, &conn, &mut list_exchange(10), 4),
        Poll::Ready(Ok(_))
    ));
    assert_eq!(initializes(&conn), greeted + 1);
}

#[test]
fn memo_identity_distinguishes_typed_ids_members_and_generations() {
    let plane = McpDoor::default();
    let def = serde_json::from_value(serde_json::json!({
        "transport":"stdio", "command":"/usr/bin/child", "pin":{"mechanism":"unpinned"}
    }))
    .unwrap();
    let peer = DoorPeer {
        plane: &plane,
        member: "srv",
        grants: Default::default(),
        def: &def,
    };
    let other = DoorPeer {
        plane: &plane,
        member: "other",
        grants: Default::default(),
        def: &def,
    };
    assert_eq!(
        peer.decide(1, &Value::from(7), || Some(1_u64.into())),
        (Some(1_u64.into()), true)
    );
    assert_eq!(
        peer.decide(1, &Value::from("7"), || Some(2_u64.into())),
        (Some(2_u64.into()), true)
    );
    assert_eq!(other.decide(1, &Value::from(7), || None), (None, true));
    assert_eq!(peer.decide(2, &Value::from(7), || None), (None, true));
    assert_eq!(
        peer.decide(1, &Value::from(7), || None),
        (Some(1_u64.into()), false)
    );
}
