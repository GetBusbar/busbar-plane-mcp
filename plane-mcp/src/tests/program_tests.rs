// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S OWN EXCHANGES WITH A STDIO CHILD (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)), driven
//! over a connector that stands in for the host's one long-lived program per member: a scripted
//! child every lease shares, whose messages reach every open lease, and whose generation the test
//! moves (a crash and a restart). The stand-in is the exchange's own seam (`ProgramConn`), a plain
//! Rust value, so this module needs no raw ABI call.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::task::Poll;

use crate::client::jsonrpc::ServerRequestGrants;
use crate::tool_program::{list_id, AskOwner, Exchanged, Peer, ProgramConn, ProgramExchange};
use busbar_contract::abi::host::conn::connector::{ReplyPiece, REPLY_BODY, REPLY_HEAD};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Replied;
use busbar_contract::abi::transport::FrameSpan;
use serde_json::{json, Value};

/// THE STAND-IN CHILD: its generation, every message it received, the messages each open lease has
/// to read (its head first), and what it says before each answer.
#[derive(Default)]
struct Child {
    generation: u64,
    received: Vec<Value>,
    leases: HashMap<u64, (bool, VecDeque<Vec<u8>>)>,
    next: u64,
    /// Written ahead of each answer: messages of the child's own and other exchanges' answers.
    chatter: Vec<Value>,
}

impl Child {
    /// What the child answers `message`: the chatter, then its answer by id (none to a notification).
    fn answer(&mut self, message: &Value) -> Vec<Value> {
        let Some(id) = message.get("id").cloned() else {
            return Vec::new();
        };
        if message.get("method").is_none() {
            // A reply to one of the child's own requests.
            return Vec::new();
        }
        let mut out = self.chatter.clone();
        let result = match message["method"].as_str() {
            Some("initialize") => json!({"protocolVersion": "2025-06-18", "capabilities": {}}),
            Some("tools/list") => {
                json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]})
            }
            _ => json!({}),
        };
        out.push(json!({"jsonrpc": "2.0", "id": id, "result": result}));
        out
    }
}

static CHILD: Mutex<Option<Child>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Child) -> R) -> R {
    f(CHILD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get_or_insert_with(Child::default))
}

/// One test at a time: the stand-in child is the process's.
static SERIAL: Mutex<()> = Mutex::new(());

/// THE HOST'S CONNECTOR, standing in for the member's one long-lived program: every lease reads
/// the stand-in child's messages.
struct ChildConn;

impl ProgramConn for ChildConn {
    fn establish(&self, _: Ticket, _: u32, _: u32, _: &str, _: u32) -> Poll<Result<u64, String>> {
        let lease = with(|c| {
            c.next += 1;
            let id = c.next;
            c.leases.insert(id, (true, VecDeque::new()));
            id
        });
        Poll::Ready(Ok(lease))
    }

    fn read_reply(
        &self,
        _: Ticket,
        _: u32,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>> {
        let got = with(|c| {
            let generation = c.generation;
            let (headed, inbox) = c.leases.get_mut(&stream)?;
            if *headed {
                *headed = false;
                return Some((
                    REPLY_HEAD,
                    format!("generation: {generation}\r\n").into_bytes(),
                ));
            }
            inbox.pop_front().map(|b| (REPLY_BODY, b))
        });
        let Some((kind, bytes)) = got else {
            return Poll::Pending;
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        let fields = if kind == REPLY_HEAD {
            FrameSpan {
                offset: 0,
                len: bytes.len() as u64,
            }
        } else {
            FrameSpan::default()
        };
        *slot = ReplyPiece {
            kind,
            fields,
            ..ReplyPiece::default()
        };
        Poll::Ready(Ok(Replied {
            piece: *slot,
            len: bytes.len(),
        }))
    }

    fn write(&self, _: Ticket, _: u32, _: u64, bytes: &[u8]) -> Poll<Result<usize, String>> {
        with(|c| {
            let message: Value = serde_json::from_slice(bytes).expect("one JSON message");
            c.received.push(message.clone());
            for said in c.answer(&message) {
                let said = serde_json::to_vec(&said).unwrap();
                for (_, inbox) in c.leases.values_mut() {
                    inbox.push_back(said.clone());
                }
            }
        });
        Poll::Ready(Ok(bytes.len()))
    }

    fn close(&self, _: Ticket, _: u32, stream: u64) -> Poll<()> {
        with(|c| c.leases.remove(&stream));
        Poll::Ready(())
    }
}

/// The door's record, as these tests keep it: the generation it greeted, what it answered.
#[derive(Default)]
struct Door {
    greeted: Option<u64>,
    claimed: Vec<(u64, String)>,
    noticed: u32,
}

impl Peer for Door {
    fn grants(&self) -> ServerRequestGrants {
        ServerRequestGrants::default()
    }
    fn claim(&mut self, generation: u64, id: &Value) -> bool {
        let key = (generation, id.to_string());
        let fresh = !self.claimed.contains(&key);
        if fresh {
            self.claimed.push(key);
        }
        fresh
    }
    fn owner(&mut self, generation: u64, id: &Value) -> AskOwner {
        // No call is relayed here: an ask is no call's, refused by the first exchange to read it.
        if self.claim(generation, id) {
            AskOwner::Refuse
        } else {
            AskOwner::Refused
        }
    }
    fn notice(&mut self) {
        self.noticed += 1;
    }
}

/// A `tools/list` exchange with the member, under `id`, driven to its end.
fn list(door: &mut Door, id: u64, ticket: u32) -> Exchanged {
    let host = ChildConn;
    let request = crate::client::jsonrpc::tools_list("", id, None).body;
    let mut exchange = ProgramExchange::new(
        "srv",
        crate::door::NEED_PROGRAM,
        vec![(request, Some(id))],
        true,
    );
    let ticket = Ticket {
        slot: ticket,
        generation: 1,
    };
    for _ in 0..64 {
        let greeted_at = door.greeted;
        let greeted = move |g: u64| greeted_at == Some(g);
        match exchange.drive(&host, ticket, 0, &greeted, door) {
            Poll::Ready(Ok(done)) => {
                if done.greeted {
                    door.greeted = Some(done.generation);
                }
                return done;
            }
            Poll::Ready(Err(e)) => panic!("the exchange failed: {e}"),
            Poll::Pending => {}
        }
    }
    panic!("the exchange never finished");
}

fn methods(received: &[Value]) -> Vec<String> {
    received
        .iter()
        .map(|m| {
            m.get("method")
                .and_then(Value::as_str)
                .map_or_else(|| "<reply>".to_string(), str::to_string)
        })
        .collect()
}

fn reset(generation: u64, chatter: Vec<Value>) {
    with(|c| {
        *c = Child {
            generation,
            chatter,
            ..Child::default()
        }
    });
}

/// RED: `initialize` (and its acknowledgement) runs ONCE PER GENERATION of the member's child: the
/// first exchange greets generation 1, the second reuses it, and after the child restarts
/// (generation 2) the next exchange greets it again.
#[test]
fn the_child_is_greeted_once_per_generation() {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(1, Vec::new());
    let mut door = Door::default();
    let first = list(&mut door, list_id(1, 0), 1);
    assert_eq!(first.generation, 1);
    assert!(first.greeted);
    assert!(first.answer.is_some());
    let second = list(&mut door, list_id(2, 0), 2);
    assert!(!second.greeted, "a greeted generation is not greeted again");
    assert_eq!(
        methods(&with(|c| c.received.clone())),
        vec![
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/list"
        ]
    );
    // The child crashed and was spawned anew: a new generation.
    with(|c| c.generation = 2);
    let third = list(&mut door, list_id(3, 0), 3);
    assert_eq!(third.generation, 2);
    assert!(third.greeted);
    assert_eq!(
        methods(&with(|c| c.received.clone()))[4..],
        ["initialize", "notifications/initialized", "tools/list"]
    );
}

/// RED: an exchange's answer is the response carrying ITS id: another exchange's answer and the
/// child's own messages that the child writes first are passed over or handled — the progress
/// note dropped, the list-changed notice brought forward, the child's `ping` answered once.
#[test]
fn an_exchange_takes_its_own_answer_and_handles_the_childs_messages() {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(
        1,
        vec![
            json!({"jsonrpc": "2.0", "id": 424242, "result": {"tools": []}}),
            json!({"jsonrpc": "2.0", "method": "notifications/progress",
                "params": {"progressToken": "busbar-7", "progress": 1}}),
            json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}),
            json!({"jsonrpc": "2.0", "id": "srv-ping", "method": "ping"}),
        ],
    );
    let mut door = Door {
        greeted: Some(1),
        ..Door::default()
    };
    let id = list_id(7, 0);
    let done = list(&mut door, id, 7);
    let answer: Value = serde_json::from_slice(&done.answer.expect("an answer")).unwrap();
    assert_eq!(answer["id"], json!(id), "its own id, not 424242");
    assert_eq!(answer["result"]["tools"][0]["name"], json!("echo"));
    // The progress note is dropped: it is no list-changed notice and nothing answers it.
    assert_eq!(
        door.noticed, 1,
        "only the list-changed notice is brought forward"
    );
    let received = with(|c| c.received.clone());
    assert_eq!(methods(&received), vec!["tools/list", "<reply>"]);
    assert_eq!(
        received[1],
        json!({"jsonrpc": "2.0", "id": "srv-ping", "result": {}}),
        "the child's ping is answered on its input"
    );
}
