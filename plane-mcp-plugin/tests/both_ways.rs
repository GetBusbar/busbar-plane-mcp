// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane's door driven both ways: linked and dropped in, one script through every plane op.

#[path = "../../plane-mcp/tests/support/door_facts.rs"]
#[allow(dead_code)]
mod door_facts;

fn loaded_door() -> busbar_plugin_loader::dispatch::LoadedDoor {
    let door: busbar_contract::abi::mechanism::door::DoorFn = busbar_plane_mcp::door;
    busbar_plugin_loader::dispatch::LoadedDoor::from(door)
}

/// An all-zero `in`/`out` frame.
fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

/// `b` as opaque octets.
fn octets(b: &'static [u8]) -> busbar_contract::abi::mechanism::call::Blob {
    busbar_contract::abi::mechanism::call::Blob::of(b)
        .with_fmt(busbar_contract::abi::mechanism::call::BLOB_OCTETS)
}

/// `b` as an ABI string.
fn text(b: &'static [u8]) -> busbar_contract::abi::mechanism::call::AbiStr {
    busbar_contract::abi::mechanism::call::AbiStr::of_bytes(b)
}

mod both_ways {
    use std::sync::Arc;

    use super::{octets, text, z};
    use busbar_contract::abi::mechanism::call::{AbiStr, Field, Outcome, Span};
    use busbar_contract::abi::mechanism::door::Door;
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        self, slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn,
        PlaneOpenOut, PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut,
        ServeIn, ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END,
        FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_ARRIVE,
        REFUSAL_GATE,
    };
    use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureSlot};
    use busbar_contract::abi::sdk::door::{abi_str, kind_op};
    use busbar_contract::abi::sdk::publish::ServedRoute;
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
    use busbar_plugin_loader::dispatch::{
        in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
        LinkedRow, LoadedDoor, NoSink, Plugin,
    };
    use serde_json::{json, Value};

    use busbar_plane_mcp::door;

    use crate::door_facts::{
        self, claim as route_of, CLASS_FEE_INDEX, CODE_HEADER_MISMATCH, CODE_INTERNAL,
        CODE_REFUSED, DEFAULT_METADATA, ENDPOINT_SECTION, H_MCP_METHOD, H_MCP_NAME,
        H_PROTOCOL_VERSION, PROTOCOL_VERSION, TOOLS_SECTION,
    };

    fn bind(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),

            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        }
    }

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    /// One fronted server, the section the door's own tests read.
    const SECTION: &[u8] = door_facts::WITNESS_SECTION;
    /// [`SECTION`] as stage 3g deals it to `validate` (`{tools: <section>}`), and a dealt section
    const DEALT: &[u8] =
        br#"{"tools": {"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}}"#;
    const BAD_DEALT: &[u8] =
        br#"{"tools": {"my_fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}}"#;
    /// The deployment's public base URL the host lends `open`.
    const PUBLIC_URL: &str = "https://busbar.example";

    /// A stateless-revision `tools/list`.
    const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A stateless-revision `tools/call`: sent on, never answered from what the plane holds.
    const TOOLS_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    /// A notification: acknowledged, never answered.
    const NOTICE: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    /// A body that is not JSON.
    const NOT_JSON: &[u8] = b"{not json";

    const fn field(name: &'static str, value: &'static str) -> Field {
        Field {
            name: abi_str(name),
            value: abi_str(value),
        }
    }

    const LIST_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/list"),
    ];
    const CALL_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
    ];

    /// The route index of `(verb, target)` in the door's route table (its first such row), the claim
    fn claim(verb: &str, target: &str) -> u32 {
        route_of(verb, target, "http")
    }

    /// What one op answered, read back: the outcome, the status it stated, the bytes it wrote and
    /// the head fields, and anything else the op answers in its own out struct.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Step {
        what: &'static str,
        outcome: Outcome,
        status: u32,
        reply: Vec<u8>,
        fields: Vec<(String, String)>,
        detail: String,
        snapshot: Option<OwnedSnapshot>,
        /// The record writes the answers carried: `(kind, key, value)`.
        records: Vec<(u32, Vec<u8>, Vec<u8>)>,
        /// The audit rows the answers carried (`RECORD_AUDIT` writes): `(outcome, action,
        /// resource)`.
        audits: Vec<(u32, String, String)>,
        /// The last ledger lane an answer named.
        lane: Option<String>,
        /// The counts the answers reported: `(class, amount)`.
        units: Vec<(u32, u64)>,
    }

    impl Step {
        fn new(what: &'static str, outcome: Outcome) -> Self {
            Step {
                what,
                outcome,
                status: 0,
                reply: Vec::new(),
                fields: Vec::new(),
                detail: String::new(),
                snapshot: None,
                records: Vec::new(),
                audits: Vec::new(),
                lane: None,
                units: Vec::new(),
            }
        }
    }

    fn arrive(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        (verb, target): (&'static str, &'static str),
        body: &'static [u8],
        fields: &'static [Field],
    ) -> (Step, Option<Vec<u8>>) {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = claim(verb, target);
        (a.input.method, a.input.target) = (text(verb.as_bytes()), text(target.as_bytes()));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let c = p.call(slot::ARRIVE, &mut a);
        let mut s = Step::new(what, c.outcome);
        s.status = a.out.refusal_status;
        s.detail = format!(
            "op_class={} principal_required={} dialect={} refusal={}",
            a.out.op_class,
            a.out.principal_need == PRINCIPAL_REQUIRED,
            a.out.dialect,
            a.out.refusal
        );
        (s, c.error)
    }

    /// One piece as the kernel pushes it: who it is from, its flags and status, the attempt it
    /// starts and the member it names, the far end's head fields and the bytes.
    #[derive(Clone, Copy)]
    struct Push {
        from: u32,
        flags: u32,
        status: u32,
        attempt: u32,
        member: &'static str,
        head: &'static [Field],
        bytes: &'static [u8],
    }

    impl Push {
        /// The caller's whole body.
        const fn caller(bytes: &'static [u8]) -> Self {
            Push {
                from: FROM_CALLER,
                flags: PIECE_LAST,
                status: 0,
                attempt: 0,
                member: "",
                head: &[],
                bytes,
            }
        }

        /// The kernel's ATTEMPT piece naming `member`.
        const fn attempt(member: &'static str) -> Self {
            Push {
                from: FROM_KERNEL,
                flags: 0,
                status: 0,
                attempt: 1,
                member,
                head: &[],
                bytes: b"",
            }
        }

        /// The far end ended with no answer at all: the kernel's `Ok(None)` piece (last, no
        const fn unanswered() -> Self {
            Push {
                from: FROM_FAR_END,
                flags: PIECE_LAST,
                status: 0,
                attempt: 0,
                member: "",
                head: &[],
                bytes: b"",
            }
        }

        /// The far end's whole answer: its status, its kept head fields and its body.
        const fn far(status: u32, head: &'static [Field], bytes: &'static [u8]) -> Self {
            Push {
                from: FROM_FAR_END,
                flags: PIECE_LAST | PIECE_HAS_STATUS,
                status,
                attempt: 0,
                member: "",
                head,
                bytes,
            }
        }
    }

    /// One `on_piece` of `unit` with a reply buffer of `cap` bytes, then re-called with the same
    fn push(p: &Plugin<Plane>, what: &'static str, unit: u64, given: Push, cap: usize) -> Step {
        let mut reply = vec![0_u8; cap];
        let (mut fields, mut arena) = ([z::<OutField>(); 16], vec![0_u8; 4096]);
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut out = Step::new(what, Outcome::Ready);
        let mut calls = 0;
        let mut flags = 0;
        let mut line = String::new();
        let mut first = true;
        loop {
            let mut i: OnPieceIn = z();
            i.head = in_head();
            (i.unit, i.from) = (unit, given.from);
            if first {
                (i.flags, i.bytes) = (given.flags, octets(given.bytes));
                (i.status_code, i.attempt_no) = (given.status, given.attempt);
                i.member = text(given.member.as_bytes());
                (i.head_fields, i.head_fields_len) = (given.head.as_ptr(), given.head.len());
            } else {
                i.bytes = octets(b"");
            }
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            out.units.extend(
                units[..f.out.units_written as usize]
                    .iter()
                    .map(|u| (u.class, u.amount)),
            );
            let span = |s: Span| {
                let at = s.offset as usize;
                arena[at..at + s.len as usize].to_vec()
            };
            for r in &records[..f.out.records_written as usize] {
                if r.op == busbar_contract::abi::plane::RECORD_AUDIT {
                    out.audits
                        .push((r.kind, at(&arena, r.key), at(&arena, r.value)));
                } else {
                    out.records.push((r.kind, span(r.key), span(r.value)));
                }
            }
            if f.out.lane.len != 0 {
                out.lane = Some(at(&arena, f.out.lane));
            }
            calls += 1;
            first = false;
            out.outcome = c.outcome;
            if f.out.reply_status != 0 {
                out.status = f.out.reply_status;
            }
            out.fields.extend(
                fields[..f.out.fields_written as usize]
                    .iter()
                    .map(|f| (at(&arena, f.name), at(&arena, f.value))),
            );
            if f.out.verb.len != 0 {
                line = format!("{} {}", at(&arena, f.out.verb), at(&arena, f.out.target));
            }
            flags |= f.out.flags;
            out.reply
                .extend_from_slice(&reply[..usize::try_from(f.out.emitted).expect("small")]);
            if c.outcome != Outcome::Ready || f.out.more == 0 || calls > 256 {
                out.detail = format!(
                    "calls={calls} done={} far={} more={} request={line}",
                    flags & EMIT_DONE != 0,
                    flags & EMIT_TO_FAR_END != 0,
                    f.out.more
                );
                return out;
            }
        }
    }

    /// The caller's whole body, answered through buffers of `cap` bytes.
    fn piece(
        p: &Plugin<Plane>,
        what: &'static str,
        unit: u64,
        from: u32,
        body: &'static [u8],
        cap: usize,
    ) -> Step {
        let given = Push {
            from,
            ..Push::caller(body)
        };
        push(p, what, unit, given, cap)
    }

    fn refusal(
        p: &Plugin<Plane>,
        what: &'static str,
        cause: u32,
        status: u32,
        words: &[u8],
    ) -> Step {
        let (mut reply, mut fields, mut arena) = ([0_u8; 512], [z::<OutField>(); 2], [0_u8; 64]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status) = (cause, status);
        // SAFETY: `words` outlives the call this `in` is built for.
        r.input.text = unsafe { AbiStr::from_raw_parts(words.as_ptr(), words.len()) };
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let mut s = Step::new(what, c.outcome);
        s.status = r.out.status;
        s.reply = reply[..usize::try_from(r.out.reply_written).expect("small")].to_vec();
        s.fields = fields[..r.out.fields_written as usize]
            .iter()
            .map(|f| (at(&arena, f.name), at(&arena, f.value)))
            .collect();
        s
    }

    /// THE SCRIPT: every plane op, each answer read back.
    fn script(p: &Plugin<Plane>) -> Vec<Step> {
        let mut t = Vec::new();

        let mut v = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: octets(BAD_DEALT),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        t.push(Step::new(
            "validate refused",
            p.call(life::VALIDATE, &mut v).outcome,
        ));
        v.input.settings = octets(DEALT);
        t.push(Step::new(
            "validate",
            p.call(life::VALIDATE, &mut v).outcome,
        ));

        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, snapshot) = p.open(&mut Frame::new(i, o));
        let mut s = Step::new("open", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        for (what, op) in [("hydrate", slot::HYDRATE), ("start", slot::START)] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            t.push(Step::new(what, p.call(op, &mut g).outcome));
        }

        let post = ("POST", "/mcp");
        t.push(arrive(p, "arrive tools/list", 7, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/list",
            7,
            FROM_CALLER,
            TOOLS_LIST,
            32,
        ));

        t.push(arrive(p, "arrive notice", 8, post, NOTICE, &[]).0);
        t.push(piece(p, "answer notice", 8, FROM_CALLER, NOTICE, 256));

        t.push(arrive(p, "arrive tools/call", 9, post, TOOLS_CALL, CALL_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/call",
            9,
            FROM_CALLER,
            TOOLS_CALL,
            256,
        ));

        t.push(arrive(p, "arrive again", 10, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(p, "far end", 10, FROM_FAR_END, b"{}", 256));

        let (s, words) = arrive(p, "arrive not json", 11, post, NOT_JSON, &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal not json", REFUSAL_ARRIVE, 0, &words));
        let (s, words) = arrive(p, "arrive GET /mcp", 12, ("GET", "/mcp"), b"", &[]);
        t.push(s);
        let words = words.unwrap_or_default();
        t.push(refusal(p, "refusal GET /mcp", REFUSAL_ARRIVE, 0, &words));
        let metadata = ("GET", DEFAULT_METADATA);
        t.push(arrive(p, "arrive metadata", 13, metadata, b"", &[]).0);

        t.push(refusal(p, "refusal gate", REFUSAL_GATE, 403, b"denied"));

        let mut s: Frame<ServeIn, ServeOut> = Frame::new(z(), z());
        (s.input.head, s.out.head) = (in_head(), out_head());
        let (mut reply, mut fields, mut arena) = (
            vec![0u8; 256],
            vec![
                OutField {
                    name: Span { offset: 0, len: 0 },
                    value: Span { offset: 0, len: 0 },
                };
                4
            ],
            vec![0u8; 256],
        );
        let target = b"/tools/nope/health";
        s.input.target = AbiStr::of_bytes(target);
        s.input.route = 2;
        (s.input.reply_buf, s.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (s.input.fields_buf, s.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (s.input.arena_buf, s.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let mut step_serve = Step::new("serve", p.call(slot::SERVE, &mut s).outcome);
        step_serve.status = s.out.status;
        t.push(step_serve);
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        t.push(Step::new("project", p.call(slot::PROJECT, &mut j).outcome));

        let mut k = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1_000,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 7,
            },
        );
        let mut s = Step::new("tick", p.call(life::TICK, &mut k).outcome);
        s.detail = format!("next={}", k.out.next_tick_ns);
        t.push(s);
        let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
        (x.input.head, x.out.head) = (in_head(), out_head());
        let mut s = Step::new("cancel", p.call(life::CANCEL, &mut x).outcome);
        s.detail = format!("disposition={}", x.out.disposition);
        t.push(s);

        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        (f.input.generation, f.input.settings) = (2, octets(b""));
        let (c, snapshot) = p.refresh(&mut f);
        let mut s = Step::new("refresh", c.outcome);
        s.snapshot = snapshot;
        t.push(s);

        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        t.push(Step::new("retire", p.call(life::RETIRE, &mut g).outcome));
        let mut e = Frame::new(in_head(), out_head());
        t.push(Step::new("close", p.call(life::CLOSE, &mut e).outcome));
        t
    }

    /// The head field of a JSON answer.
    fn json_type() -> (String, String) {
        ("content-type".to_string(), "application/json".to_string())
    }

    /// A whole answer's stated length (the served engine's JSON answers stated theirs).
    fn length_of(reply: &[u8]) -> (String, String) {
        ("content-length".to_string(), reply.len().to_string())
    }

    fn step<'a>(t: &'a [Step], what: &str) -> &'a Step {
        t.iter()
            .find(|s| s.what == what)
            .unwrap_or_else(|| panic!("the script has no `{what}` step"))
    }

    fn document(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("a JSON document")
    }

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of_loaded(crate::loaded_door())
            .expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the cdylib `cargo test` builds beside the test
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let path = crate::plugin_cdylib();
        let stated = LinkedRow::of_loaded(crate::loaded_door())
            .expect("the door renders its Statement")
            .statement;
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    /// The Statement's sections, as the loader reads them, are the grammar's: `tools:` declared and
    #[test]
    fn the_statements_sections_are_the_grammars() {
        let d = Dispatcher::new(DispatchConfig::default());
        let served = linked(&d).served();
        assert_eq!(served.section, TOOLS_SECTION);
        assert_eq!(served.owns, vec![ENDPOINT_SECTION]);
    }

    /// The linked transcript is the one the plane's own pure functions say the door answers: each
    #[test]
    fn the_door_answers_what_the_plane_says() {
        let d = Dispatcher::new(DispatchConfig::default());
        let t = script(&linked(&d));

        assert_eq!(step(&t, "validate refused").outcome, Outcome::Refused);
        assert_eq!(step(&t, "validate").outcome, Outcome::Ready);
        let open = step(&t, "open");
        assert_eq!(open.outcome, Outcome::Ready);
        let snapshot = open.snapshot.as_ref().expect("open publishes a snapshot");
        assert_eq!(snapshot.generation, 1);
        let claims: Vec<_> = snapshot
            .claims
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();

        let specs: Vec<_> = door_facts::ROUTES
            .iter()
            .zip(door_facts::ROUTES_OPEN)
            .map(|(&(verb, target, carrier), &open)| {
                ServedRoute {
                    verb,
                    target,
                    carrier,
                    open,
                }
                .claim_spec()
            })
            .collect();
        let want: Vec<_> = specs
            .iter()
            .map(|c| {
                (
                    c.verb.as_str(),
                    c.target.as_str(),
                    c.carrier.as_str(),
                    c.flags,
                )
            })
            .collect();
        assert_eq!(claims, want, "the claims are the door's routes");
        assert_eq!(claims.len(), door_facts::ROUTES.len());
        let admin: Vec<_> = snapshot
            .admin_routes
            .iter()
            .map(|r| (r.verb.as_str(), r.target.as_str(), r.flags))
            .collect();
        let want: Vec<_> = door_facts::ADMIN_VERBS
            .iter()
            .map(|&(verb, target)| (verb, target, 0))
            .collect();
        assert_eq!(admin, want, "the admin routes are the door's");

        let audience = Some(format!("{PUBLIC_URL}/mcp"));
        assert_eq!(snapshot.audience, audience);
        assert_eq!(
            snapshot.resource_metadata,
            Some(format!("{PUBLIC_URL}{DEFAULT_METADATA}"))
        );
        assert_eq!(
            snapshot.audience.as_deref(),
            Some("https://busbar.example/mcp")
        );

        let a = step(&t, "arrive tools/list");
        assert_eq!(a.outcome, Outcome::Ready);
        assert_eq!(
            a.detail,
            format!(
                "op_class={} principal_required=true dialect=0 refusal=0",
                door_facts::OP_CLASS_TOOLS_LIST
            )
        );
        let answer = step(&t, "answer tools/list");
        assert_eq!((answer.outcome, answer.status), (Outcome::Ready, 200));
        assert!(
            answer.detail.starts_with("calls=")
                && answer
                    .detail
                    .ends_with("done=true far=false more=0 request="),
            "{}",
            answer.detail
        );
        let calls: usize = answer.detail["calls=".len()..]
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .expect("a call count");
        assert!(
            calls > 1,
            "a 32-byte buffer takes the answer over several calls"
        );
        assert_eq!(
            answer.reply,
            door_facts::WITNESS_TOOLS_LIST_ANSWER,
            "the catalogue's own bytes"
        );
        assert_eq!(document(&answer.reply)["id"], json!(9));
        assert_eq!(
            answer.fields,
            vec![json_type(), length_of(&answer.reply)],
            "a JSON document says so, and states its length"
        );

        let a = step(&t, "arrive notice");
        assert_eq!(a.outcome, Outcome::Ready);
        assert!(a
            .detail
            .starts_with(&format!("op_class={} ", door_facts::OP_CLASS_NOTIFICATION)));
        let n = step(&t, "answer notice");
        assert_eq!(
            (n.outcome, n.status, n.reply.as_slice()),
            (Outcome::Ready, 202, &b""[..])
        );

        assert_eq!(step(&t, "arrive tools/call").outcome, Outcome::Ready);
        let c = step(&t, "answer tools/call");
        assert_eq!((c.outcome, c.status), (Outcome::Ready, 404));
        assert_eq!(
            document(&c.reply)["error"]["data"]["reason"],
            json!("not_granted")
        );
        assert_eq!(step(&t, "far end").outcome, Outcome::Refused);

        let a = step(&t, "arrive not json");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 400));
        let r = step(&t, "refusal not json");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 400));
        let body = document(&r.reply);
        assert_eq!(body["error"]["code"], json!(-32700));
        assert_eq!(body["error"]["message"], json!(door_facts::NOT_JSON));
        assert_eq!(body["id"], Value::Null);

        let a = step(&t, "arrive GET /mcp");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 405));
        let r = step(&t, "refusal GET /mcp");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 405));
        let (error, description) = door_facts::METHOD_NOT_ALLOWED;
        assert_eq!(
            r.reply,
            serde_json::to_vec(&json!({ "error": error, "error_description": description }))
                .expect("a JSON document")
        );
        assert_eq!(
            r.fields,
            vec![("allow".to_string(), "POST".to_string()), json_type()]
        );

        let a = step(&t, "arrive metadata");
        assert_eq!((a.outcome, a.status), (Outcome::Refused, 404));
        assert!(a
            .detail
            .ends_with(&format!("refusal={}", door_facts::UNSERVED)));

        let r = step(&t, "refusal gate");
        assert_eq!((r.outcome, r.status), (Outcome::Ready, 0));
        let body = document(&r.reply);
        assert_eq!(body["error"]["code"], json!(CODE_REFUSED));
        assert_eq!(body["error"]["message"], json!("denied"));

        for what in ["hydrate", "start"] {
            assert_eq!(step(&t, what).outcome, Outcome::Ready, "{what}");
        }
        let serve = step(&t, "serve");
        assert_eq!((serve.outcome, serve.status), (Outcome::Ready, 404));
        assert_eq!(step(&t, "project").outcome, Outcome::Ready, "project");

        assert_eq!(
            step(&t, "tick").detail,
            format!("next={}", 1_000 + 250_000_000)
        );
        assert_eq!(
            step(&t, "cancel").detail,
            format!("disposition={}", plane::CANCEL_ABORTED)
        );
        let refresh = step(&t, "refresh");
        assert_eq!(refresh.outcome, Outcome::Ready);
        let snapshot = refresh.snapshot.as_ref().expect("refresh publishes");
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.audience, audience, "the base URL `open` was lent");
        for what in ["retire", "close"] {
            assert_eq!(step(&t, what).outcome, Outcome::Ready, "{what}");
        }
    }

    /// `refresh` of [`SECTION`] to `generation`, the applied document's other owned sections
    fn refresh_owning(p: &Plugin<Plane>, generation: u64, owned: &[u8]) -> String {
        use busbar_contract::abi::mechanism::call::{Blob, BLOB_OCTETS};
        let extensions = if owned.is_empty() {
            Vec::new()
        } else {
            busbar_contract::abi::mechanism::extensions::encode(&[(plane::EXT_OWNED, owned)])
        };
        let mut f: Frame<RefreshIn, PlaneRefreshOut> = Frame::new(z(), z());
        (f.input.head, f.out.head) = (in_head(), out_head());
        if !extensions.is_empty() {
            // SAFETY: `extensions` outlives the call the blob is lent to.
            f.input.head.extensions = unsafe {
                Blob::from_raw_parts(extensions.as_ptr(), extensions.len(), BLOB_OCTETS, 0)
            };
        }
        (f.input.generation, f.input.settings) = (generation, octets(SECTION));
        let (c, snapshot) = p.refresh(&mut f);
        format!(
            "refresh {:?} {:?} {}",
            c.outcome,
            snapshot.map(|s| s.generation),
            String::from_utf8_lossy(&c.error.unwrap_or_default())
        )
    }

    /// G4: AN APPLY CARRYING A MALFORMED `mcp:` BLOCK IS REFUSED AT `refresh`, in the block's own
    #[test]
    fn an_apply_carrying_a_malformed_endpoint_block_is_refused_at_refresh() {
        let d = Dispatcher::new(DispatchConfig::default());
        for (how, p) in [("linked", linked(&d)), ("dropped in", dropped(&d))] {
            let mut i: PlaneOpenIn = z();
            i.open.head = in_head();
            (i.open.generation, i.open.settings) = (1, octets(SECTION));
            i.public_url = text(PUBLIC_URL.as_bytes());
            let mut o: PlaneOpenOut = z();
            o.open.head = out_head();
            assert_eq!(
                p.open(&mut Frame::new(i, o)).0.outcome,
                Outcome::Ready,
                "{how}: open"
            );
            let refused = refresh_owning(
                &p,
                2,
                br#"{"mcp":{"canonical_uri":"https://gw.example/elsewhere","authorization_servers":["https://l.example"]}}"#,
            );
            assert!(
                refused.starts_with(&format!("refresh {:?} None ", Outcome::Refused)),
                "{how}: a malformed `mcp:` refuses the refresh: {refused}"
            );
            assert!(
                refused.contains("only at `/mcp`"),
                "{how}: in the block's own words: {refused}"
            );
            assert_eq!(
                refresh_owning(
                    &p,
                    3,
                    br#"{"mcp":{"canonical_uri":"https://gw.example/mcp","authorization_servers":["https://l.example"]}}"#,
                ),
                format!("refresh {:?} Some(3) ", Outcome::Ready),
                "{how}: a well-formed `mcp:` refreshes"
            );
            assert_eq!(
                refresh_owning(&p, 4, b""),
                format!("refresh {:?} Some(4) ", Outcome::Ready),
                "{how}: no block refreshes"
            );
        }
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// The kernel refuses with `reason` at its own `status` (no unit had arrived), and the door
    fn kernel_refusal(p: &Plugin<Plane>, reason: u32, status: u32) -> Step {
        let words = b"refused";
        let (mut reply, mut fields, mut arena) = ([0_u8; 512], [z::<OutField>(); 2], [0_u8; 64]);
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        (r.input.cause, r.input.status, r.input.reason) = (plane::REFUSAL_KERNEL, status, reason);
        r.input.text = text(words);
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        let c = p.call(slot::REFUSAL, &mut r);
        let mut s = Step::new("kernel refusal", c.outcome);
        s.status = r.out.status;
        s.reply = reply[..usize::try_from(r.out.reply_written).expect("small")].to_vec();
        s
    }

    #[test]
    fn p_item_refusal_reason_collapse_the_door_answers_every_reason_at_the_kernels_status_never_internal(
    ) {
        use busbar_contract::abi::plane::{reason_of, RefusalCode};
        let d = Dispatcher::new(DispatchConfig::default());
        let p = linked(&d);
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, _) = p.open(&mut Frame::new(i, o));
        assert_eq!(c.outcome, Outcome::Ready, "the door opens");
        let mut rendered = 0;
        for code in RefusalCode::ALL {
            if reason_of(code.code()).is_none() {
                continue;
            }
            let class = code.class();
            let status = if class.is_node_fault() { 500 } else { 403 };
            let r = kernel_refusal(&p, code.code(), status);
            assert_eq!(
                (r.outcome, r.status),
                (Outcome::Ready, 0),
                "{code:?} (class {class:?}) is answered at the kernel's status"
            );
            let body = document(&r.reply);

            let want = if matches!(
                code,
                RefusalCode::Unauthenticated | RefusalCode::BodyTooLarge
            ) {
                json!(-32600)
            } else {
                json!(CODE_REFUSED)
            };
            assert_eq!(
                body["error"]["code"], want,
                "{code:?} (class {class:?}) renders {body}"
            );
            assert_ne!(
                body["error"]["code"],
                json!(CODE_INTERNAL),
                "{code:?} (class {class:?}) is never the internal error"
            );
            rendered += 1;
        }
        assert!(rendered > 0, "the walk rendered at least one reason");
    }

    /// A HOST whose entitlement answer is a fixed table of `"<kind>:<name>"` grants, and which
    struct Grants(&'static [&'static str]);

    impl busbar_contract::services::HostServices for Grants {
        fn now(&self) -> busbar_plugin_loader::dispatch::Reading {
            busbar_plugin_loader::dispatch::Reading {
                wall_ns: 0,
                mono_ns: 0,
            }
        }
        fn dest_judge(
            &self,
            _: &str,
            _: u32,
            _: u32,
            _: Option<busbar_plugin_loader::dispatch::Later>,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_get(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_list(
            &self,
            _: &Caller,
            _: busbar_contract::services::RecordsList,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_claim(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: u64,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn unit_nest(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::NestAsk,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_open(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &str,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_find(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_settle(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: u64,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_resume(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: u64,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn trust_sight(
            &self,
            _: &Caller,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        /// The kernel's Approve as this section's approvals seed it: `read_file` approved at its
        fn trust_serves(
            &self,
            _: &Caller,
            counterparty: &str,
            item: Option<&str>,
            _: Option<&str>,
        ) -> Stored {
            use busbar_contract::abi::host::service::{
                DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN_ITEM,
            };
            Stored::ready(match (counterparty, item) {
                ("fs", Some("read_file")) => DISTRUST_NONE,
                ("fs", Some("draft")) => DISTRUST_NOT_APPROVED,
                _ => DISTRUST_UNKNOWN_ITEM,
            })
        }
        fn trust_due(&self, _: &Caller) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
            Stored::ready(if unit.is_some() && self.0.contains(&target) {
                busbar_contract::abi::host::service::ENTITLED
            } else {
                busbar_contract::abi::host::service::NOT_ENTITLED
            })
        }
        fn random_fill(&self, _: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn records_secret(
            &self,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn disk_append(
            &self,
            _: &busbar_contract::services::DiskDest,
            _: Vec<u8>,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_lookup(
            &self,
            _: &Caller,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn content_scan(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn hook_call(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::HookAsk,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
            busbar_contract::services::Snapshot::Refused(UNSERVED)
        }

        fn trust_unreached(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_sight_item(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _item: &str,
            _digest: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_decide(
            &self,
            _caller: &busbar_contract::services::Caller,
            _key: busbar_contract::services::TrustKeyRef<'_>,
            _expected: Option<&str>,
            _approve: bool,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_state(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn session_emit(
            &self,
            _caller: &busbar_contract::services::Caller,
            _session: u64,
            _bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_mint(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _ttl_secs: u64,
            _record: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_take(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
    }

    /// [`Grants`], and a random source that answers (fresh bytes at every call): a host the plane
    struct Minting(Grants, std::sync::atomic::AtomicU64);

    impl busbar_contract::services::HostServices for Minting {
        fn now(&self) -> busbar_plugin_loader::dispatch::Reading {
            busbar_plugin_loader::dispatch::Reading {
                wall_ns: 0,
                mono_ns: 0,
            }
        }
        fn dest_judge(
            &self,
            _: &str,
            _: u32,
            _: u32,
            _: Option<busbar_plugin_loader::dispatch::Later>,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_get(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_list(
            &self,
            _: &Caller,
            _: busbar_contract::services::RecordsList,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_claim(
            &self,
            _: &Caller,
            _: &str,
            _: &[u8],
            _: u64,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn unit_nest(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::NestAsk,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_open(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &str,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_find(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_settle(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: u64,
            _: &[u8],
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_resume(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: u64,
            _: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(Stored::refused(UNSERVED))
        }
        fn trust_sight(
            &self,
            _: &Caller,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        /// The kernel's Approve as this section's approvals seed it: `read_file` approved at its
        fn trust_serves(
            &self,
            _: &Caller,
            counterparty: &str,
            item: Option<&str>,
            _: Option<&str>,
        ) -> Stored {
            use busbar_contract::abi::host::service::{
                DISTRUST_NONE, DISTRUST_NOT_APPROVED, DISTRUST_UNKNOWN_ITEM,
            };
            Stored::ready(match (counterparty, item) {
                ("fs", Some("read_file")) => DISTRUST_NONE,
                ("fs", Some("draft")) => DISTRUST_NOT_APPROVED,
                _ => DISTRUST_UNKNOWN_ITEM,
            })
        }
        fn trust_due(&self, _: &Caller) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn entitlement_check(&self, _: &Caller, unit: Option<u64>, target: &str) -> Stored {
            Stored::ready(if unit.is_some() && self.0 .0.contains(&target) {
                busbar_contract::abi::host::service::ENTITLED
            } else {
                busbar_contract::abi::host::service::NOT_ENTITLED
            })
        }
        fn random_fill(&self, len: u64) -> Stored {
            let n = self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut stored = Stored::ready(0);
            stored.bytes = (0..len).map(|i| (n as u8).wrapping_add(i as u8)).collect();
            stored
        }
        fn records_secret(
            &self,
            _: &str,
            _: &str,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn disk_append(
            &self,
            _: &busbar_contract::services::DiskDest,
            _: Vec<u8>,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_lookup(
            &self,
            _: &Caller,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn content_scan(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: &[u8],
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn hook_call(
            &self,
            _: &Caller,
            _: Option<u64>,
            _: busbar_contract::services::HookAsk,
            _: busbar_plugin_loader::dispatch::Later,
        ) -> busbar_plugin_loader::dispatch::Ran {
            busbar_plugin_loader::dispatch::Ran::Now(Stored::refused(UNSERVED))
        }
        fn snapshot_read(&self, _: &Caller, _: u32) -> busbar_contract::services::Snapshot {
            busbar_contract::services::Snapshot::Refused(UNSERVED)
        }

        fn trust_unreached(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_sight_item(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _item: &str,
            _digest: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_decide(
            &self,
            _caller: &busbar_contract::services::Caller,
            _key: busbar_contract::services::TrustKeyRef<'_>,
            _expected: Option<&str>,
            _approve: bool,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_state(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn session_emit(
            &self,
            _caller: &busbar_contract::services::Caller,
            _session: u64,
            _bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_mint(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _ttl_secs: u64,
            _record: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_take(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
    }

    use busbar_contract::services::{Caller, Stored, UNSERVED};

    /// Every grant the relayed calls need.
    const ALL: &[&str] = &[
        "mcp_server:fs",
        "mcp_tool:fs_read_file",
        "mcp_tool:fs_draft",
    ];

    /// One server with one approved tool (its `path` argument mirrored in `Mcp-Param-Path`), one
    const RELAY_SECTION: &[u8] = door_facts::RELAY_SECTION;

    /// A relayed call, its path argument mirrored.
    const RELAY_CALL: &[u8] = door_facts::RELAY_CALL;
    const RELAY_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
        field("mcp-param-path", "/a"),
    ];
    /// The same call whose mirrored header disagrees with its body.
    const MISMATCH_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_read_file"),
        field("mcp-param-path", "/b"),
    ];
    /// A call to the tool no schema hash was approved for.
    const DRAFT_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"fs_draft","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const DRAFT_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/call"),
        field(H_MCP_NAME, "fs_draft"),
    ];
    /// A listing from a caller that prefers an event stream.
    const STREAM_LIST_FIELDS: &[Field] = &[
        field(H_PROTOCOL_VERSION, PROTOCOL_VERSION),
        field(H_MCP_METHOD, "tools/list"),
        field("accept", "text/event-stream, application/json"),
    ];

    const JSON_HEAD: &[Field] = &[field("content-type", "application/json")];
    const SSE_HEAD: &[Field] = &[field("content-type", "text/event-stream")];
    /// The far end's answers: a result, a JSON-RPC error, a result streamed after a progress
    const FAR_OK: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"hi"}]}}"#;
    const FAR_ERROR: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#;
    const FAR_SSE: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"busbar-0\",\"progress\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[]}}\n\n";
    /// A gateway in front of the server answered for it: HTTP 502 and a body that is no JSON-RPC.
    const FAR_BAD_GATEWAY: &[u8] = b"<html><body>502 Bad Gateway</body></html>";
    const FAR_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;

    /// THE RELAY SCRIPT: the calls a member answers, the ones the plane refuses itself, and the
    fn relay_script(p: &Plugin<Plane>) -> Vec<Step> {
        let mut t = Vec::new();
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(RELAY_SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        t.push(Step::new("open", p.open(&mut Frame::new(i, o)).0.outcome));

        let post = ("POST", "/mcp");
        let far_answers = [
            ("answer ok", FAR_OK, JSON_HEAD),
            ("answer error", FAR_ERROR, JSON_HEAD),
            ("answer stream", FAR_SSE, SSE_HEAD),
            ("answer ask", FAR_ASK, JSON_HEAD),
        ];
        for (n, (what, far, head)) in (40_u64..).zip(far_answers) {
            t.push(arrive(p, "arrive call", n, post, RELAY_CALL, RELAY_FIELDS).0);
            t.push(push(p, "attempt", n, Push::attempt("fs"), 64));
            t.push(push(p, "send", n, Push::caller(RELAY_CALL), 64));
            t.push(push(p, what, n, Push::far(200, head, far), 64));
        }
        t.push(arrive(p, "arrive unanswered", 45, post, RELAY_CALL, RELAY_FIELDS).0);
        t.push(push(p, "attempt unanswered", 45, Push::attempt("fs"), 64));
        t.push(push(p, "send unanswered", 45, Push::caller(RELAY_CALL), 64));
        t.push(push(p, "answer none", 45, Push::unanswered(), 64));
        t.push(arrive(p, "arrive 5xx", 46, post, RELAY_CALL, RELAY_FIELDS).0);
        t.push(push(p, "attempt 5xx", 46, Push::attempt("fs"), 64));
        t.push(push(p, "send 5xx", 46, Push::caller(RELAY_CALL), 64));
        t.push(push(
            p,
            "answer 5xx",
            46,
            Push::far(502, &[], FAR_BAD_GATEWAY),
            64,
        ));
        t.push(arrive(p, "arrive draft", 50, post, DRAFT_CALL, DRAFT_FIELDS).0);
        t.push(push(p, "attempt draft", 50, Push::attempt("fs"), 64));
        t.push(push(p, "answer draft", 50, Push::caller(DRAFT_CALL), 64));
        t.push(arrive(p, "arrive mismatch", 51, post, RELAY_CALL, MISMATCH_FIELDS).0);
        t.push(push(p, "answer mismatch", 51, Push::caller(RELAY_CALL), 64));
        t.push(arrive(p, "arrive list", 52, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(push(p, "answer list", 52, Push::caller(TOOLS_LIST), 64));
        t.push(
            arrive(
                p,
                "arrive stream list",
                53,
                post,
                TOOLS_LIST,
                STREAM_LIST_FIELDS,
            )
            .0,
        );
        t.push(push(
            p,
            "answer stream list",
            53,
            Push::caller(TOOLS_LIST),
            64,
        ));
        t.push(project(p, "project call", RELAY_CALL));
        t.push(project(p, "project list", TOOLS_LIST));
        t.push(project_with(
            p,
            "project rewritten",
            RELAY_CALL,
            Some(br#"{"messages":[{"role":"user","content":"{\"path\":\"/redacted\"}"}],"tools":null}"#),
        ));
        t.push(project_with(
            p,
            "project unusable rewrite",
            RELAY_CALL,
            Some(br#"{"messages":[{"role":"user","content":"not arguments"}],"tools":null}"#),
        ));
        t
    }

    /// `project` of `body`: the view's scalars and strings and the projected body, read back.
    fn project(p: &Plugin<Plane>, what: &'static str, body: &'static [u8]) -> Step {
        project_with(p, what, body, None)
    }

    /// `project` of `body` with a request-stage hook's `rewrite`: the view's scalars and strings,
    fn project_with(
        p: &Plugin<Plane>,
        what: &'static str,
        body: &'static [u8],
        rewrite: Option<&'static [u8]>,
    ) -> Step {
        let mut arena = vec![0_u8; 4096];
        let mut turns = vec![
            busbar_contract::abi::hook::MessageView {
                role: AbiStr::ABSENT,
                text: AbiStr::ABSENT,
            };
            4
        ];
        let mut j: Frame<ProjectIn, ProjectOut> = Frame::new(z(), z());
        (j.input.head, j.out.head) = (in_head(), out_head());
        j.input.body = octets(body);
        if let Some(rewrite) = rewrite {
            j.input.rewrite = octets(rewrite);
        }
        (j.input.arena_buf, j.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (j.input.messages_buf, j.input.messages_cap) = (turns.as_mut_ptr(), turns.len());
        let c = p.call(slot::PROJECT, &mut j);
        let mut s = Step::new(what, c.outcome);
        if c.outcome == Outcome::Ready {
            let base = arena.as_ptr() as usize;
            let view = j.out.view;

            let span_of = |a: AbiStr| {
                if a.is_absent() {
                    return Span { offset: 0, len: 0 };
                }
                Span {
                    offset: u32::try_from(a.ptr() as usize - base).expect("in the arena"),
                    len: u32::try_from(a.len()).expect("small"),
                }
            };
            s.detail = format!(
                "messages={} chars={} flags={} pool={:?} dialect={}",
                view.message_count,
                view.total_chars,
                view.flags,
                at(&arena, span_of(view.pool)),
                at(&arena, span_of(view.ingress_dialect)),
            );
            if j.out.body.offset != busbar_contract::abi::plane::SPAN_ABSENT {
                s.reply = at(&arena, j.out.body).into_bytes();
            }
            for turn in turns.iter().take(j.out.prompt.messages_len) {
                s.fields.push((
                    format!("turn:{}", at(&arena, span_of(turn.role))),
                    at(&arena, span_of(turn.text)),
                ));
            }
            if j.out.rewritten.len != 0 {
                s.fields
                    .push(("rewritten".to_string(), at(&arena, j.out.rewritten)));
            }
        }
        s
    }

    /// `project`: a call is one turn of tool arguments named by the plane, with its
    #[test]
    fn a_call_projects_its_invocation_for_the_hooks() {
        let t = relay_script(&linked(&served(ALL)));
        let call = step(&t, "project call");
        assert_eq!(call.outcome, Outcome::Ready);
        assert_eq!(
            call.detail,
            format!(
                "messages=1 chars={} flags={} pool=\"fs\" dialect=mcp",
                door_facts::RELAY_CALL_TEXT_CHARS,
                busbar_contract::abi::hook::REQUEST_HAS_TOOLS
            )
        );
        assert_eq!(
            document(&call.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/a" } })
        );
        let list = step(&t, "project list");
        assert_eq!(list.outcome, Outcome::Ready);
        assert!(
            list.reply.is_empty() && list.fields.is_empty(),
            "a listing projects no invocation and no turn: {list:?}"
        );
    }

    /// `project`'s PROMPT VIEW is the served engine's projection of an invocation: one `user` turn,
    #[test]
    fn a_call_projects_one_user_turn_of_its_arguments() {
        let t = relay_script(&linked(&served(ALL)));
        let call = step(&t, "project call");
        assert_eq!(
            call.fields,
            vec![("turn:user".to_string(), r#"{"path":"/a"}"#.to_string())]
        );
    }

    #[test]
    fn a_rewrite_replaces_the_arguments_and_the_rewritten_call_is_projected() {
        let t = relay_script(&linked(&served(ALL)));
        let rewritten = step(&t, "project rewritten");
        assert_eq!(rewritten.outcome, Outcome::Ready);
        assert_eq!(
            document(&rewritten.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/redacted" } })
        );
        let body = rewritten
            .fields
            .iter()
            .find(|(n, _)| n == "rewritten")
            .map(|(_, v)| v.clone())
            .expect("the rewritten request is answered");
        let mut expected = document(RELAY_CALL);
        expected["params"]["arguments"] = json!({ "path": "/redacted" });
        assert_eq!(document(body.as_bytes()), expected);
        let unusable = step(&t, "project unusable rewrite");
        assert_eq!(unusable.outcome, Outcome::Ready);
        assert!(unusable.fields.iter().all(|(n, _)| n != "rewritten"));
        assert_eq!(
            document(&unusable.reply),
            json!({ "tool": "fs_read_file", "arguments": { "path": "/a" } })
        );
    }

    fn served(grants: &'static [&'static str]) -> Dispatcher {
        Dispatcher::with_services(DispatchConfig::default(), Arc::new(Grants(grants)))
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_relay_the_same() {
        let d = served(ALL);
        let want = relay_script(&linked(&d));
        assert_eq!(relay_script(&dropped(&d)), want, "the dropped-in door");
        let d = served(&[]);
        let want = relay_script(&linked(&d));
        assert_eq!(
            relay_script(&dropped(&d)),
            want,
            "the dropped-in door, entitled to nothing"
        );
    }

    /// The relayed call, as the door states it on the wire: the ATTEMPT is taken, the caller's body
    #[test]
    fn a_relayed_call_is_sent_on_settled_metered_logged_and_audited() {
        let t = relay_script(&linked(&served(ALL)));
        let attempt = step(&t, "attempt");
        assert_eq!((attempt.outcome, attempt.reply.len()), (Outcome::Ready, 0));
        let send = step(&t, "send");
        assert_eq!(send.outcome, Outcome::Ready);
        assert!(
            send.detail
                .ends_with("done=false far=true more=0 request=POST /fs/rpc?v=1"),
            "{}",
            send.detail
        );
        assert_eq!(document(&send.reply)["params"]["name"], json!("read_file"));

        let ok = step(&t, "answer ok");
        assert_eq!((ok.outcome, ok.status), (Outcome::Ready, 200));
        assert_eq!(document(&ok.reply)["id"], json!(30));
        assert_eq!(
            document(&ok.reply)["result"]["resultType"],
            json!("complete")
        );
        assert_eq!(ok.fields, vec![json_type(), length_of(&ok.reply)]);
        assert!(ok.detail.contains("done=true far=false"), "{}", ok.detail);

        assert_eq!(
            ok.units,
            vec![
                (CLASS_FEE_INDEX, 1),
                (0, 1),
                (1, u64::try_from(FAR_OK.len()).expect("a small answer"))
            ],
            "the one tool call the server answered, its answer's bytes, and its fee unit"
        );

        assert_eq!(
            ok.records,
            vec![(
                door_facts::RECORD_CALL,
                door_facts::UNGOVERNED.as_bytes().to_vec(),
                door_facts::call_suffix(0, "fs", "fs_read_file", "dispatched", "", "sha256:aa", 1),
            )],
            "one call record"
        );

        assert_eq!(
            ok.audits,
            vec![(
                busbar_contract::abi::plane::AUDIT_APPLIED,
                "mcp_tool.call".to_string(),
                "mcp_tool:fs_read_file".to_string()
            )],
            "one applied audit row"
        );
        assert_eq!(
            send.lane.as_deref(),
            Some("mcp_server:fs"),
            "the call's lane is its server's"
        );
        assert_ne!(
            send.lane.as_deref(),
            Some("fs_read_file"),
            "a per-tool lane is no lane the card can price"
        );

        let error = step(&t, "answer error");
        assert_eq!(document(&error.reply)["result"]["isError"], json!(true));

        let ask = step(&t, "answer ask");
        assert_eq!(ask.status, 403);
        assert_eq!(
            document(&ask.reply)["error"]["data"]["reason"],
            json!("ask_no_sealer")
        );
    }

    #[test]
    fn a_call_its_upstream_never_answered_bills_its_fee_unit_and_no_class() {
        let t = relay_script(&linked(&served(ALL)));
        let send = step(&t, "send unanswered");
        assert!(
            send.detail.contains("far=true"),
            "the call went out: {}",
            send.detail
        );
        let none = step(&t, "answer none");
        assert_eq!((none.outcome, none.status), (Outcome::Ready, 200));
        assert_eq!(document(&none.reply)["id"], json!(30));
        assert_eq!(
            document(&none.reply)["result"]["isError"],
            json!(true),
            "the upstream-failure result: {:?}",
            String::from_utf8_lossy(&none.reply)
        );
        assert_eq!(
            none.units,
            vec![(CLASS_FEE_INDEX, 1)],
            "the fee unit alone: no tool call and no byte was measured"
        );
    }

    /// $ AN UPSTREAM THAT ANSWERED HTTP 5xx WITH NO JSON-RPC BODY IS STILL A SERVED CALL
    #[test]
    fn an_upstream_5xx_that_is_no_json_rpc_counts_as_a_served_call() {
        let t = relay_script(&linked(&served(ALL)));
        let answered = step(&t, "answer 5xx");
        assert_eq!((answered.outcome, answered.status), (Outcome::Ready, 200));
        assert_eq!(
            document(&answered.reply)["result"]["isError"],
            json!(true),
            "the upstream-failure result: {:?}",
            String::from_utf8_lossy(&answered.reply)
        );
        assert_eq!(
            answered.units,
            vec![
                (CLASS_FEE_INDEX, 1),
                (0, 1),
                (
                    1,
                    u64::try_from(FAR_BAD_GATEWAY.len()).expect("a small body")
                )
            ],
            "one tool call, the bytes the far end answered with, and the fee unit"
        );
    }

    /// The calls the plane refuses itself, with a member picked: the catalogue's and the mirror's
    #[test]
    fn a_call_the_plane_refuses_is_answered_and_never_sent() {
        let t = relay_script(&linked(&served(ALL)));
        let draft = step(&t, "answer draft");
        assert_eq!((draft.outcome, draft.status), (Outcome::Ready, 403));
        assert!(
            draft.detail.contains("done=true far=false"),
            "{}",
            draft.detail
        );
        assert_eq!(
            document(&draft.reply)["error"]["data"]["reason"],
            json!("not_approved")
        );
        let mismatch = step(&t, "answer mismatch");
        assert_eq!(mismatch.status, 400);
        assert_eq!(
            document(&mismatch.reply)["error"]["code"],
            json!(CODE_HEADER_MISMATCH)
        );
    }

    /// THE ENTITLEMENT BINDING: what a caller sees and may call is the kernel's answer for it.
    #[test]
    fn what_a_caller_sees_and_calls_is_what_the_kernel_entitles() {
        let granted = relay_script(&linked(&served(ALL)));
        let tools = document(&step(&granted, "answer list").reply)["result"]["tools"].clone();
        assert_eq!(tools.as_array().map(Vec::len), Some(2));
        let none = relay_script(&linked(&served(&[])));
        let tools = document(&step(&none, "answer list").reply)["result"]["tools"].clone();
        assert_eq!(tools, json!([]));
        let refused = step(&none, "send");
        assert_eq!((refused.outcome, refused.status), (Outcome::Ready, 404));
        assert_eq!(
            document(&refused.reply)["error"]["data"]["reason"],
            json!("not_granted")
        );
        assert!(
            refused.detail.contains("far=false"),
            "never sent: {}",
            refused.detail
        );
    }

    /// A caller that prefers an event stream is answered with one: the answer after the plane's
    #[test]
    fn a_caller_preferring_a_stream_is_answered_with_one() {
        let t = relay_script(&linked(&served(ALL)));
        let s = step(&t, "answer stream list");
        assert_eq!(s.status, 200);
        assert_eq!(
            s.fields,
            vec![
                ("content-type".to_string(), "text/event-stream".to_string()),
                (
                    "cache-control".to_string(),
                    "no-cache, no-store".to_string()
                ),
            ]
        );
        let text = String::from_utf8(s.reply.clone()).expect("text");
        let events: Vec<Value> = text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .map(|d| serde_json::from_str(d).expect("an event"))
            .collect();
        assert_eq!(events.last().map(|e| e["id"].clone()), Some(json!(9)));
        assert_eq!(events[0]["method"], json!("notifications/message"));
    }

    /// A call capture for the hand-built table entry below: one slot per thread, as `plugin_door!`
    struct TestCapture;
    impl CaptureHome for TestCapture {
        fn retention() -> &'static busbar_contract::abi::sdk::capture::CaptureRetention {
            static RETENTION: std::sync::OnceLock<
                busbar_contract::abi::sdk::capture::CaptureRetention,
            > = std::sync::OnceLock::new();
            RETENTION.get_or_init(Default::default)
        }
        fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
            thread_local! {
                static SLOT: std::cell::RefCell<CaptureSlot> =
                    std::cell::RefCell::new(CaptureSlot::new());
            }
            SLOT.with(|s| f(&mut s.borrow_mut()))
        }
    }

    /// An `on_piece` that relays the caller's bytes back instead of answering from the catalogue.
    struct Echo;
    impl SafeSlot for Echo {
        type In = OnPieceIn;
        type Out = OnPieceOut;
        type State = ();
        fn call(
            _: Instance<'_, ()>,
            input: Lent<'_, OnPieceIn>,
            mut out: Out<'_, OnPieceOut>,
        ) -> Outcome {
            let bytes = input.bytes().bytes();
            let n = input.reply_buf().stream(bytes);
            out.set(|o| &o.emitted, n as u64);
            out.set(|o| &o.reply_status, 200);
            out.set(|o| &o.flags, EMIT_DONE);
            Outcome::Ready
        }
    }

    /// The mcp door with `on_piece` swapped for [`Echo`].
    extern "C" fn echo_door() -> *const Door {
        let d = door();
        // SAFETY: the macro's `'static` door states a plane table.
        let mut ops = unsafe { *d.ops().cast::<plane::Ops>() };
        ops.on_piece = kind_op::<plane::Ops, Safe<Echo>, TestCapture, { slot::ON_PIECE }>();
        let ops: &'static plane::Ops = Box::leak(Box::new(ops));
        let mut parts = d.parts();
        parts.ops = std::ptr::from_ref(ops).cast();
        // SAFETY: the mcp door's own `'static` Statement, over a leaked plane table whose every
        // slot honours the call convention (one swapped for the SDK's own `kind_op`).
        Box::leak(Box::new(unsafe { Door::__from_parts(parts) }))
    }

    #[test]
    fn red_a_door_that_stops_answering_from_the_catalogue_answers_differently() {
        let d = Dispatcher::new(DispatchConfig::default());
        let honest = script(&linked(&d));
        // SAFETY: `echo_door` answers a leaked `'static`, fully initialised door whose Statement is
        // the macro door's own.
        let row = LinkedRow::of_loaded(unsafe { LoadedDoor::from_raw(echo_door) })
            .expect("the door states its Statement");
        let red = script(&load_linked::<Plane>(&row, bind(&d)).expect("the door loads"));
        let (h, r) = (
            step(&honest, "answer tools/list"),
            step(&red, "answer tools/list"),
        );
        assert_ne!(r.reply, h.reply, "the answer is where the two differ");
        assert_ne!(red, honest);
    }

    /// The host's envelope sink, keeping the text of every diagnostic and log record a call
    /// carried: what the host writes to the plugin's own log file.
    #[derive(Default)]
    struct HostLog(std::sync::Mutex<Vec<String>>);

    impl busbar_plugin_loader::dispatch::EnvelopeSink for HostLog {
        fn metric(&self, _: busbar_plugin_loader::dispatch::Metric<'_>) {}
        fn diag(&self, d: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(String::from_utf8_lossy(d.text).into_owned());
        }
        fn dropped(&self, _: busbar_plugin_loader::dispatch::Dropped) {}
    }

    #[test]
    fn the_ungoverned_stream_diagnostic_reaches_the_host_log_dropped_in_as_linked() {
        let d = Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(Minting(Grants(&[]), std::sync::atomic::AtomicU64::new(1))),
        );
        const ACCEPT: &[Field] = &[field("accept", "text/event-stream")];
        for dropped_in in [false, true] {
            let log = Arc::new(HostLog::default());
            let bound = Bind {
                sink: log.clone(),
                ..bind(&d)
            };
            let p: Plugin<Plane> = if dropped_in {
                let path = crate::plugin_cdylib();
                let stated = LinkedRow::of_loaded(crate::loaded_door())
                    .expect("the door renders its Statement")
                    .statement;
                load_dropped(&path, &stated, bound).expect("the dropped door loads")
            } else {
                let row = LinkedRow::of_loaded(crate::loaded_door())
                    .expect("the linked door states its Statement");
                load_linked(&row, bound).expect("the linked door loads")
            };
            let mut i: PlaneOpenIn = z();
            i.open.head = in_head();
            (i.open.generation, i.open.settings) = (1, octets(SECTION));
            i.public_url = text(PUBLIC_URL.as_bytes());
            let mut o: PlaneOpenOut = z();
            o.open.head = out_head();
            assert_eq!(p.open(&mut Frame::new(i, o)).0.outcome, Outcome::Ready);
            let (arrived, _) = arrive(&p, "stream", 171, ("GET", "/mcp"), b"", ACCEPT);
            assert_eq!(arrived.outcome, Outcome::Ready, "{}", arrived.detail);
            let mut reply = vec![0_u8; 1 << 12];
            let (mut fields, mut arena) = ([z::<OutField>(); 16], vec![0_u8; 4096]);
            let mut records = [z::<RecordWrite>(); 16];
            let mut units = [z::<UnitCount>(); 8];
            let mut i: OnPieceIn = z();
            i.head = in_head();
            (i.unit, i.stream, i.from, i.flags) = (171, 171, FROM_CALLER, 0);
            i.bytes = octets(b"");
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head();
            let mut f = Frame::new(i, o);
            let c = p.call(slot::ON_PIECE, &mut f);
            let said = format!(
                "status={} reply={}",
                f.out.reply_status,
                String::from_utf8_lossy(&reply[..f.out.emitted as usize])
            );
            assert_eq!(c.outcome, Outcome::Ready, "dropped-in {dropped_in}: {said}");
            let lines = log
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(
                lines.iter().any(|l| l.contains("ungoverned chain")),
                "dropped-in {dropped_in}: the diagnostic reaches the host log: {lines:?} ({said})"
            );
        }
    }
}

mod bounds {
    //! WHAT THE DOOR HOLDS AND GATHERS IS BOUNDED. A unit the kernel refuses is over, and the door

    use std::sync::Arc;

    use super::{octets, text, z};
    use busbar_contract::abi::mechanism::call::{Field, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::GenIn;
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
        RecordWrite, RefusalIn, RefusalOut, UnitCount, FROM_CALLER, FROM_FAR_END, PIECE_LAST,
        REFUSAL_GATE,
    };
    use busbar_contract::abi::sdk::door::abi_str;

    use crate::door_facts::{claim, H_MCP_METHOD, H_PROTOCOL_VERSION, PROTOCOL_VERSION};
    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{
        in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
        Plugin,
    };

    const SECTION: &[u8] =
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
    const PUBLIC_URL: &str = "https://busbar.example";
    const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const LIST_FIELDS: &[Field] = &[
        Field {
            name: abi_str(H_PROTOCOL_VERSION),
            value: abi_str(PROTOCOL_VERSION),
        },
        Field {
            name: abi_str(H_MCP_METHOD),
            value: abi_str("tools/list"),
        },
    ];

    /// The linked door, opened over [`SECTION`] and started.
    fn started(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of_loaded(crate::loaded_door())
            .expect("the linked door states its Statement");
        let bind = Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        };
        let p = load_linked(&row, bind).expect("the linked door loads");
        let mut i: PlaneOpenIn = z();
        i.open.head = in_head();
        (i.open.generation, i.open.settings) = (1, octets(SECTION));
        i.public_url = text(PUBLIC_URL.as_bytes());
        let mut o: PlaneOpenOut = z();
        o.open.head = out_head();
        let (c, _) = p.open(&mut Frame::new(i, o));
        assert_eq!(c.outcome, Outcome::Ready, "open");
        for op in [slot::HYDRATE, slot::START] {
            let mut g = Frame::new(
                GenIn {
                    head: in_head(),
                    generation: 1,
                },
                out_head(),
            );
            assert_eq!(p.call(op, &mut g).outcome, Outcome::Ready);
        }
        p
    }

    /// `body` with `fields` arrives as `unit`, POSTed on the mount: its outcome and the status the
    fn arrive(
        p: &Plugin<Plane>,
        unit: u64,
        body: &'static [u8],
        fields: &'static [Field],
    ) -> (Outcome, u32) {
        let route = claim("POST", "/mcp", "http");
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        (a.input.head, a.out.head) = (in_head(), out_head());
        a.input.unit = unit;
        a.input.claim = route;
        (a.input.method, a.input.target) = (text(b"POST"), text(b"/mcp"));
        a.input.body = octets(body);
        (a.input.fields, a.input.fields_len) = (fields.as_ptr(), fields.len());
        let outcome = p.call(slot::ARRIVE, &mut a).outcome;
        (outcome, a.out.refusal_status)
    }

    /// What one `on_piece` answered: its outcome, the status it stated and the bytes it emitted.
    struct Piece {
        outcome: Outcome,
        status: u32,
        reply: Vec<u8>,
    }

    /// One `on_piece` of `unit` from `from` carrying `flags`, `stream` and `caller`, through a
    fn push(
        p: &Plugin<Plane>,
        (unit, from, flags): (u64, u32, u32),
        (stream, caller): (u64, &'static str),
        cap: usize,
    ) -> Piece {
        let mut reply = vec![0_u8; cap];
        let (mut fields, mut arena) = ([z::<OutField>(); 16], vec![0_u8; 4096]);
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut i: OnPieceIn = z();
        i.head = in_head();
        (i.unit, i.from, i.stream) = (unit, from, stream);
        i.caller_ref = text(caller.as_bytes());
        (i.flags, i.bytes) = (flags, octets(TOOLS_LIST));
        (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: OnPieceOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        let c = p.call(slot::ON_PIECE, &mut f);
        let emitted = usize::try_from(f.out.emitted).expect("small");
        Piece {
            outcome: c.outcome,
            status: f.out.reply_status,
            reply: reply[..emitted].to_vec(),
        }
    }

    /// One whole-body `on_piece` of `unit` from `from`: its outcome.
    fn piece(p: &Plugin<Plane>, unit: u64, from: u32) -> Outcome {
        push(p, (unit, from, PIECE_LAST), (0, ""), 1 << 16).outcome
    }

    /// The kernel refuses `unit` (a gate's `403`), and the plane renders the refusal.
    fn refuse(p: &Plugin<Plane>, unit: u64) {
        let (mut reply, mut fields, mut arena) =
            (vec![0_u8; 4096], [z::<OutField>(); 4], vec![0_u8; 512]);
        let mut records = [z::<RecordWrite>(); 4];
        let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
        (r.input.head, r.out.head) = (in_head(), out_head());
        r.input.unit = unit;
        (r.input.cause, r.input.status) = (REFUSAL_GATE, 403);
        r.input.text = text(b"denied");
        (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
        (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
        (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
        (r.input.records_buf, r.input.records_cap) = (records.as_mut_ptr(), records.len());
        assert_eq!(
            p.call(slot::REFUSAL, &mut r).outcome,
            Outcome::Ready,
            "refusal"
        );
    }

    /// A unit the kernel refuses after it arrived is over: the plane no longer holds it, so a
    #[test]
    fn a_unit_the_kernel_refuses_is_dropped() {
        let d = Dispatcher::new(DispatchConfig::default());
        let p = started(&d);
        assert_eq!(
            arrive(&p, 7, TOOLS_LIST, LIST_FIELDS).0,
            Outcome::Ready,
            "arrive"
        );
        refuse(&p, 7);
        assert_eq!(
            piece(&p, 7, FROM_CALLER),
            Outcome::Refused,
            "the refused unit is still held"
        );
    }

    /// A unit a piece of which the plane refuses is over too: nothing else would ever end it.
    #[test]
    fn a_unit_whose_piece_the_plane_refuses_is_dropped() {
        let d = Dispatcher::new(DispatchConfig::default());
        let p = started(&d);
        assert_eq!(
            arrive(&p, 8, TOOLS_LIST, LIST_FIELDS).0,
            Outcome::Ready,
            "arrive"
        );

        assert_eq!(piece(&p, 8, FROM_FAR_END), Outcome::Refused);
        assert_eq!(
            piece(&p, 8, FROM_CALLER),
            Outcome::Refused,
            "the unit whose piece was refused is still held"
        );
    }

    /// A `subscriptions/listen`, opting in to a list category.
    const LISTEN: &[u8] = br#"{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const LISTEN_FIELDS: &[Field] = &[
        Field {
            name: abi_str(H_PROTOCOL_VERSION),
            value: abi_str(PROTOCOL_VERSION),
        },
        Field {
            name: abi_str(H_MCP_METHOD),
            value: abi_str("subscriptions/listen"),
        },
    ];

    /// A HOST WITH A CLOCK: the shared services double, serving `clock.now` (a subscription is
    struct Clocked;

    impl busbar_contract::services::HostServices for Clocked {
        fn now(&self) -> busbar_contract::services::Reading {
            busbar_contract::services::Reading {
                wall_ns: 1_800_000_000_000_000_000,
                mono_ns: 1_000_000_000,
            }
        }

        fn dest_judge(
            &self,
            _dest: &str,
            _class: u32,
            _flags: u32,
            _later: Option<busbar_contract::services::Later>,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn records_get(
            &self,
            _caller: &busbar_contract::services::Caller,
            _kind: &str,
            _key: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn records_list(
            &self,
            _caller: &busbar_contract::services::Caller,
            _list: busbar_contract::services::RecordsList,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn records_claim(
            &self,
            _caller: &busbar_contract::services::Caller,
            _kind: &str,
            _key: &[u8],
            _ttl_ms: u64,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn sign(
            &self,
            _caller: &busbar_contract::services::Caller,
            _data: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_sight(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _hash: &str,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn trust_unreached(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_sight_item(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _item: &str,
            _digest: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_decide(
            &self,
            _caller: &busbar_contract::services::Caller,
            _key: busbar_contract::services::TrustKeyRef<'_>,
            _expected: Option<&str>,
            _approve: bool,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_state(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_serves(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _item: Option<&str>,
            _digest: Option<&str>,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_due(
            &self,
            _caller: &busbar_contract::services::Caller,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn trust_verify(
            &self,
            _caller: &busbar_contract::services::Caller,
            _counterparty: &str,
            _payload: &[u8],
            _signatures: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn entitlement_check(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _target: &str,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn session_emit(
            &self,
            _caller: &busbar_contract::services::Caller,
            _session: u64,
            _bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_mint(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _ttl_secs: u64,
            _record: &[u8],
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn ticket_take(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn random_fill(&self, _len: u64) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn records_secret(
            &self,
            _kind: &str,
            _id: &str,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn unit_nest(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _ask: busbar_contract::services::NestAsk,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn work_open(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _kind: &str,
            _record: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn work_find(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _reference: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn work_settle(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _handle: u64,
            _record: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn work_resume(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _handle: u64,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn disk_append(
            &self,
            _dest: &busbar_contract::services::DiskDest,
            _bytes: Vec<u8>,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn verify_lookup(
            &self,
            _caller: &busbar_contract::services::Caller,
            _key: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn verify_store(
            &self,
            _caller: &busbar_contract::services::Caller,
            _key: &[u8],
            _entry: &[u8],
            _ttl_ms: u64,
        ) -> busbar_contract::services::Stored {
            busbar_contract::services::Stored::refused(busbar_contract::services::UNSERVED)
        }
        fn content_scan(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _content: &[u8],
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn hook_call(
            &self,
            _caller: &busbar_contract::services::Caller,
            _unit: Option<u64>,
            _ask: busbar_contract::services::HookAsk,
            _later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused(
                busbar_contract::services::UNSERVED,
            ))
        }
        fn snapshot_read(
            &self,
            _caller: &busbar_contract::services::Caller,
            _scope: u32,
        ) -> busbar_contract::services::Snapshot {
            busbar_contract::services::Snapshot::Refused(busbar_contract::services::UNSERVED)
        }
    }

    /// A dispatcher whose host serves a clock.
    fn clocked() -> Dispatcher {
        Dispatcher::with_services(DispatchConfig::default(), Arc::new(Clocked))
    }

    /// One caller opening its quota's worth of subscriptions, plus one, cuts off no other caller's
    #[test]
    fn a_caller_at_its_subscription_quota_is_refused_and_evicts_no_other_caller() {
        const QUOTA: u64 = 64;
        let d = clocked();
        let p = started(&d);

        let open = |unit: u64, caller: &'static str, cap: usize| {
            assert_eq!(
                arrive(&p, unit, LISTEN, LISTEN_FIELDS).0,
                Outcome::Ready,
                "arrive listen"
            );
            push(&p, (unit, FROM_CALLER, 0), (unit, caller), cap)
        };
        open(1, "caller-b", 1);
        for unit in 100..100 + QUOTA {
            assert_eq!(open(unit, "caller-a", 1).outcome, Outcome::Ready);
        }
        let over = open(100 + QUOTA, "caller-a", 1 << 16);
        assert_eq!(
            over.status, 429,
            "the caller's extra subscription is refused"
        );
        assert!(
            String::from_utf8_lossy(&over.reply).contains("subscription_quota"),
            "the refusal names its reason"
        );
        let b = push(&p, (1, FROM_CALLER, 0), (1, "caller-b"), 1 << 16);
        assert_eq!(
            b.outcome,
            Outcome::Ready,
            "caller B's stream survives caller A"
        );
        assert!(
            !b.reply.is_empty(),
            "caller B's stream still has its frame to write"
        );
    }

    #[test]
    fn a_subscription_on_a_host_whose_clock_is_unbound_is_refused() {
        let d = Dispatcher::new(DispatchConfig::default());
        let p = started(&d);
        assert_eq!(
            arrive(&p, 1, LISTEN, LISTEN_FIELDS).0,
            Outcome::Ready,
            "arrive listen"
        );
        let refused = push(&p, (1, FROM_CALLER, 0), (1, "caller-a"), 1 << 16);
        assert_eq!(
            refused.status,
            503,
            "a subscription the clock cannot time is refused: {}",
            String::from_utf8_lossy(&refused.reply)
        );
    }

    /// A full unit table refuses the next arrival (429) and never evicts: the first unit is still
    #[test]
    fn a_full_unit_table_refuses_the_next_arrival_and_evicts_nothing() {
        let d = Dispatcher::new(DispatchConfig::default());
        let p = started(&d);
        let mut first_refused = None;
        for unit in 1..=5000 {
            if arrive(&p, unit, TOOLS_LIST, LIST_FIELDS) != (Outcome::Ready, 0)
                && first_refused.is_none()
            {
                first_refused = Some((unit, arrive(&p, unit, TOOLS_LIST, LIST_FIELDS)));
            }
        }
        assert_eq!(
            first_refused,
            Some((4097, (Outcome::Refused, 429))),
            "the arrival past the cap"
        );
        assert_eq!(
            piece(&p, 1, FROM_CALLER),
            Outcome::Ready,
            "the first unit was evicted to make room"
        );
    }
}

fn plugin_cdylib() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
            .expect("build this plugin and set BUSBAR_PLUGIN_CDYLIB to its fresh cdylib"),
    );
    assert!(
        path.is_absolute(),
        "BUSBAR_PLUGIN_CDYLIB must be absolute: {}",
        path.display()
    );
    assert!(
        path.is_file(),
        "the built plugin cdylib is missing: {}",
        path.display()
    );
    path
}
