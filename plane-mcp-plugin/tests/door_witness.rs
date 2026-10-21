// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, LINKED AND DROPPED IN, ANSWERS THE SAME (BUSBAR-1.6.0.md, the plane driver's
//! "Proven by": the plane conformance suite, compiled-in and dropped-in through one table).
//!
//! The linked door (`busbar_plane_mcp::door`, the crate's only public item) and this crate's
//! dropped-in image (its built cdylib, the same door behind `export_door!`) are each admitted
//! through the one loader on one dispatcher and run ONE script through every plane op, each answer
//! read back. The two transcripts must be identical, step for step.
//!
//! What the linked transcript must say, against the plane's own tables and pure functions, is held
//! in the logic crate (`plane-mcp/src/tests/door_witness_tests.rs`), which alone can see them: it
//! runs this same script and relay script. This file reaches the door and nothing else, so the
//! wire facts the script sends are spelled here; the logic crate's copy pins them to its tables.

/// THE MCP PLANE'S CONFORMANCE RIG, BOTH WAYS.
mod both_ways {
    use std::mem::zeroed;
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_OCTETS};
    use busbar_contract::abi::mechanism::lifecycle::{
        slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
    };
    use busbar_contract::abi::plane::{
        slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
        PlaneRefreshOut, ProjectIn, ProjectOut, RecordWrite, RefusalIn, RefusalOut, ServeIn,
        ServeOut, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
        PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_REQUIRED, REFUSAL_ARRIVE, REFUSAL_GATE,
    };
    use busbar_contract::abi::sdk::door::abi_str;
    use busbar_plugin_loader::dispatch::kinds::plane::{OwnedSnapshot, Plane};
    use busbar_plugin_loader::dispatch::{
        in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig,
        Dispatcher, Frame, LinkedRow, NoSink, Plugin,
    };

    // The door: this plugin's one public item.
    use busbar_plane_mcp::door;

    /// The wire's header names and revision (the logic crate's `codec` constants, which its copy of
    /// this script reads).
    const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";
    const H_MCP_METHOD: &str = "mcp-method";
    const H_MCP_NAME: &str = "mcp-name";
    const PROTOCOL_VERSION: &str = "2026-07-28";
    /// The protected-resource metadata path the door serves (the logic crate's
    /// `tool_claims::DEFAULT_METADATA`).
    const DEFAULT_METADATA: &str = "/.well-known/oauth-protected-resource/mcp";
    /// The head of the door's route table, `(verb, target)` in claim order: the claims the script's
    /// arrivals carry (the logic crate's copy pins these rows to its `door::ROUTES`).
    const ROUTES: &[(&str, &str)] = &[("GET", DEFAULT_METADATA), ("POST", "/mcp"), ("GET", "/mcp")];

    fn z<T>() -> T {
        // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
        unsafe { zeroed() }
    }

    fn bind(d: &Dispatcher) -> Bind {
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: d.adopter(),
            // The conformance door is driven op by op and opens nothing: bound as a probe.
            conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
        }
    }

    fn octets(b: &'static [u8]) -> Blob {
        Blob {
            ptr: b.as_ptr(),
            len: b.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    }

    fn text(b: &'static [u8]) -> AbiStr {
        AbiStr {
            ptr: b.as_ptr(),
            len: b.len(),
        }
    }

    fn at(buf: &[u8], s: Span) -> String {
        String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
    }

    // ── the fixtures ─────────────────────────────────────────────────────────────────────────────────

    /// One fronted server, the section the door's own tests read.
    const SECTION: &[u8] =
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
    /// [`SECTION`] as stage 3g deals it to `validate` (`{tools: <section>}`), and a dealt section
    /// the grammar refuses: a server id holding the routing-key separator.
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
    /// an arrival carries.
    fn claim(verb: &str, target: &str) -> u32 {
        let i = ROUTES
            .iter()
            .position(|&(v, t)| v == verb && t == target)
            .expect("the door routes it");
        u32::try_from(i).expect("a small table")
    }

    // ── one step of the transcript ───────────────────────────────────────────────────────────────────

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
        /// status, no bytes; `busbar-kernel` `plane_driver/route.rs`, the far walk's read loop).
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
    /// `from` and zero bytes while the door answers `more = 1`. The bytes of every call, in order,
    /// the head fields and the request line it wrote, and its flags.
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
        r.input.text = AbiStr {
            ptr: words.as_ptr(),
            len: words.len(),
        };
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

        // A request the plane answers from what it holds, written 32 bytes at a time.
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
        // A notification: acknowledged with no body.
        t.push(arrive(p, "arrive notice", 8, post, NOTICE, &[]).0);
        t.push(piece(p, "answer notice", 8, FROM_CALLER, NOTICE, 256));
        // A call the plane sends on: not answered here.
        t.push(arrive(p, "arrive tools/call", 9, post, TOOLS_CALL, CALL_FIELDS).0);
        t.push(piece(
            p,
            "answer tools/call",
            9,
            FROM_CALLER,
            TOOLS_CALL,
            256,
        ));
        // A far end's piece for a unit the plane answered itself.
        t.push(arrive(p, "arrive again", 10, post, TOOLS_LIST, LIST_FIELDS).0);
        t.push(piece(p, "far end", 10, FROM_FAR_END, b"{}", 256));

        // Refused arrivals, each rendered in the plane's own words.
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
        // A refusal the kernel decided (a gate), in the one error envelope.
        t.push(refusal(p, "refusal gate", REFUSAL_GATE, 403, b"denied"));

        // A trust verb naming no registration: `404`, before anything else.
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
        s.input.target = AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        };
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

    // ── the doors ────────────────────────────────────────────────────────────────────────────────────

    fn linked(d: &Dispatcher) -> Plugin<Plane> {
        let row = LinkedRow::of(door).expect("the linked door states its Statement");
        load_linked(&row, bind(d)).expect("the linked door loads")
    }

    /// This crate's dropped-in image, the cdylib `cargo test` builds beside the test
    /// (`conformance::cdylib_of`). A missing artifact is a failure, never a skip: this test IS the
    /// dropped-in door's proof.
    fn dropped(d: &Dispatcher) -> Plugin<Plane> {
        let path = busbar_plugin_loader::conformance::cdylib_of("busbar_plane_mcp_plugin");
        let stated = rendering_of(door).expect("the door renders its Statement");
        load_dropped(&path, &stated, bind(d)).expect("the dropped door loads")
    }

    #[test]
    fn the_linked_and_the_dropped_in_door_answer_every_op_the_same() {
        let d = Dispatcher::new(DispatchConfig::default());
        let linked = script(&linked(&d));
        assert_eq!(script(&dropped(&d)), linked, "the dropped-in door");
    }

    /// The linked transcript is the one the plane's own pure functions say the door answers.
    // ── the relayed call and the entitlement binding ───────────────────────────────────────────────

    /// A HOST whose entitlement answer is a fixed table of `"<kind>:<name>"` grants, and which
    /// serves nothing else: the kernel's entitlement service, as the door asks it. As the kernel's
    /// (`KernelServices::entitled`), a crossing that serves no unit is entitled to nothing: the
    /// loader's request lookup must hand the unit the crossing serves.
    struct Grants(&'static [&'static str]);

    impl busbar_plugin_loader::dispatch::HostServices for Grants {
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
        /// digest, `draft` allowed and pending (ARCHITECT Q3: the door renders the verdict).
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
    }

    use busbar_contract::services::{Caller, Stored, UNSERVED};

    /// Every grant the relayed calls need.
    const ALL: &[&str] = &[
        "mcp_server:fs",
        "mcp_tool:fs_read_file",
        "mcp_tool:fs_draft",
    ];

    /// One server with one approved tool (its `path` argument mirrored in `Mcp-Param-Path`), one
    /// tool awaiting approval, and the `roots` grant with nothing declared to disclose.
    const RELAY_SECTION: &[u8] = br#"{"fs": {"url": "https://mcp.example/fs/rpc?v=1", "pin": {"mechanism": "pinned_pubkey", "key": "sha256/K="}, "grants": {"roots": true}, "tools_allow": {"read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}}, "draft": {}}}}"#;

    /// A relayed call, its path argument mirrored.
    const RELAY_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{"path":"/a"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
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
    /// frame, and an ask for roots busbar holds the grant for and has nothing to disclose.
    const FAR_OK: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"hi"}]}}"#;
    const FAR_ERROR: &[u8] =
        br#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#;
    const FAR_SSE: &[u8] = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"busbar-0\",\"progress\":1}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[]}}\n\n";
    /// A gateway in front of the server answered for it: HTTP 502 and a body that is no JSON-RPC.
    const FAR_BAD_GATEWAY: &[u8] = b"<html><body>502 Bad Gateway</body></html>";
    const FAR_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;

    /// THE RELAY SCRIPT: the calls a member answers, the ones the plane refuses itself, and the
    /// listings the kernel's entitlement narrows; each answer read back.
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
    /// the projected body (`reply`), the prompt view's turns and the rewritten body (`fields`, as
    /// `("turn:<role>", text)` and `("rewritten", body)`), read back through the arena.
    fn project_with(
        p: &Plugin<Plane>,
        what: &'static str,
        body: &'static [u8],
        rewrite: Option<&'static [u8]>,
    ) -> Step {
        let mut arena = vec![0_u8; 4096];
        let mut turns = vec![
            busbar_contract::abi::hook::MessageView {
                role: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                text: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
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
            // A string the view leaves unset (NULL) reads as empty, as a span absent from the arena.
            let span_of = |a: AbiStr| {
                if a.ptr.is_null() {
                    return Span { offset: 0, len: 0 };
                }
                Span {
                    offset: u32::try_from(a.ptr as usize - base).expect("in the arena"),
                    len: u32::try_from(a.len).expect("small"),
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
}
