// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The relayed call, pure: admission in the engine's order and words, the request the client
//! dialect builds, and the far end's answer settled.

use serde_json::{json, Value};

use super::*;
use crate::ask::tests::Plain;
use crate::catalogue::{Catalogue, ToolEntry};
use crate::tests::everyone;

/// Admits one call with no trust verdict against it (every tool serves).
fn admit_call(
    catalogue: &Catalogue,
    id: &Value,
    params: Option<&Value>,
    header: &impl Fn(&str) -> Option<String>,
    admit: &impl Fn(&str, &str) -> bool,
    ask: &mut dyn FnMut(&ToolEntry, &Value) -> crate::ask::AskDecision,
) -> Admission {
    admit_trusted(
        catalogue,
        id,
        params,
        header,
        admit,
        &mut |_| Trust::Verdict(DISTRUST_NONE),
        ask,
    )
}

/// Settles an http round's answer, correlated to the id the round's request carried.
fn settle_call(
    admitted: &AdmittedCall,
    def: Option<&McpServerDefCfg>,
    status: u32,
    raw: &[u8],
    sse: bool,
    round: u32,
) -> Settled {
    let sent = crate::client::jsonrpc::dispatch_request_id(round);
    settle_call_as(admitted, def, status, raw, sse, round, sent)
}

/// The http continuation (`inputResponses` and `requestState`) judged as the door judges it.
fn judge_continuation(
    server: &str,
    bounds: &crate::tools_config::SamplingBoundsCfg,
    continuation: &Value,
) -> Result<(), AskRefusal> {
    judge_input_response(server, bounds, continuation.to_string().len())
}

/// One server: an approved tool whose `path` argument is mirrored in `Mcp-Param-Path`, a tool
/// awaiting approval, a tool that must be answered as a task, and a tool that asks its caller.
const SECTION: &str = r#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
  "grants": {"roots": true},
  "tools_allow": {
    "read_file": {"schema_hash": "sha256:aa", "input_schema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}, "output_schema": {"type": "object", "required": ["n"]}},
    "draft": {},
    "batch": {"schema_hash": "sha256:bb", "task_support": "required"},
    "confirm": {"schema_hash": "sha256:cc", "ask_caller": [{"ok": {"method": "elicitation/create", "params": {"message": "sure?"}}}]}
  }}}"#;

fn section() -> crate::tools_config::ToolsCfg {
    crate::statement::read_tools_section(SECTION.as_bytes()).expect("the section reads")
}

fn catalogue() -> Catalogue {
    Catalogue::build(1, &section())
}

fn params(name: &str, arguments: Value) -> Value {
    json!({ "name": name, "arguments": arguments, "_meta": {} })
}

fn proceed(_: &ToolEntry, _: &Value) -> crate::ask::AskDecision {
    crate::ask::AskDecision::Proceed
}

/// Busbar's own exchange completed with `p`'s `inputResponses` as every round's answers.
fn answering(p: &Value) -> impl FnMut(&ToolEntry, &Value) -> crate::ask::AskDecision {
    let answers = p
        .get("inputResponses")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    move |_: &ToolEntry, _: &Value| crate::ask::AskDecision::Answered(answers.clone())
}

fn no_header(_: &str) -> Option<String> {
    None
}

fn refused(a: Admission) -> (Refusal, Option<CallLine>) {
    match a {
        Admission::Refused(r, line) => (r, line),
        other => panic!("not refused: {other:?}"),
    }
}

fn go(a: Admission) -> AdmittedCall {
    match a {
        Admission::Go(a) => a,
        other => panic!("not admitted: {other:?}"),
    }
}

#[test]
fn a_call_with_no_name_is_malformed_and_logged_with_no_tool() {
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&json!({})),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!((r.status, r.code), (400, crate::codec::CODE_INVALID_PARAMS));
    assert_eq!(r.message, "`params.name` is required and must be a string.");
    let line = line.expect("logged");
    assert_eq!(
        (line.tool.as_str(), line.reason.as_str()),
        ("", "malformed_params")
    );
    assert_eq!(
        line.audit, None,
        "the served engine audited no malformed call"
    );
}

/// RED W11 (website `mcp.md:161,432`: the audit records every check, refusals included): a name
/// past the ceiling is refused, AND the refusal is logged and audited (rejected), under a BOUNDED
/// rendering of the name (a prefix and its byte length, which no real tool name can spell), never
/// the name verbatim.
#[test]
fn an_oversized_name_refusal_is_audited_under_a_bounded_name() {
    let long = "x".repeat(MAX_TOOL_NAME_BYTES + 1);
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params(&long, json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(r.status, 400);
    assert!(r.message.starts_with("`params.name` is 257 bytes"));
    let line = line.expect("the refusal is logged");
    assert_eq!(line.reason, "tool_name_too_long");
    assert_eq!(line.outcome, "refused");
    assert!(
        line.tool.len() < MAX_TOOL_NAME_BYTES && line.tool.contains("257 bytes"),
        "the log holds a bounded rendering of the name: {}",
        line.tool
    );
    let audit = line.audit.expect("the refusal is audited");
    assert!(!audit.applied, "rejected");
    assert!(
        audit.resource.contains("257 bytes") && audit.resource.len() < MAX_TOOL_NAME_BYTES,
        "the audit row names the bounded rendering: {}",
        audit.resource
    );
}

#[test]
fn an_unknown_and_an_ungranted_tool_read_the_same_and_log_apart() {
    let (unknown, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_nope", json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(unknown.status, 404);
    let line = line.expect("logged");
    assert_eq!(line.reason, "unknown_tool");
    assert_eq!(line.audit, Some(AuditRow::tool("fs_nope", false)));
    let (hidden, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_read_file", json!({}))),
        &no_header,
        &|kind: &str, _: &str| kind != crate::statement::SCOPE_TOOL,
        &mut proceed,
    ));
    assert_eq!(hidden.status, 404);
    assert_eq!(
        hidden.message,
        unknown.message.replace("fs_nope", "fs_read_file")
    );
    assert_eq!(line.expect("logged").reason, "not_granted");
}

/// THE KERNEL'S VERDICT, RENDERED (ARCHITECT Q3): the door judges no trust; it renders what the
/// kernel's Approve (`trust.serves`) answered for the called tool. An item never sighted is not
/// found, as an unknown name is; a known one the operator has not approved is refused; every other
/// distrust is refused under its own reason; a server the re-fetch could not reach fails the call
/// as an upstream failure (a tool error), never sent.
#[test]
fn the_kernels_trust_verdict_is_rendered_and_never_judged_here() {
    use busbar_contract::abi::host::service as svc;
    let cases: [(Trust, Option<(u32, &str)>); 8] = [
        (Trust::Verdict(svc::DISTRUST_NONE), None),
        (
            Trust::Verdict(svc::DISTRUST_UNKNOWN_ITEM),
            Some((404, "unknown_tool")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_NOT_APPROVED),
            Some((403, "not_approved")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_CHANGED),
            Some((403, "quarantined")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_QUARANTINED),
            Some((403, "quarantined")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_UNSIGHTED),
            Some((403, "pending")),
        ),
        (
            Trust::Verdict(svc::DISTRUST_UNKNOWN),
            Some((403, "not_serving")),
        ),
        (
            Trust::Unreached("down".to_string()),
            Some((200, "upstream_failed")),
        ),
    ];
    for (trust, want) in cases {
        let mut asked = Vec::new();
        let admission = admit_trusted(
            &catalogue(),
            &json!(1),
            Some(&params("fs_draft", json!({}))),
            &no_header,
            &everyone,
            &mut |entry: &ToolEntry| {
                asked.push((entry.server.clone(), entry.tool.clone()));
                trust.clone()
            },
            &mut proceed,
        );
        assert_eq!(
            asked,
            [("fs".to_string(), "draft".to_string())],
            "the verdict is asked once, of the called tool's registration and trust key"
        );
        match want {
            None => {
                go(admission);
            }
            Some((200, reason)) => match admission {
                Admission::Unreached(body, line) => {
                    let body: Value = serde_json::from_slice(&body).expect("json");
                    assert_eq!(body["result"]["isError"], json!(true), "a tool error");
                    assert_eq!(line.reason, reason);
                    assert_eq!(line.outcome, "refused", "never sent");
                }
                other => panic!("the unreached call is a tool error: {other:?}"),
            },
            Some((status, reason)) => {
                let (r, line) = refused(admission);
                assert_eq!(r.status, status, "{trust:?}");
                assert_eq!(r.data, Some(json!({ "reason": reason })), "{trust:?}");
                assert_eq!(line.expect("logged").reason, reason, "{trust:?}");
            }
        }
    }
}

/// The verdict is asked only of a tool the caller is granted: an ungranted call is not found before
/// the kernel is asked anything.
#[test]
fn the_verdict_is_asked_only_after_the_grants() {
    let (r, _) = refused(admit_trusted(
        &catalogue(),
        &json!(1),
        Some(&params("fs_draft", json!({}))),
        &no_header,
        &|_, _| false,
        &mut |_| panic!("the kernel is asked about an ungranted call"),
        &mut proceed,
    ));
    assert_eq!(r.status, 404);
}

#[test]
fn a_mirrored_parameter_must_agree_with_the_body() {
    let cat = catalogue();
    let p = params("fs_read_file", json!({ "path": "/a" }));
    let (r, line) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(
        (r.status, r.code),
        (400, crate::codec::CODE_HEADER_MISMATCH)
    );
    assert!(r.message.contains("`Mcp-Param-Path`"));
    let line = line.expect("logged");
    assert_eq!(
        line.audit, None,
        "a header mismatch is malformed, never audited"
    );
    assert_eq!(
        (
            line.server.as_str(),
            line.tool.as_str(),
            line.tool_digest.as_str()
        ),
        ("fs", "fs_read_file", "sha256:aa")
    );
    let wrong = |name: &str| (name == "mcp-param-path").then(|| "/b".to_string());
    let (r, _) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &wrong,
        &everyone,
        &mut proceed,
    ));
    assert!(r
        .message
        .ends_with("does not match the body's `arguments.path`."));
    let right = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    let a = go(admit_call(
        &cat,
        &json!(1),
        Some(&p),
        &right,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(a.arguments, json!({ "path": "/a" }));
    assert_eq!(a.progress_token, None);
}

#[test]
fn a_required_task_needs_the_extension() {
    let (r, line) = refused(admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_batch", json!({}))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(
        (r.status, r.code),
        (400, crate::codec::CODE_MISSING_CLIENT_CAPABILITY)
    );
    let line = line.expect("logged");
    assert_eq!(line.reason, REASON_TASKS_UNDECLARED);
    assert_eq!(line.audit, Some(AuditRow::tool("fs_batch", false)));
    let declared = json!({ "name": "fs_batch", "arguments": {},
        "_meta": { crate::codec::META_CLIENT_CAPABILITIES: { "extensions": { TASKS_EXTENSION_ID: {} } } } });
    go(admit_call(
        &catalogue(),
        &json!(1),
        Some(&declared),
        &no_header,
        &everyone,
        &mut proceed,
    ));
}

#[test]
fn an_answer_binds_only_what_was_asked_and_never_a_sent_argument() {
    let cat = catalogue();
    let answered = json!({ "name": "fs_confirm", "arguments": {}, "inputResponses": { "ok": true }, "_meta": {} });
    let a = go(admit_call(
        &cat,
        &json!(1),
        Some(&answered),
        &no_header,
        &everyone,
        &mut answering(&answered),
    ));
    assert_eq!(a.arguments, json!({ "ok": true }));
    let smuggled = json!({ "name": "fs_confirm", "arguments": {}, "inputResponses": { "amount": 1 }, "_meta": {} });
    let (r, line) = refused(admit_call(
        &cat,
        &json!(1),
        Some(&smuggled),
        &no_header,
        &everyone,
        &mut answering(&smuggled),
    ));
    assert_eq!(r.status, 404);
    assert!(r.message.starts_with("the answer named `amount`"));
    assert_eq!(line.expect("logged").reason, REASON_ANSWER_UNDECLARED);
    let rewritten = json!({ "name": "fs_confirm", "arguments": { "ok": false }, "inputResponses": { "ok": true }, "_meta": {} });
    refused(admit_call(
        &cat,
        &json!(1),
        Some(&rewritten),
        &no_header,
        &everyone,
        &mut answering(&rewritten),
    ));
}

/// `fs_read_file` admitted with `arguments`, then judged by `judge` ([`judge_arguments`]).
fn judged(arguments: Value, judge: &mut dyn FnMut(&ToolEntry, &str) -> Option<u64>) -> Admission {
    let p = params("fs_read_file", arguments);
    let header = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    let admission = admit_call(
        &catalogue(),
        &json!(7),
        Some(&p),
        &header,
        &everyone,
        &mut proceed,
    );
    judge_arguments(admission, judge)
}

/// THE ARGUMENT GUARD ASKS THE HOST (BUSBAR-1.6.0.md Appendix C B.3 item 11, `dest.judge`): every
/// host the arguments name is put to the judge for the called tool, an IPv6 literal bracketed as
/// `dest.judge` reads it, and the host's verdict alone decides. A host the plane holds no rule
/// about is refused when the judge refuses it, in the guard's bytes; one the judge admits is sent.
#[test]
fn the_hosts_verdict_decides_an_argument_url() {
    let arguments = json!({ "path": "/a", "fetch": "http://public.example/x", "peer": "https://[2001:db8::1]:8443/" });
    let mut asked = Vec::new();
    let a = go(judged(arguments.clone(), &mut |entry, dest| {
        asked.push((entry.tool.clone(), dest.to_string()));
        Some(busbar_contract::abi::host::service::DEST_ALLOWED)
    }));
    assert_eq!(
        a.arguments, arguments,
        "admitted, the arguments are sent as they came"
    );
    asked.sort();
    assert_eq!(
        asked,
        [
            ("read_file".to_string(), "[2001:db8::1]".to_string()),
            ("read_file".to_string(), "public.example".to_string()),
        ],
        "each host is asked of the host, once, for the called tool"
    );

    let (r, line) = refused(judged(arguments, &mut |_, dest| {
        Some(if dest == "public.example" {
            busbar_contract::abi::host::service::DEST_METADATA
        } else {
            busbar_contract::abi::host::service::DEST_ALLOWED
        })
    }));
    assert_eq!((r.status, r.code), (403, crate::codec::CODE_REFUSED));
    assert_eq!(r.data, Some(json!({ "reason": "tool_argument_refused" })));
    assert!(
        r.message.starts_with("tool argument /fetch carries a URL"),
        "{}",
        r.message
    );
    let line = line.expect("logged");
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        ("refused", "tool_argument_refused")
    );
}

/// A host that gives no verdict (it serves no `dest.judge`, or the judgement failed) refuses the
/// value rather than admitting it unjudged; arguments naming no host never ask it.
#[test]
fn a_host_that_gives_no_verdict_refuses_the_argument() {
    let (r, _) = refused(judged(
        json!({ "path": "/a", "fetch": "https://public.example/" }),
        &mut |_, _| None,
    ));
    assert_eq!(r.status, 403);
    assert!(r.message.contains("could not be checked"), "{}", r.message);
    go(judged(json!({ "path": "/a" }), &mut |_, dest| {
        panic!("no host is named, yet `{dest}` was asked")
    }));
}

fn admitted() -> AdmittedCall {
    let right = |name: &str| (name == "mcp-param-path").then(|| "/a".to_string());
    go(admit_call(
        &catalogue(),
        &json!(7),
        Some(&params("fs_read_file", json!({ "path": "/a" }))),
        &right,
        &everyone,
        &mut proceed,
    ))
}

#[test]
fn the_request_is_the_dialect_builders_at_the_members_path() {
    let section = section();
    let def = section.servers.get("fs").expect("registered");
    let o = outbound(&admitted(), "fs", def, 0, None).expect("reachable");
    assert_eq!((o.verb, o.target.as_str()), ("POST", "/fs"));
    let body: Value = serde_json::from_slice(&o.body).expect("json");
    assert_eq!(
        body["params"]["name"],
        json!("read_file"),
        "the upstream's own name"
    );
    assert_eq!(body["id"], json!(0));
    // A RELAYED ASK NEEDS A CALLER WHO CAN ANSWER IT (Law 11): the roots grant alone advertises
    // nothing to a caller that declared no roots; with the caller's roots declared it is.
    assert_eq!(
        body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES],
        json!({}),
        "nothing is advertised the caller could not answer"
    );
    let mut declaring = admitted();
    declaring.capabilities = json!({ "roots": {}, "sampling": {} });
    let o = outbound(&declaring, "fs", def, 0, None).expect("reachable");
    let body: Value = serde_json::from_slice(&o.body).expect("json");
    assert_eq!(
        body["params"]["_meta"][crate::codec::META_CLIENT_CAPABILITIES],
        json!({ "roots": {} }),
        "the roots grant and the caller's roots advertise roots; an ungranted kind is not"
    );
    assert!(
        o.fields.iter().all(|(n, _)| n != "authorization"),
        "no credential here"
    );
    assert!(o
        .fields
        .contains(&("mcp-name".to_string(), "read_file".to_string())));
}

#[test]
fn the_target_is_the_urls_path_and_query() {
    assert_eq!(path_of("https://h.example"), "/");
    assert_eq!(path_of("https://h.example/a/b"), "/a/b");
    assert_eq!(path_of("https://h.example/a?x=1"), "/a?x=1");
    assert_eq!(path_of("https://h.example?x=1"), "/?x=1");
}

#[test]
fn the_last_event_is_the_answer() {
    let raw = b"event: message\ndata: {\"a\":1}\n\ndata: {\"b\":\ndata: 2}\n\n";
    assert_eq!(last_sse_data(raw), b"{\"b\":\n2}".to_vec());
    assert_eq!(last_sse_data(b"nothing"), Vec::<u8>::new());
}

fn answer_of(s: Settled) -> (u32, Value, CallLine) {
    match s {
        Settled::Answer { status, body, line } => {
            (status, serde_json::from_slice(&body).expect("json"), line)
        }
        other => panic!("an answer: {other:?}"),
    }
}

fn settle_far(far: &str) -> Settled {
    let section = section();
    settle_call(
        &admitted(),
        section.servers.get("fs"),
        200,
        far.as_bytes(),
        false,
        0,
    )
}

/// A result with no `resultType` gets the dialect's `complete` ahead of the upstream's own members,
/// which follow as they came; an empty result is the stamp alone.
#[test]
fn a_result_is_stamped_and_dispatched() {
    let settled = settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"structuredContent":{"n":1}}}"#,
    );
    let Settled::Answer { body: bytes, .. } = &settled else {
        panic!("an answer: {settled:?}")
    };
    assert_eq!(
        String::from_utf8_lossy(bytes),
        r#"{"id":7,"jsonrpc":"2.0","result":{"resultType":"complete","content":[],"structuredContent":{"n":1}}}"#
    );
    let (status, body, line) = answer_of(settled);
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["result"]["resultType"], json!("complete"));
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
    assert_eq!(line.audit, Some(AuditRow::tool("fs_read_file", true)));
    let (_, empty, _) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":0,"result":{ }}"#));
    assert_eq!(empty["result"], json!({ "resultType": "complete" }));
}

/// The far end's answer carrying `result` as the upstream wrote it.
fn far_result(result: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":0,"result":{result}}}"#)
}

/// LAW 11 (THE DESIGN 2126, 2131-2132; product hard rule 3369-3373): a tool's result is the
/// upstream's data and reaches the caller as the upstream sent it. `Vec<String>` and `<b>x</b>` in
/// the content text, in `structuredContent` and in `_meta` are the tool's answer, not markup busbar
/// may strip, and the result's bytes are the upstream's own, member order included.
/// RED arm: a built-in strip served `Vec` for `Vec<String>` and `x` for `<b>x</b>`.
#[test]
fn a_result_reaches_its_caller_as_the_upstream_sent_it() {
    let sent = r#"{"resultType":"complete","structuredContent":{"t":"Vec<String>","n":1,"h":"<b>x</b>"},"content":[{"type":"text","text":"fn f() -> Vec<String> { <b>x</b> }"}],"_meta":{"m":"<i>y</i>"}}"#;
    let settled = settle_far(&far_result(sent));
    let Settled::Answer { body: bytes, .. } = &settled else {
        panic!("an answer: {settled:?}")
    };
    assert!(
        bytes.windows(sent.len()).any(|w| w == sent.as_bytes()),
        "the upstream's result bytes, verbatim: {}",
        String::from_utf8_lossy(bytes)
    );
    let (status, body, line) = answer_of(settled);
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(
        body["result"],
        serde_json::from_str::<Value>(sent).expect("json"),
        "the upstream's result, unchanged"
    );
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
}

/// LAW 11 (THE DESIGN 2131-2132): a `structuredContent` that does not match the tool's published
/// `outputSchema` is still the upstream's answer. It is relayed unchanged; busbar never answers in
/// the upstream's place.
/// RED arm: busbar replaced it with its own `isError` result, "The structured result was NOT
/// served".
#[test]
fn structured_output_breaking_the_published_schema_is_relayed_unchanged() {
    let sent = r#"{"resultType":"complete","content":[],"structuredContent":{}}"#;
    let (status, body, line) = answer_of(settle_far(&far_result(sent)));
    assert_eq!(status, 200);
    assert_eq!(
        body["result"],
        serde_json::from_str::<Value>(sent).expect("json"),
        "the upstream's result, as it came"
    );
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));
    assert_eq!(line.audit, Some(AuditRow::tool("fs_read_file", true)));
}

/// THE TASK PATH SETTLES THE SAME RESULT (Law 11): a task's completed result is the upstream's,
/// stored and served as it came. A source plant, because the task's continuation is reached only
/// through a live door: no rewrite of the result is named on that path.
/// RED arm: `door_tasks.rs` ran the markup strip over every completed task result.
///
/// The plant reads the task path's CODE (comments stripped) for the module under any path or alias
/// (`crate::sanitize`, `super::sanitize`, `use crate::sanitize as s`) and for a call of any of the
/// module's public functions by its own name, however it was imported.
#[test]
fn the_task_path_names_no_rewrite_of_the_result() {
    let code: String = include_str!("../door_tasks.rs")
        .lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains("sanitize"),
        "a task's completed result passes through no markup strip: the task path names the module"
    );
    let strips: Vec<&str> = include_str!("../sanitize.rs")
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("pub fn "))
        .filter_map(|l| l.split('(').next())
        .collect();
    assert!(!strips.is_empty(), "the markup strip's functions are read");
    for strip in strips {
        assert!(
            !code.contains(&format!("{strip}(")),
            "a task's completed result passes through no markup strip: `{strip}` is called"
        );
    }
}

#[test]
fn an_upstream_error_is_a_tool_failure_naming_the_server() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"nope"}}"#,
    ));
    assert_eq!(status, 200);
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert_eq!(
        text,
        "The MCP server `fs` did not complete this tool call: MCP upstream answered JSON-RPC error -32601: nope"
    );
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        ("dispatched", "upstream_failed")
    );
    assert_eq!(
        line.audit,
        Some(AuditRow::tool("fs_read_file", false)),
        "the call went out and did not succeed: rejected"
    );
}

/// LAW 11 (THE DESIGN 2126, 2131-2132; product hard rule 3369-3373): the upstream's JSON-RPC
/// error message is the upstream's data and reaches the caller unchanged inside busbar's failure
/// words; `Vec<String>` and `<b>x</b>` are not markup busbar may strip.
/// RED arm: the failure text ran through the markup strip, serving `Vec` and `x`.
#[test]
fn an_upstream_error_message_reaches_its_caller_unchanged() {
    let (_, body, _) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32602,"message":"want Vec<String>, got <b>x</b>"}}"#,
    ));
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert_eq!(
        text,
        "The MCP server `fs` did not complete this tool call: MCP upstream answered JSON-RPC error -32602: want Vec<String>, got <b>x</b>"
    );
}

/// P-ITEM: EMPTY REPLY / UNARY-EMPTY TERMINALITY (spec DONE item 2, "All P-item behaviours match
/// 1.5.5"; the drive log's P4, commit 470351a480, which the money briefs name "mcp bills empty
/// answer as complete"). An envelope with a real result is the upstream's complete answer; one
/// with neither `result` nor `error` is never settled as one.
///
/// This is a money boundary. A JSON-RPC answer carries exactly one of `result` or `error`; a
/// document with NEITHER used to fall through to a complete answer and charge the caller for a
/// result that never came. On the served door it is the upstream's failure: an `isError` result
/// naming the server, logged `upstream_failed` and audited rejected, never the `dispatched` line
/// of a delivered result. The 1.5.5 behaviour this plane matches is its one surface's (the llm
/// surface; owner correction 2026-09-28): a response the caller cannot use is not billed as a
/// delivered one (v1.5.5 `crates/busbar/src/proxy/response_body.rs:415-440`).
#[test]
fn p_item_empty_reply_only_a_real_result_settles_complete() {
    let (status, body, line) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":0,"result":{}}"#));
    assert_eq!(status, 200);
    assert_eq!(body["result"], json!({ "resultType": "complete" }));
    assert_eq!((line.outcome, line.reason.as_str()), ("dispatched", ""));

    let (status, body, line) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":0}"#));
    assert_eq!(status, 200);
    assert_eq!(body["id"], json!(7));
    assert_eq!(body["result"]["isError"], json!(true));
    let text = body["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.starts_with("The MCP server `fs` did not complete this tool call:")
            && text.contains("neither `result` nor `error`"),
        "{text}"
    );
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        ("dispatched", "upstream_failed"),
        "an empty envelope is the upstream's failure, never a delivered result"
    );
    assert_eq!(line.audit, Some(AuditRow::tool("fs_read_file", false)));
}

#[test]
fn an_answer_to_something_else_is_never_served() {
    let (_, body, _) = answer_of(settle_far(r#"{"jsonrpc":"2.0","id":5,"result":{}}"#));
    assert!(body["result"]["content"][0]["text"]
        .as_str()
        .is_some_and(|t| t.contains("cannot correlate")));
}

#[test]
fn an_ungranted_ask_is_refused_and_never_forwarded() {
    let (status, body, line) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"e":{"method":"elicitation/create"}}}}"#,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_ungranted"));
    assert!(body.get("result").is_none());
    assert_eq!(line.outcome, "refused");
}

/// LAW 11 (U16): a granted roots ask is RELAYED to the caller, its result as it came; busbar
/// answers none of it. RED arm: a satisfier answering from the operator's roots would settle a
/// next round (an answer busbar wrote) instead of handing the upstream's result back.
#[test]
fn a_granted_roots_ask_is_relayed_to_the_caller_as_it_came() {
    let far = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#;
    match settle_far(far) {
        Settled::Relay {
            result,
            round,
            child,
        } => {
            assert_eq!(round, 0);
            assert_eq!(
                child, None,
                "an `input_required` result is not a child's request"
            );
            let sent: Value = serde_json::from_str(far).expect("json");
            assert_eq!(
                result, sent["result"],
                "the upstream's result, byte for byte"
            );
        }
        other => panic!("relayed: {other:?}"),
    }
}

/// LAW 11 (BUSBAR-1.6.0 lines 2127-2132, the relay-only ruling at 418-422): a granted SAMPLING ask
/// is relayed to the caller exactly as the upstream sent it. busbar runs no completion for it on any
/// plane; the caller answers it. A pin: predev already relays on this path, and this holds it there.
#[test]
fn a_granted_sampling_ask_is_relayed_to_the_caller_unchanged() {
    let section = section();
    let mut def = section.servers.get("fs").expect("fs").clone();
    def.grants.sampling = true;
    let far = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"s":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"hi"}}],"maxTokens":5}}},"requestState":"opaque"}}"#;
    match settle_call(&admitted(), Some(&def), 200, far.as_bytes(), false, 0) {
        Settled::Relay {
            result,
            round,
            child,
        } => {
            assert_eq!(round, 0);
            assert_eq!(child, None);
            let sent: Value = serde_json::from_str(far).expect("json");
            assert_eq!(
                result, sent["result"],
                "the upstream's sampling ask, byte for byte"
            );
        }
        other => panic!("relayed: {other:?}"),
    }
}

/// LAW 11 (finding 20): what the caller reads about an upstream's ask says what the code does — the
/// ask is RELAYED to the caller, or not relayed under the operator's policy. It never says busbar
/// satisfies an ask, or that an ask terminates at busbar.
#[test]
fn an_ask_refusal_tells_the_caller_the_ask_is_relayed_never_satisfied() {
    let ungranted = settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"s":{"method":"sampling/createMessage"}}}}"#,
    );
    let mixed =
        settle_far(r#"{"jsonrpc":"2.0","id":0,"result":{"content":[],"requestState":"x"}}"#);
    for settled in [ungranted, mixed] {
        let (status, body, _) = answer_of(settled);
        assert_eq!(status, 403);
        let message = body["error"]["message"].as_str().expect("message");
        for stale in ["satisf", "terminates at busbar", "never forwarded"] {
            assert!(
                !message.contains(stale),
                "the caller-visible text says `{stale}`: {message}"
            );
        }
        assert!(
            message.contains("relayed"),
            "the caller-visible text names the relay: {message}"
        );
    }
}

/// An ask mixing a granted kind with an ungranted one is refused naming the ungranted one: the
/// most privileged kind alone does not decide a map whose lesser entries are ungranted.
#[test]
fn an_ask_mixing_an_ungranted_kind_is_refused() {
    let (status, body, _) = answer_of(settle_far(
        r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"},"e":{"method":"elicitation/create"}}}}"#,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_ungranted"));
    assert!(body["error"]["message"]
        .as_str()
        .is_some_and(|m| m.contains("elicitation")));
}

#[test]
fn the_round_cap_bites_before_the_grant_is_read() {
    let section = section();
    let far = br#"{"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}}}}"#;
    let (status, body, _) = answer_of(settle_call(
        &admitted(),
        section.servers.get("fs"),
        200,
        far,
        false,
        3,
    ));
    assert_eq!(status, 403);
    assert_eq!(body["error"]["data"]["reason"], json!("ask_round_cap"));
}

#[test]
fn a_result_still_carrying_an_ask_is_refused_at_the_terminal_check() {
    assert_eq!(
        upstream_ask_field(&json!({ "requestState": "x" })),
        Some("requestState")
    );
    assert_eq!(upstream_ask_field(&json!({ "content": [] })), None);
}

#[test]
fn a_tasks_verb_is_gated_then_names_no_task_of_this_callers() {
    let undeclared = task_verb(&json!(1), Some(&json!({ "taskId": "t", "_meta": {} })));
    assert_eq!(
        undeclared.code,
        crate::codec::CODE_MISSING_CLIENT_CAPABILITY
    );
    let meta = json!({ crate::codec::META_CLIENT_CAPABILITIES: { "extensions": { TASKS_EXTENSION_ID: {} } } });
    let no_id = task_verb(&json!(1), Some(&json!({ "_meta": meta })));
    assert_eq!(
        (no_id.status, no_id.code),
        (400, crate::codec::CODE_INVALID_PARAMS)
    );
    assert_eq!(
        no_id.message,
        "`params.taskId` is required and must be a string."
    );
    let unknown = task_verb(&json!(1), Some(&json!({ "taskId": "t", "_meta": meta })));
    assert_eq!(
        unknown.message,
        "No task with that `taskId` exists for this caller."
    );
}

/// THE INVOKE REWRITE CONTRACT, as the served engine applied a `prompt: rw` hook's reply to a
/// call's arguments: an object `content`, a JSON-string `content` that parses to an object, or a
/// role-less entry itself; the last usable entry wins; nothing usable is not applied.
#[test]
fn a_rewrite_replaces_the_arguments_by_the_invoke_contract() {
    let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fs_read","arguments":{"path":"/secret"},"_meta":{"k":"v"}}}"#;
    let request = || serde_json::from_slice::<Value>(body).unwrap();
    let args = |rewrite: serde_json::Value| {
        let mut v = request();
        rewritten(&mut v, &serde_json::to_vec(&rewrite).unwrap()).map(|()| {
            assert_eq!(v["params"]["_meta"], serde_json::json!({ "k": "v" }));
            assert_eq!(v["id"], 7);
            v["params"]["arguments"].clone()
        })
    };
    let object = serde_json::json!({ "path": "/x" });
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user", "content": object }] })),
        Some(object.clone())
    );
    assert_eq!(
        args(
            serde_json::json!({ "messages": [{ "role": "user", "content": "{\"path\":\"/x\"}" }] })
        ),
        Some(object.clone())
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "path": "/x" }] })),
        Some(object.clone())
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [
            { "role": "user", "content": { "path": "/first" } },
            { "role": "user", "content": "plain words" },
            { "role": "user", "content": { "path": "/x" } },
        ] })),
        Some(object)
    );
    // Nothing usable: a role with no content, plain text, a scalar, no messages at all.
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user" }] })),
        None
    );
    assert_eq!(
        args(serde_json::json!({ "messages": [{ "role": "user", "content": "7" }] })),
        None
    );
    assert_eq!(args(serde_json::json!({ "tools": [] })), None);
    let mut untouched = request();
    assert_eq!(rewritten(&mut untouched, b"not json"), None);
    assert_eq!(untouched, request());
    // A request that is not a call is never rewritten.
    let mut list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    assert_eq!(
        rewritten(
            &mut list,
            br#"{"messages":[{"role":"user","content":{"path":"/x"}}]}"#
        ),
        None
    );
    assert_eq!(list["params"], json!({}));
}

/// THE AUDIT ROW OF BUSBAR'S OWN ASK (SEAM-L(k)): an ask of the caller is `mcp.caller_ask` applied on
/// the tool; a task created is the call applied; a task that could not start is rejected.
#[test]
fn an_ask_of_the_caller_and_a_task_are_audited_in_the_engines_words() {
    let mut ask = |_: &ToolEntry, _: &Value| crate::ask::AskDecision::Ask {
        asks: Vec::new(),
        request_state: "s".to_string(),
    };
    let line = match admit_call(
        &catalogue(),
        &json!(1),
        Some(&params("fs_confirm", json!({}))),
        &no_header,
        &everyone,
        &mut ask,
    ) {
        Admission::Asked(_, line) => line,
        other => panic!("asked: {other:?}"),
    };
    assert_eq!(
        line.audit,
        Some(AuditRow {
            action: ACTION_CALLER_ASK,
            resource: "mcp_tool:fs_confirm".to_string(),
            applied: true,
        })
    );
    let entry = catalogue().tool("fs_batch").expect("registered").clone();
    assert_eq!(
        task_line(&entry, busbar_contract::vocab::REASON_TASK_CREATED).audit,
        Some(AuditRow::tool("fs_batch", true))
    );
    assert_eq!(
        task_line(&entry, "task_unavailable").audit,
        Some(AuditRow::tool("fs_batch", false))
    );
}

// ---------------------------------------------------------------------------------------------
// THE INPUT-SIDE SAMPLING BOUNDS (owner ruling Q22c, BUSBAR-1.6.0 l.3951): a granted
// `sampling/createMessage` ask is relayed only while it is within `tools.<server>.sampling_bounds`.
// Each bound: one over the cap is refused naming the exact key (RED before this change: it relayed),
// exactly at the cap still relays, and the default applies when the key is omitted.
// ---------------------------------------------------------------------------------------------

/// The `fs` definition with the sampling grant held and `bounds` applied.
fn sampling_def(
    bounds: impl FnOnce(&mut crate::tools_config::SamplingBoundsCfg),
) -> crate::tools_config::McpServerDefCfg {
    let mut def = section().servers.get("fs").expect("fs").clone();
    def.grants.sampling = true;
    bounds(&mut def.sampling_bounds);
    def
}

/// One far-end answer asking `params` as a `sampling/createMessage`, settled under `def`.
fn sampling_settle(def: &crate::tools_config::McpServerDefCfg, params: Value) -> Settled {
    let far = json!({ "jsonrpc": "2.0", "id": 0, "result": {
        "resultType": "input_required",
        "inputRequests": { "s": { "method": "sampling/createMessage", "params": params } },
        "requestState": "opaque"
    }});
    settle_call(
        &admitted(),
        Some(def),
        200,
        far.to_string().as_bytes(),
        false,
        0,
    )
}

fn text_messages(n: usize, text: &str) -> Value {
    Value::Array(
        (0..n)
            .map(|_| json!({ "role": "user", "content": { "type": "text", "text": text } }))
            .collect(),
    )
}

/// Refused: 403, `sampling_bound_exceeded`, the message names `key` and the limit.
fn assert_bound_refused(settled: Settled, key: &str, limit: &str) {
    let (status, body, line) = answer_of(settled);
    assert_eq!(status, 403, "{body}");
    assert_eq!(
        body["error"]["data"]["reason"],
        json!("sampling_bound_exceeded")
    );
    let message = body["error"]["message"].as_str().expect("message");
    assert!(
        message.contains(&format!("tools.fs.sampling_bounds.{key}")),
        "the refusal names the exact key: {message}"
    );
    assert!(message.contains(limit), "and its limit {limit}: {message}");
    assert_eq!(
        (line.outcome, line.reason.as_str()),
        ("refused", "sampling_bound_exceeded")
    );
}

fn assert_relayed(settled: Settled) {
    assert!(
        matches!(settled, Settled::Relay { .. }),
        "within the bound the ask is relayed: {settled:?}"
    );
}

#[test]
fn sampling_max_messages_over_the_cap_is_refused_at_the_cap_relays() {
    let def = sampling_def(|b| b.max_messages = 3);
    assert_bound_refused(
        sampling_settle(&def, json!({ "messages": text_messages(4, "") })),
        "max_messages",
        "3",
    );
    assert_relayed(sampling_settle(
        &def,
        json!({ "messages": text_messages(3, "") }),
    ));
}

#[test]
fn sampling_max_prompt_bytes_counts_the_system_prompt_and_every_message() {
    let def = sampling_def(|b| b.max_prompt_bytes = 10);
    // 4 (system) + 3 + 3 = 10: at the cap.
    let at = json!({ "systemPrompt": "abcd", "messages": text_messages(2, "xyz") });
    assert_relayed(sampling_settle(&def, at));
    let over = json!({ "systemPrompt": "abcde", "messages": text_messages(2, "xyz") });
    assert_bound_refused(sampling_settle(&def, over), "max_prompt_bytes", "10");
}

#[test]
fn sampling_max_stop_sequences_over_the_cap_is_refused_at_the_cap_relays() {
    let def = sampling_def(|b| b.max_stop_sequences = 2);
    let stops = |n: usize| json!({ "messages": [], "stopSequences": vec!["s"; n] });
    assert_bound_refused(sampling_settle(&def, stops(3)), "max_stop_sequences", "2");
    assert_relayed(sampling_settle(&def, stops(2)));
}

#[test]
fn sampling_max_stop_sequence_bytes_over_the_cap_is_refused_at_the_cap_relays() {
    let def = sampling_def(|b| b.max_stop_sequence_bytes = 4);
    assert_bound_refused(
        sampling_settle(&def, json!({ "stopSequences": ["abcde"] })),
        "max_stop_sequence_bytes",
        "4",
    );
    assert_relayed(sampling_settle(&def, json!({ "stopSequences": ["abcd"] })));
}

#[test]
fn sampling_temperature_outside_the_range_is_refused_at_the_edges_relays() {
    let def = sampling_def(|b| {
        b.temperature_min_milli = 200;
        b.temperature_max_milli = 1500;
    });
    assert_bound_refused(
        sampling_settle(&def, json!({ "temperature": 1.6 })),
        "temperature_max_milli",
        "1500",
    );
    assert_bound_refused(
        sampling_settle(&def, json!({ "temperature": 0.1 })),
        "temperature_min_milli",
        "200",
    );
    assert_bound_refused(
        sampling_settle(&def, json!({ "temperature": "hot" })),
        "temperature_min_milli",
        "200",
    );
    assert_relayed(sampling_settle(&def, json!({ "temperature": 0.2 })));
    assert_relayed(sampling_settle(&def, json!({ "temperature": 1.5 })));
    // Absent temperature is never a violation.
    assert_relayed(sampling_settle(&def, json!({})));
}

/// The defaults apply when `sampling_bounds` is not written at all: 64 messages, 65536 prompt bytes,
/// 8 stop sequences of 64 bytes, temperature 0.0..=2.0.
#[test]
fn sampling_bounds_default_when_the_keys_are_omitted() {
    let def = sampling_def(|_| {});
    assert_eq!(
        def.sampling_bounds,
        crate::tools_config::SamplingBoundsCfg {
            max_messages: 64,
            max_prompt_bytes: 65536,
            max_stop_sequences: 8,
            max_stop_sequence_bytes: 64,
            temperature_min_milli: 0,
            temperature_max_milli: 2000,
            max_input_response_bytes: 1_048_576,
        }
    );
    assert_bound_refused(
        sampling_settle(&def, json!({ "messages": text_messages(65, "") })),
        "max_messages",
        "64",
    );
    assert_relayed(sampling_settle(
        &def,
        json!({ "messages": text_messages(64, "") }),
    ));
    assert_bound_refused(
        sampling_settle(&def, json!({ "systemPrompt": "x".repeat(65537) })),
        "max_prompt_bytes",
        "65536",
    );
    assert_relayed(sampling_settle(
        &def,
        json!({ "systemPrompt": "x".repeat(65536) }),
    ));
    assert_bound_refused(
        sampling_settle(&def, json!({ "stopSequences": vec!["s"; 9] })),
        "max_stop_sequences",
        "8",
    );
    assert_bound_refused(
        sampling_settle(&def, json!({ "stopSequences": ["x".repeat(65)] })),
        "max_stop_sequence_bytes",
        "64",
    );
    assert_bound_refused(
        sampling_settle(&def, json!({ "temperature": 2.001 })),
        "temperature_max_milli",
        "2000",
    );
    assert_relayed(sampling_settle(&def, json!({ "temperature": 2.0 })));
}

/// The bound is read where there is no definition too (the defaults), and a roots ask is never
/// measured.
#[test]
fn sampling_bounds_measure_only_sampling_asks() {
    let roots = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list","params":{"messages":[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65]}}}}}"#;
    assert_relayed(settle_far(roots));
}

/// THE CALLER'S REPLY IS BOUNDED TOO (ARCHITECT 2026-10-14): the continuation sent upstream
/// (`inputResponses` with the `requestState` it carries) is measured as serialised; one byte over
/// `max_input_response_bytes` is refused by name (`sampling_bound_exceeded`, 403) and not forwarded,
/// exactly at the cap it is forwarded.
#[test]
fn input_responses_over_the_cap_are_refused_and_not_forwarded_at_the_cap_forwarded() {
    let continuation = json!({
        "inputResponses": { "s": { "action": "accept", "content": { "text": "x".repeat(40) } } },
        "requestState": "opaque"
    });
    let exact = continuation.to_string().len();
    let at = sampling_def(|b| b.max_input_response_bytes = u32::try_from(exact).expect("small"));
    judge_continuation("fs", &at.sampling_bounds, &continuation)
        .expect("exactly at the cap is forwarded");

    let over =
        sampling_def(|b| b.max_input_response_bytes = u32::try_from(exact - 1).expect("small"));
    let refusal = judge_continuation("fs", &over.sampling_bounds, &continuation)
        .expect_err("one byte over is refused");
    assert!(matches!(
        &refusal,
        crate::call::AskRefusal::SamplingBound {
            key: "max_input_response_bytes",
            ..
        }
    ));
    assert_eq!(refusal.audit_reason(), "sampling_bound_exceeded");
    assert!(refusal.to_string().contains(&format!("{exact} bytes")));
    assert_bound_refused(
        crate::call::ask_refused(&admitted(), &refusal),
        "max_input_response_bytes",
        &(exact - 1).to_string(),
    );
}

/// The default cap is 1 MiB: a reply just over it is refused, with the key unwritten.
#[test]
fn input_responses_default_cap_is_one_mebibyte() {
    let def = sampling_def(|_| {});
    assert_eq!(def.sampling_bounds.max_input_response_bytes, 1_048_576);
    let big = json!({ "inputResponses": { "s": "y".repeat(1_048_576) } });
    judge_continuation("fs", &def.sampling_bounds, &big).expect_err("over");
    let small = json!({ "inputResponses": { "s": "y" }, "requestState": "z" });
    judge_continuation("fs", &def.sampling_bounds, &small).expect("under");
}

// ---------------------------------------------------------------------------------------------
// BUSBAR'S OWN ANSWERS ACROSS ROUNDS AND ACROSS A RELAYED ASK (row 159 mcp findings C-M5, C-M6):
// what went out on the first call is what goes out on every retry of the same exchange, plus the
// answers of the round the retry closes.
// ---------------------------------------------------------------------------------------------

/// A tool whose operator asks its caller in TWO rounds before it runs.
const TWO_ROUNDS: &str = r#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"},
  "tools_allow": {
    "pay": {"schema_hash": "sha256:dd", "ask_caller": [
      {"confirm": {"method": "elicitation/create", "params": {"message": "sure?"}}},
      {"really": {"method": "elicitation/create", "params": {"message": "really sure?"}}}
    ]}
  }}}"#;

/// `p` admitted with busbar's own ask decided over `seal`, as the door decides it.
fn admit_asking(cat: &Catalogue, seal: &mut Plain, p: &Value) -> Admission {
    let mut ask = |entry: &ToolEntry, arguments: &Value| {
        let retry = crate::ask::Retry {
            responses: p.get("inputResponses"),
            state: p.get("requestState").and_then(Value::as_str),
        };
        let bind = crate::ask::Bind {
            principal: "k",
            method: crate::codec::METHOD_TOOLS_CALL,
            capability: &entry.namespaced,
            generation: 1,
            now: 100,
            roots_epoch: 0,
        };
        crate::ask::decide(
            &entry.ask_caller,
            3,
            &json!({ "elicitation": {} }),
            retry,
            bind,
            &crate::ask::digest_arguments(arguments),
            Some(&mut *seal),
        )
    };
    admit_call(cat, &json!(1), Some(p), &no_header, &everyone, &mut ask)
}

/// The `requestState` an `input_required` answer carries.
fn asked_state(a: Admission) -> String {
    let Admission::Asked(body, _) = a else {
        panic!("busbar asks its caller: {a:?}");
    };
    let body: Value = serde_json::from_slice(&body).expect("json");
    body["result"]["requestState"]
        .as_str()
        .expect("a sealed state")
        .to_string()
}

/// C-M6: an exchange of two rounds goes out with BOTH rounds' answers. The caller's retry answers
/// the round it was asked (MRTR: `inputResponses` answers the `inputRequests` of the result it
/// retries), so the earlier round's answers ride in the sealed state, not in the caller's memory.
#[test]
fn a_two_round_exchange_goes_out_with_every_rounds_answers() {
    let section = crate::statement::read_tools_section(TWO_ROUNDS.as_bytes()).expect("reads");
    let cat = Catalogue::build(1, &section);
    let mut seal = Plain::default();
    let first = json!({ "name": "fs_pay", "arguments": { "amount": 5 }, "_meta": {} });
    let s0 = asked_state(admit_asking(&cat, &mut seal, &first));
    let mut second = first.clone();
    second["inputResponses"] = json!({ "confirm": { "action": "accept" } });
    second["requestState"] = json!(s0);
    let s1 = asked_state(admit_asking(&cat, &mut seal, &second));
    let mut last = first.clone();
    last["inputResponses"] = json!({ "really": { "action": "accept" } });
    last["requestState"] = json!(s1);
    let a = go(admit_asking(&cat, &mut seal, &last));
    assert_eq!(
        a.arguments,
        json!({
            "amount": 5,
            "confirm": { "action": "accept" },
            "really": { "action": "accept" },
        }),
        "the first round's answer is lost when the last round's retry carries only its own"
    );
}

/// C-M5: the retry of an upstream's ask relayed to the caller goes out as the first call did (the
/// caller's arguments with busbar's own answers merged), plus the upstream's answers in the
/// continuation. The relayed state carries busbar's own answers sealed (`a`).
#[test]
fn a_relayed_asks_retry_goes_out_with_busbars_own_answers_merged_again() {
    let leg: crate::ask::UpstreamLeg = serde_json::from_value(json!({
        "m": "fs", "s": "theirs", "r": 1, "a": { "ok": true }
    }))
    .expect("a leg reads");
    let retry = json!({ "name": "fs_confirm", "arguments": { "n": 1 },
        "inputResponses": { "u": { "action": "accept" } }, "requestState": "ours", "_meta": {} });
    let mut relayed = |_: &ToolEntry, _: &Value| crate::ask::AskDecision::Relayed(leg.clone());
    let a = go(admit_call(
        &catalogue(),
        &json!(1),
        Some(&retry),
        &no_header,
        &everyone,
        &mut relayed,
    ));
    assert_eq!(
        a.arguments,
        json!({ "n": 1, "ok": true }),
        "the retry must be the same request as the first call: busbar's own answer is merged again"
    );
    let relay = a.relay.expect("the relayed retry");
    assert_eq!(
        relay.continuation["inputResponses"],
        json!({ "u": { "action": "accept" } }),
        "the caller's answers go to the upstream, not into the arguments"
    );
}

/// C-M7 (owner ruling Q22c): `max_prompt_bytes` measures every content part an ask carries, not
/// only its text: an image, an audio clip or an embedded resource is prompt the caller's model is
/// handed, and an upstream picks its size.
#[test]
fn sampling_max_prompt_bytes_counts_every_content_part() {
    let def = sampling_def(|b| b.max_prompt_bytes = 64);
    for part in [
        json!({ "type": "image", "data": "x".repeat(100), "mimeType": "image/png" }),
        json!({ "type": "audio", "data": "x".repeat(100), "mimeType": "audio/wav" }),
        json!({ "type": "resource", "resource": { "uri": "file:///a", "text": "x".repeat(100) } }),
    ] {
        let settled = sampling_settle(
            &def,
            json!({ "messages": [{ "role": "user", "content": part }] }),
        );
        assert!(
            matches!(settled, Settled::Answer { .. }),
            "a {} part past max_prompt_bytes must be refused, got {settled:?}",
            part["type"]
        );
        assert_bound_refused(settled, "max_prompt_bytes", "64");
    }
    // In an array of parts too.
    let mixed = json!({ "messages": [{ "role": "user", "content": [
        { "type": "text", "text": "hi" },
        { "type": "image", "data": "x".repeat(100), "mimeType": "image/png" }
    ] }] });
    let settled = sampling_settle(&def, mixed);
    assert!(
        matches!(settled, Settled::Answer { .. }),
        "an image beside a text part must be measured, got {settled:?}"
    );
    // The control: a small image is within the bound.
    let small = json!({ "messages": [{ "role": "user", "content":
        { "type": "image", "data": "xx", "mimeType": "image/png" } }] });
    assert_relayed(sampling_settle(&def, small));
}

/// C-M5, the sealing half: the relayed state's leg carries busbar's own answers the call went out
/// with ([`own_answers`]), and its retry goes out with the first call's arguments exactly.
#[test]
fn the_relayed_leg_seals_the_answers_the_first_call_went_out_with() {
    let cat = catalogue();
    let first = json!({ "name": "fs_confirm", "arguments": { "n": 1 },
        "inputResponses": { "ok": true }, "_meta": {} });
    let sent = go(admit_call(
        &cat,
        &json!(1),
        Some(&first),
        &no_header,
        &everyone,
        &mut answering(&first),
    ));
    assert_eq!(sent.arguments, json!({ "n": 1, "ok": true }));
    let answers = own_answers(&sent);
    assert_eq!(answers, json!({ "ok": true }).as_object().cloned());
    let leg = crate::ask::UpstreamLeg {
        member: "fs".into(),
        state: None,
        round: 1,
        child: None,
        answers,
    };
    let retry = json!({ "name": "fs_confirm", "arguments": { "n": 1 },
        "inputResponses": { "u": true }, "requestState": "ours", "_meta": {} });
    let mut relayed = |_: &ToolEntry, _: &Value| crate::ask::AskDecision::Relayed(leg.clone());
    let again = go(admit_call(
        &cat,
        &json!(1),
        Some(&retry),
        &no_header,
        &everyone,
        &mut relayed,
    ));
    assert_eq!(again.arguments, sent.arguments);
    assert_eq!(again.sent_digest, sent.sent_digest);
    // A call that went out with none seals none.
    let plain = go(admit_call(
        &cat,
        &json!(1),
        Some(&params("fs_confirm", json!({ "n": 1 }))),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    assert_eq!(own_answers(&plain), None);
}

/// RED W10 (website `mcp.md:141-144`: an unknown and an ungranted tool give "the same words"): the
/// two answers are BYTE-IDENTICAL on the wire, status, message and `data` alike, whether the plane
/// refuses the ungranted call itself or renders the kernel's grant denial ([`not_granted`]): a
/// caller probing names learns only that there is nothing there for it. The per-call log keeps
/// the two apart (`unknown_tool`, `not_granted`), where the operator reads them.
#[test]
fn an_unknown_and_an_ungranted_tool_are_byte_identical_on_the_wire() {
    let id = json!(7);
    let asked = params("fs_read_file", json!({}));
    let (unknown, unknown_line) = refused(admit_call(
        &Catalogue::build(1, &crate::tools_config::ToolsCfg::default()),
        &id,
        Some(&asked),
        &no_header,
        &everyone,
        &mut proceed,
    ));
    let (ungranted, ungranted_line) = refused(admit_call(
        &catalogue(),
        &id,
        Some(&asked),
        &no_header,
        &|kind: &str, _: &str| kind != crate::statement::SCOPE_TOOL,
        &mut proceed,
    ));
    let denied = not_granted(&id, "fs_read_file");
    assert_eq!(unknown.status, ungranted.status);
    assert_eq!(
        String::from_utf8(unknown.body()).unwrap(),
        String::from_utf8(ungranted.body()).unwrap(),
        "an unknown and an ungranted tool read the same on the wire"
    );
    assert_eq!(
        (denied.status, denied.body()),
        (ungranted.status, ungranted.body())
    );
    assert_eq!(unknown_line.expect("logged").reason, "unknown_tool");
    assert_eq!(ungranted_line.expect("logged").reason, "not_granted");
}

/// RED W7 (security.md: a redirect is a failure, never followed): a relayed call's far end that
/// answers `302` is an upstream failure, whatever well-formed result rides it: the result is never
/// served to the caller.
#[test]
fn a_302_from_the_upstream_is_a_failure_not_a_result() {
    let section = section();
    let far = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the redirect"}]}}"#;
    let (_, body, line) = answer_of(settle_call(
        &admitted(),
        section.servers.get("fs"),
        302,
        far.as_bytes(),
        false,
        0,
    ));
    assert_eq!(
        body["result"]["isError"],
        json!(true),
        "an upstream failure: {body}"
    );
    assert!(
        !body.to_string().contains("from the redirect"),
        "nothing the redirect carried is served: {body}"
    );
    assert_eq!(line.reason, vocab::REASON_UPSTREAM_FAILED, "{line:?}");
}

/// One approved tool `t` on server `s` whose input schema is `schema`.
fn entry_with_schema(schema: &Value) -> ToolEntry {
    let section = json!({"s": {"url": "https://mcp.example/s", "pin": {"mechanism": "unpinned"},
        "tools_allow": {"t": {"schema_hash": "sha256:aa", "input_schema": schema}}}});
    let section = crate::statement::read_tools_section(section.to_string().as_bytes())
        .expect("the section reads");
    Catalogue::build(1, &section)
        .tool("s_t")
        .expect("approved")
        .clone()
}

/// M1-7: an `x-mcp-header` may annotate an integer or a boolean. The body's value is rendered as
/// the header carries it (a decimal integer, `true`/`false`), so a header that mirrors it agrees,
/// one that does not disagrees, and a body that sets it with no header is refused.
#[test]
fn an_integer_or_boolean_annotated_argument_is_compared_as_the_header_renders_it() {
    let entry = entry_with_schema(&json!({"type": "object", "properties": {
        "count": {"type": "integer", "x-mcp-header": "Count"},
        "dry": {"type": "boolean", "x-mcp-header": "Dry"}
    }}));
    let headers = |count: &'static str, dry: &'static str| {
        move |name: &str| match name {
            "mcp-param-count" => Some(count.to_string()),
            "mcp-param-dry" => Some(dry.to_string()),
            _ => None,
        }
    };
    let args = json!({"count": 42, "dry": true});
    assert_eq!(
        custom_param_mismatch(&entry, &args, &headers("42", "true")),
        None,
        "the header mirrors the body"
    );
    assert!(custom_param_mismatch(&entry, &args, &headers("41", "true"))
        .is_some_and(|m| m.contains("does not match")));
    assert!(
        custom_param_mismatch(&entry, &args, &headers("42", "false"))
            .is_some_and(|m| m.contains("does not match"))
    );
    assert!(
        custom_param_mismatch(&entry, &args, &no_header).is_some(),
        "a body that sets an annotated integer must carry its header"
    );
}

/// M1-8: an annotation on a nested property, reached through a chain of `properties`, is validated
/// against the argument at that path.
#[test]
fn a_nested_annotated_argument_is_compared_with_its_header() {
    let entry = entry_with_schema(&json!({"type": "object", "properties": {
        "opts": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"}
        }}
    }}));
    let args = json!({"opts": {"region": "a"}});
    let wrong = |name: &str| (name == "mcp-param-region").then(|| "b".to_string());
    assert!(
        custom_param_mismatch(&entry, &args, &wrong).is_some(),
        "a nested annotated argument the header disagrees with is refused"
    );
    let right = |name: &str| (name == "mcp-param-region").then(|| "a".to_string());
    assert_eq!(custom_param_mismatch(&entry, &args, &right), None);
}

/// M1-9: the relayed request mirrors every annotated argument into its `Mcp-Param-*` header, as a
/// conforming client must, or a server that checks the mirror refuses it.
#[test]
fn the_relayed_request_mirrors_its_annotated_arguments() {
    let section = section();
    let def = section.servers.get("fs").expect("registered");
    let o = outbound(&admitted(), "fs", def, 0, None).expect("reachable");
    assert!(
        o.fields
            .contains(&("mcp-param-path".to_string(), "/a".to_string())),
        "the annotated `path` argument is mirrored: {:?}",
        o.fields
    );
}
