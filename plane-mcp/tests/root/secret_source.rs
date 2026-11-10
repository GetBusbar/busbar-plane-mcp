// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::serve::planes_tests::PUBLISHING;
use crate::root::serve::secret_source_tests as scan;
use axum::http::{HeaderMap, StatusCode};
use busbar_contract::secret::SecretAxis;
use busbar_contract::secret_ref::SecretRef;

struct SourceFixture {
    reference: SecretRef,
    needles: Vec<String>,
}
impl SourceFixture {
    fn new(role: &str, value: &str) -> Self {
        #[cfg(distribution_root)]
        crate::dist_root_install::install();
        let reference = crate::root::linked::secret_rows()
            .sugars()
            .reference_for_role(role, value)
            .expect("the actual linked source declares the fixture role");
        let mut needles = scan::source_needles();
        needles.extend([value.to_owned(), reference.describe()]);
        Self { reference, needles }
    }
}
fn authored(secret: &SourceFixture) -> serde_json::Value {
    serde_json::to_value(
        secret
            .reference
            .authoring(&busbar_contract::caps::KernelSeal::acquire_for_kernel()),
    )
    .expect("the authored source reference")
}
fn source_in(render: &str, secret: &SourceFixture) -> Vec<String> {
    scan::source_in(render, &secret.needles)
}
fn assert_clean(
    case: &str,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
    secret: &SourceFixture,
) {
    scan::assert_clean(case, status, headers, body, &secret.needles);
}
fn refused_naming_its_source(secret: &SourceFixture) -> String {
    #[cfg(distribution_root)]
    crate::dist_root_install::install();
    let text = busbar_kernel::config::secret::resolve_linked_string_at_config(
        &secret.reference,
        &busbar_contract::config_time::ConfigScope::config_time(),
    )
    .expect_err("the actual source refuses the reference");
    assert!(
        !source_in(&text, secret).is_empty(),
        "the actual source refusal must make the caller scan meaningful: {text}"
    );
    text
}
fn missing(case: &str) -> String {
    std::env::temp_dir()
        .join(format!(
            "busbar-secret-source-{case}-{}",
            std::process::id()
        ))
        .display()
        .to_string()
}
fn file(path: impl AsRef<str>) -> SourceFixture {
    SourceFixture::new(
        busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
        path.as_ref(),
    )
}
fn unset(case: &str) -> String {
    let var = format!("BUSBAR_SECRET_SOURCE_{case}_{}", std::process::id());
    std::env::remove_var(&var);
    var
}
fn env(key: impl AsRef<str>) -> SourceFixture {
    SourceFixture::new(
        busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL,
        key.as_ref(),
    )
}
use crate::root::serve::plane_mcp_door::tool_door::{
    send_headed, surface, three_tools, tool_digest, try_rig_tools, Rig, TlsToolServer, CALL,
};
use scan::rendered;
use std::sync::{Arc, Mutex};

fn program_section(secret: &SourceFixture) -> serde_yaml::Value {
    let mut fs = serde_yaml::Mapping::new();
    fs.insert(
        "transport".into(),
        crate::root::serve::lines::carrier()
            .expect("this build links a line carrier")
            .into(),
    );
    fs.insert("command".into(), "/bin/sh".into());
    fs.insert(
        "cwd".into(),
        std::env::current_dir()
            .expect("an absolute fixture cwd")
            .to_str()
            .expect("a UTF-8 fixture cwd")
            .into(),
    );
    fs.insert(
        "args".into(),
        serde_yaml::Value::Sequence(vec![
            "-c".into(),
            crate::root::serve::plane_mcp_door::program_member::script().into(),
        ]),
    );
    let reference = authored(secret);
    let environment: serde_yaml::Mapping =
        serde_yaml::from_str(&format!("{{ env: {{ TOKEN: {reference} }} }}")).expect("a reference");
    for (key, value) in environment {
        fs.insert(key, value);
    }
    fs.insert(
        "pin".into(),
        serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").expect("a pin"),
    );
    fs.insert(
        "tools_allow".into(),
        serde_yaml::from_str(&format!(
            "{{ read_file: {{ schema_hash: \"{}\" }} }}",
            tool_digest()
        ))
        .expect("an approval"),
    );
    let mut tools = serde_yaml::Mapping::new();
    tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
    serde_yaml::Value::Mapping(tools)
}

fn exchange_section(server: &TlsToolServer, secret: &SourceFixture) -> serde_yaml::Value {
    let mut tools = server.section();
    tools["fs"]["allow_private"] = true.into();
    tools["fs"]["aud"] = format!("https://127.0.0.1:{}", server.port).into();
    tools["fs"]["tools_allow"]["write_file"] = serde_yaml::from_str(&format!(
        "{{ schema_hash: \"{}\" }}",
        surface("write_digest"),
    ))
    .expect("an approval");
    tools["fs"]["tools_allow"]["stat"] = serde_yaml::from_str(&format!(
        "{{ schema_hash: \"{}\" }}",
        surface("stat_digest"),
    ))
    .expect("an approval");
    tools["fs"]["token_exchange"] = serde_yaml::to_value(serde_json::json!({
        "token_url": "https://as.example/token",
        "subject_token": authored(secret),
    }))
    .expect("an exchange with a reference");
    tools
}

async fn call(rig: &Rig) -> (StatusCode, HeaderMap, Vec<u8>) {
    send_headed(
        &rig.router,
        Some(&rig.bound_token()),
        CALL,
        "tools/call",
        Some("fs_read_file"),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_unresolved_env_reaches_the_caller_without_its_source() {
    const TEST: &str = concat!(
        module_path!(),
        "::tool_door_a_program_members_unresolved_env_reaches_the_caller_without_its_source"
    );
    let Some(case) = crate::root::door_steps::tests::isolated_fixture_cases(
        TEST,
        &["tools-program-env", "tools-program-file"],
    ) else {
        return;
    };
    let _one = PUBLISHING.lock().await;
    let cases = [
        ("tools-program-env", env(unset("TOOLS_PROGRAM_ENV"))),
        ("tools-program-file", file(missing("tools-program-file"))),
    ];
    for (instance, secret) in cases {
        if instance != case {
            continue;
        }
        refused_naming_its_source(&secret);
        let rig = try_rig_tools(instance, 0, program_section(&secret)).await.unwrap_or_else(|e| {
            panic!("{instance}: a member's env that did not resolve refuses its spawns, never the compose: {e}")
        });
        let (status, headers, body) = call(&rig).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the tool returns its failure result"
        );
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(answer["id"], 30);
        assert_eq!(answer["result"]["isError"], true);
        assert!(
            answer["result"]["content"][0]["text"]
                .as_str()
                .expect("the tool failure text")
                .contains(busbar_contract::conn::ConnError::Refused.text()),
            "{instance}: the failed spawn reaches the caller as the connector's refusal"
        );
        assert_clean(instance, status, &headers, &body, &secret);
        assert!(
            !String::from_utf8_lossy(&body).contains("from the server"),
            "{instance}: the member is not served"
        );
    }
    crate::root::door_steps::tests::isolated_fixture_done(TEST, &case);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_program_members_env_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-program-apply";
    let var = unset("TOOLS_PROGRAM_APPLY");
    std::env::set_var(&var, "busbar-own-program-token");
    let secret = env(&var);
    let rig = try_rig_tools(instance, 0, program_section(&secret))
        .await
        .expect("the door composes");
    let (status, _, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
    let first: serde_json::Value = serde_json::from_slice(&body).expect("the initial tool reply");
    assert_ne!(
        first["result"]["isError"], true,
        "the initial program call succeeded: {first}"
    );
    assert!(
        first["result"]["content"][0]["text"]
            .as_str()
            .is_some_and(|text| text.starts_with("from the server ")),
        "the initial call reached the actual child: {first}"
    );
    let facts = |reply: &serde_json::Value| {
        reply["result"]["content"][0]["text"]
            .as_str()
            .expect("the child result")
            .split_ascii_whitespace()
            .filter_map(|word| word.split_once('='))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = facts(&first);
    assert!(before["pid"].parse::<u32>().is_ok_and(|pid| pid > 0));
    assert_eq!(before["calls"], "1");
    std::env::remove_var(&var);
    refused_naming_its_source(&secret);
    rig.live.apply(&rig.app).await;
    let (status, headers, body) = call(&rig).await;
    assert_clean(instance, status, &headers, &body, &secret);
    assert_eq!(status, StatusCode::OK, "the spawned program keeps serving");
    assert!(
        String::from_utf8_lossy(&body).contains("from the server"),
        "the member is served by the program spawned while its reference resolved"
    );
    let second: serde_json::Value =
        serde_json::from_slice(&body).expect("the post-apply tool reply");
    assert_ne!(
        second["result"]["isError"], true,
        "the retained child served: {second}"
    );
    let after = facts(&second);
    assert_eq!(
        after["pid"], before["pid"],
        "the same actual child survived apply"
    );
    assert_eq!(after["calls"], "2", "the retained child handled both calls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_an_unresolved_subject_token_refuses_the_boot_naming_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-compose";
    let secret = env(unset("TOOLS_EXCHANGE_COMPOSE"));
    refused_naming_its_source(&secret);
    let mut server = TlsToolServer::listing(Arc::new(Mutex::new(three_tools()))).await;
    let Err(refusal) = server
        .try_rig(instance, exchange_section(&server, &secret), &|app| app)
        .await
    else {
        panic!("a subject token that does not resolve refuses the composition");
    };
    println!("SECRET-SOURCE {instance}: compose refused (operator): {refusal}");
    assert!(
        !source_in(&refusal, &secret).is_empty(),
        "the operator's refusal names the source: {refusal}"
    );
    assert!(
        server.heard.try_recv().is_err(),
        "the unresolved subject token refuses before any upstream request"
    );
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tool_door_a_subject_token_gone_by_an_apply_reaches_the_caller_without_its_source() {
    let _one = PUBLISHING.lock().await;
    let instance = "tools-exchange-apply";
    let var = unset("TOOLS_EXCHANGE_APPLY");
    std::env::set_var(&var, "busbar-own-subject-token");
    let secret = env(&var);
    let server = TlsToolServer::listing(Arc::new(Mutex::new(three_tools()))).await;
    let rig = server
        .rig(instance, exchange_section(&server, &secret), &|app| app)
        .await;
    let (status, _, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "served while it resolves: {}",
        String::from_utf8_lossy(&body)
    );
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
    assert_eq!(answer["id"], 30);
    assert_eq!(answer["result"]["content"][0]["text"], "from the server");
    let before = rig.live.current().generation;
    std::env::remove_var(&var);
    refused_naming_its_source(&secret);
    rig.live.apply(&rig.app).await;
    assert_eq!(
        rig.live.current().generation,
        before,
        "the door keeps the generation it serves"
    );
    let (status, headers, body) = call(&rig).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the retained generation still serves"
    );
    let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
    assert_eq!(answer["id"], 30);
    assert_eq!(answer["result"]["content"][0]["text"], "from the server");
    assert_clean(instance, status, &headers, &body, &secret);
    server.close().await;
}

#[path = "secret_source_class.rs"]
mod class;

fn isolated_source_answer(test: &str, case: &str) -> (StatusCode, Vec<u8>) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test.split_once("::").unwrap().1, "--nocapture"])
        .env("BUSBAR_SECRET_SOURCE_TEST", test)
        .env("BUSBAR_SECRET_SOURCE_CASE", case)
        .output()
        .expect("run the exact independent source fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{case}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prefix = format!("SECRET-SOURCE-ANSWER {test} {case} ");
    let answer = stdout
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("the child completed every source scan and emitted its real response");
    let (status, body): (u16, Vec<u8>) = serde_json::from_str(answer).unwrap();
    (StatusCode::from_u16(status).unwrap(), body)
}
