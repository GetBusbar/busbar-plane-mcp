// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed state's window requires a successful reading from the host's clock.

use serde_json::json;

use crate::ask::{self as ask, AskDecision, AskRefusal, AskState, Rejected, UpstreamLeg};
use crate::plane_door::{decide_ask, Held, SealHost, Site};
use crate::{codec, statement, tools_config};
use busbar_contract::abi::sdk::publish::Keyed;
use serde_json::Value;

/// A HOST'S CLOCK, as the seal reads it: the Unix second it answers, or `None` when its
/// read fails or it serves no clock.
struct HostClock {
    secs: Option<u64>,
}

/// A clock at second 1000, where a state is minted.
static MINTS: HostClock = HostClock { secs: Some(1000) };
/// A clock past every window minted at [`MINTS`].
static LAPSED: HostClock = HostClock { secs: Some(9000) };
/// A host whose clock read fails.
static FAILS: HostClock = HostClock { secs: None };

/// A seal host with a controllable clock and deterministic digest signature.
struct HostDouble<'a> {
    clock: &'static HostClock,
    spent: &'a Keyed<String, u64>,
}

impl SealHost for HostDouble<'_> {
    fn sign(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        let digest = busbar_contract::redacted::sha256_hex(data);
        Some(digest.as_bytes()[..64].to_vec())
    }

    fn now(&mut self) -> Option<u64> {
        self.clock.secs
    }
}

impl ask::Seal for HostDouble<'_> {
    fn mint(&mut self, state: &AskState) -> Option<String> {
        crate::seal::seal_state(state, &mut |data| SealHost::sign(self, data))
    }

    fn open(&mut self, blob: &str) -> Result<AskState, Rejected> {
        crate::seal::unseal_state(blob, &mut |data| SealHost::sign(self, data))
    }

    fn nonce(&mut self) -> Option<String> {
        Some([7u8; 16].iter().map(|b| format!("{b:02x}")).collect())
    }

    fn redeem(&mut self, nonce: &str, expires_at: u64, now: u64) -> bool {
        self.spent.with_all(|seen| {
            seen.retain(|_, expiry| *expiry >= now);
            seen.insert(nonce.to_string(), expires_at).is_none()
        })
    }
}

fn with_seal<R>(
    table: &'static HostClock,
    spent: &Keyed<String, u64>,
    f: impl FnOnce(&mut HostDouble<'_>) -> R,
) -> R {
    let mut seal = HostDouble {
        clock: table,
        spent,
    };
    f(&mut seal)
}

fn held() -> Held {
    let section = statement::test_support::read_tools_section(
        br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#,
    )
    .expect("the section reads");
    Held::of(1, section)
}

fn confirm() -> Vec<tools_config::AskRoundCfg> {
    serde_json::from_value(json!([{
        "ok": { "method": "elicitation/create", "params": { "message": "sure?" } }
    }]))
    .expect("the operator's rounds read")
}

fn site(rounds: &[tools_config::AskRoundCfg]) -> Site<'_> {
    Site {
        principal: "k",
        roots_epoch: 0,
        method: codec::METHOD_TOOLS_CALL,
        server: "fs",
        capability: "fs_confirm",
        rounds,
    }
}

fn caps() -> Value {
    let mut params = json!({ "_meta": {} });
    params["_meta"][codec::META_CLIENT_CAPABILITIES] = json!({ "elicitation": {} });
    params
}

fn decide_on(
    table: &'static HostClock,
    spent: &Keyed<String, u64>,
    rounds: &[tools_config::AskRoundCfg],
    params: &Value,
) -> AskDecision {
    with_seal(table, spent, |seal| {
        decide_ask(&held(), site(rounds), Some(params), &json!({}), Some(seal))
    })
}

#[test]
fn busbars_own_state_is_refused_when_the_clock_fails() {
    let (spent, rounds) = (Keyed::new(), confirm());
    let AskDecision::Ask { request_state, .. } = decide_on(&MINTS, &spent, &rounds, &caps()) else {
        panic!("the first round asks");
    };
    let mut retry = caps();
    retry["requestState"] = json!(request_state);
    retry["inputResponses"] = json!({ "ok": true });

    assert!(
        matches!(
            decide_on(&LAPSED, &spent, &rounds, &retry),
            AskDecision::Refuse(AskRefusal::StateRejected(Rejected::Expired))
        ),
        "a lapsed state is expired"
    );

    {
        let table = &FAILS;
        let d = decide_on(table, &spent, &rounds, &retry);
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "refused for the clock, got {d:?}"
        );

        let d = decide_on(table, &spent, &rounds, &caps());
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "no mint, got {d:?}"
        );
    }
}

#[test]
fn a_relayed_state_is_refused_when_the_clock_fails() {
    let (spent, none) = (Keyed::new(), Vec::new());
    let held = held();
    let leg = UpstreamLeg {
        member: "fs".into(),
        state: None,
        round: 1,
        child: None,
        answers: None,
    };
    let state = with_seal(&MINTS, &spent, |seal| {
        let bind = ask::Bind {
            principal: "k",
            method: codec::METHOD_TOOLS_CALL,
            capability: "fs_confirm",
            generation: held.catalogue.generation(),
            now: 1000,
            roots_epoch: 0,
        };
        ask::relay_state_for(
            bind,
            &ask::digest_arguments(&json!({})),
            leg,
            ask::DEFAULT_TTL_SECS,
            seal,
        )
    })
    .expect("a relayed state is sealed");
    let mut retry = caps();
    retry["requestState"] = json!(state);
    assert!(
        matches!(
            decide_on(&LAPSED, &spent, &none, &retry),
            AskDecision::Refuse(AskRefusal::StateRejected(Rejected::Expired))
        ),
        "a lapsed relayed state is expired"
    );
    {
        let table = &FAILS;
        let d = decide_on(table, &spent, &none, &retry);
        assert!(
            matches!(d, AskDecision::Refuse(AskRefusal::ClockUnavailable { .. })),
            "refused for the clock, got {d:?}"
        );
    }
}

/// A relayed state's seal under the failing clock: the refusal and the words the caller reads.
fn relayed_under_failed_clock(ttl_secs: u64) -> crate::call::AskRefusal {
    let spent = Keyed::new();
    let leg = UpstreamLeg {
        member: "fs".into(),
        state: None,
        round: 1,
        child: None,
        answers: None,
    };
    let bind = |now| ask::Bind {
        principal: "k",
        method: codec::METHOD_TOOLS_CALL,
        capability: "fs_read_file",
        generation: 1,
        now,
        roots_epoch: 0,
    };
    with_seal(&FAILS, &spent, |seal| {
        crate::plane_door::seal_relayed(seal, "fs", bind, "d", leg, ttl_secs)
    })
    .expect_err("a state is never sealed at a time that was not read")
}

/// A failed host clock refuses a relayed ask as `ask_unavailable` and names the clock.
#[test]
fn a_relayed_ask_under_a_failed_clock_is_refused_naming_the_clock() {
    let refusal = relayed_under_failed_clock(ask::DEFAULT_TTL_SECS);
    assert_eq!(refusal.audit_reason(), "ask_unavailable");
    assert!(
        refusal
            .to_string()
            .contains(crate::plane_door::CLOCK_UNAVAILABLE),
        "{refusal}"
    );
}

/// A task parked on its caller's answer (the task relay's window) refuses the same way.
#[test]
fn a_task_relay_under_a_failed_clock_is_refused_naming_the_clock() {
    let refusal = relayed_under_failed_clock(crate::tool_tasks::TASK_RELAY_TTL_SECS);
    assert_eq!(refusal.audit_reason(), "ask_unavailable");
    assert!(
        refusal
            .to_string()
            .contains(crate::plane_door::CLOCK_UNAVAILABLE),
        "{refusal}"
    );
}

#[test]
fn initial_upstream_answers_do_not_bypass_local_asks_or_presented_state() {
    let spent = Keyed::new();
    let mut supplied = caps();
    supplied["inputResponses"] = json!({"ok":true,"unknown":{"x":1}});
    assert_eq!(
        decide_on(&MINTS, &spent, &[], &supplied),
        AskDecision::Proceed
    );
    assert!(
        matches!(
            decide_on(&MINTS, &spent, &confirm(), &supplied),
            AskDecision::Ask { .. }
        ),
        "an operator-owned gate still issues its signed challenge"
    );
    supplied["requestState"] = json!("tampered");
    assert!(
        matches!(
            decide_on(&MINTS, &spent, &[], &supplied),
            AskDecision::Refuse(_)
        ),
        "initial upstream data cannot excuse presented state"
    );
}
