// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRUST SURFACE, PLANE SIDE: what a registered server was last seen to OFFER, judged against

use std::collections::BTreeMap;

use busbar_contract::redacted::sha256_hex;
use serde_json::Value;

use crate::tools_config::McpServerDefCfg;

/// One tool's identity, as `sha256:<hex>` over its name, description and input schema: one digest,
#[must_use]
pub fn tool_digest(name: &str, description: &str, input_schema: &Value) -> String {
    let mut framed = Vec::new();

    for part in [name, description, &canonical_json(input_schema)] {
        framed.extend_from_slice(&(part.len() as u64).to_be_bytes());
        framed.extend_from_slice(part.as_bytes());
    }
    format!("sha256:{}", sha256_hex(&framed))
}

/// `value` with every object's keys sorted, recursively: key ORDER is not drift, any change of key,
#[must_use]
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push('{');
            for (i, (k, v)) in sorted.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

/// What an upstream was observed to offer: `tool -> digest`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observation {
    /// The capability set.
    pub capabilities: BTreeMap<String, String>,
}

/// THE OBSERVATION a `tools/list` result carries, or why it is not one. Strict about the shape: a
pub fn observe(result: &Value) -> Result<Observation, String> {
    let Some(items) = result.get("tools").and_then(Value::as_array) else {
        return Err("the `tools/list` result carries no `tools` array".to_string());
    };
    let mut capabilities = BTreeMap::new();
    for item in items {
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            return Err("a `tools/list` entry carries no `name`".to_string());
        };
        if name.trim().is_empty() {
            return Err("a `tools/list` entry carries an empty `name`".to_string());
        }
        let description = match item.get("description") {
            None => "",
            Some(Value::String(description)) => description,
            Some(_) => {
                return Err(
                    "a `tools/list` entry carries a `description` that is not a string".to_string(),
                );
            }
        };
        let schema = item
            .get("inputSchema")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));
        if capabilities
            .insert(name.to_string(), tool_digest(name, description, &schema))
            .is_some()
        {
            return Err("a `tools/list` result repeats a tool name".to_string());
        }
    }
    Ok(Observation { capabilities })
}

/// The hash a sighting reports to the kernel's trust book (`trust.sight`): the observed capability
#[must_use]
pub fn catalogue_hash(observation: &Observation) -> String {
    let mut bytes = Vec::new();
    for (name, digest) in &observation.capabilities {
        bytes.extend_from_slice(name.as_bytes());
        bytes.push(0);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.push(b'\n');
    }
    format!("sha256:{}", sha256_hex(&bytes))
}

/// The last contact: the SDK's one shape of a sighting
pub type Sighting = busbar_contract::abi::sdk::trust::Sighting<Observation>;

/// One item of the kernel's trust state (`trust.state`): the kernel owns every
/// approval and every verdict; the plane's views read them, they derive none.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelItem {
    /// The item (the tool, as `tools_allow` names it).
    pub item: String,
    /// Its state word: `new`, `same`, `drifted`, `quarantined` or `approved`.
    pub word: String,
    /// The digest the kernel holds it approved at; `None` = none.
    pub approved: Option<String>,
}

impl KernelItem {
    /// The kernel serves it: its word is `approved` or `same` and it holds an approved digest. A
    fn serves(&self) -> bool {
        self.approved.is_some() && (self.word == "approved" || self.word == "same")
    }

    /// The kernel holds it demoted: `drifted`, or `quarantined` (a durable demotion it replayed
    fn demoted(&self) -> bool {
        self.word == "drifted" || self.word == "quarantined"
    }
}

/// The view's state word: the SDK's one state word of a trust view
pub use busbar_contract::abi::sdk::trust::State;

/// The changes queue: what the server offers now against what the kernel holds approved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    /// Offered now, approved at nothing.
    pub added: Vec<String>,
    /// Approved, and the kernel holds it drifted (or quarantined): the rug-pull row.
    pub changed: Vec<String>,
    /// Approved, and no longer offered.
    pub removed: Vec<String>,
}

/// The changes queue of `sighting` against the kernel's `items`. The verdict on a tool offered at
#[must_use]
pub fn drift(items: &[KernelItem], sighting: &Sighting) -> Drift {
    let Sighting::Seen(obs) = sighting else {
        return Drift {
            changed: items
                .iter()
                .filter(|i| i.demoted())
                .map(|i| i.item.clone())
                .collect(),
            ..Drift::default()
        };
    };
    let held = |name: &str| items.iter().find(|i| i.item == name);
    let mut d = Drift::default();
    for name in obs.capabilities.keys() {
        match held(name) {
            Some(i) if i.demoted() => d.changed.push(name.clone()),
            Some(i) if i.serves() => {}
            _ => d.added.push(name.clone()),
        }
    }
    for i in items {
        if i.serves() && !obs.capabilities.contains_key(&i.item) {
            d.removed.push(i.item.clone());
        }
    }
    d
}

/// The view's state, read off the verdict the kernel enforces. Order is precedence: a failed
#[must_use]
pub fn state(items: &[KernelItem], sighting: &Sighting) -> State {
    if matches!(sighting, Sighting::Failed(_)) {
        return State::Error;
    }
    if items.iter().any(KernelItem::demoted) {
        return State::Quarantined;
    }
    if !items.iter().any(KernelItem::serves) {
        return State::Pending;
    }
    let d = drift(items, sighting);
    if d.added.is_empty() && d.changed.is_empty() && d.removed.is_empty() {
        State::Approved
    } else {
        State::Quarantined
    }
}

/// How many tools the last successful sighting carried.
fn observed(sighting: &Sighting) -> usize {
    match sighting {
        Sighting::Seen(o) => o.capabilities.len(),
        _ => 0,
    }
}

/// Why the last contact failed, when it did.
fn failure(sighting: &Sighting) -> Option<&str> {
    match sighting {
        Sighting::Failed(reason) => Some(reason),
        _ => None,
    }
}

/// One capability's standing status, in the trust view.
#[derive(serde::Serialize)]
struct CapabilityView<'a> {
    tool: &'a str,
    status: &'static str,
    approved_digest: Option<&'a str>,
}

/// THE TRUST VIEW of one registration (`connect` and `changes` answer it), field for field the
/// served engine's: its name, the derived state, the pin mechanism, the identity axis, the changes
/// queue, the observation's size, the failure and every capability's standing status in name order.
#[derive(serde::Serialize)]
struct TrustView<'a> {
    name: &'a str,
    state: &'static str,
    pin_mechanism: &'static str,
    pin_changed: bool,
    added: Vec<String>,
    changed: Vec<String>,
    removed: Vec<String>,
    observed_tools: usize,
    failure: Option<&'a str>,
    capabilities: Vec<CapabilityView<'a>>,
}

/// THE HEALTH VIEW (`health` answers it): the one bit a caller polls for, and why.
#[derive(serde::Serialize)]
struct HealthView<'a> {
    name: &'a str,
    state: &'static str,
    serving: bool,
    contacted: bool,
    failure: Option<&'a str>,
    observed_tools: usize,
}

/// The trust view of registration `name` (`def`) under `sighting` and the kernel's trust state of
#[must_use]
pub fn trust_view(
    name: &str,
    def: &McpServerDefCfg,
    sighting: &Sighting,
    items: &[KernelItem],
) -> String {
    let d = drift(items, sighting);
    let mut capabilities: BTreeMap<&str, CapabilityView<'_>> = items
        .iter()
        .filter(|i| i.serves())
        .filter_map(|i| {
            let digest = i.approved.as_deref()?;
            Some((
                i.item.as_str(),
                CapabilityView {
                    tool: &i.item,
                    status: "approved",
                    approved_digest: Some(digest),
                },
            ))
        })
        .collect();

    let others = items.iter().map(|i| i.item.as_str());
    for tool in others.chain(def.tools_allow.keys().map(String::as_str)) {
        capabilities.entry(tool).or_insert(CapabilityView {
            tool,
            status: "pending",
            approved_digest: None,
        });
    }
    let view = TrustView {
        name,
        state: state(items, sighting).word(),
        pin_mechanism: def.pin.mechanism.token(),

        pin_changed: false,
        added: d.added,
        changed: d.changed,
        removed: d.removed,
        observed_tools: observed(sighting),
        failure: failure(sighting),
        capabilities: capabilities.into_values().collect(),
    };
    serde_json::to_string(&view).unwrap_or_default()
}

/// The health view of registration `name` under `sighting` and the kernel's trust state of it
#[must_use]
pub fn health_view(name: &str, sighting: &Sighting, items: &[KernelItem]) -> String {
    let derived = state(items, sighting);
    let view = HealthView {
        name,
        state: derived.word(),
        serving: derived == State::Approved,
        contacted: !matches!(sighting, Sighting::Never),
        failure: failure(sighting),
        observed_tools: observed(sighting),
    };
    serde_json::to_string(&view).unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/trust_tests.rs"]
mod tests;
