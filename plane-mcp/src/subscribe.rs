// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `subscriptions/listen`: THE SERVER-TO-CLIENT CHANNEL OF REVISION `2026-07-28`, as a pure state

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeSet;

use busbar_contract::jsonrpc::{error_body, INVALID_REQUEST};
use serde_json::{json, Map, Value};

use crate::catalogue::{Catalogue, Lookup};

/// How long one subscription is held before it is closed with a graceful result. LOAD-BEARING FOR
pub const MAX_LIFETIME_NS: u64 = 300 * 1_000_000_000;

/// How often a stream that has nothing to say says it is alive.
pub const KEEPALIVE_NS: u64 = 15 * 1_000_000_000;

/// The ceiling on distinct uris one `subscriptions/listen` may name under `resourceSubscriptions`,
pub const MAX_SUBSCRIBED_URIS: usize = 64;

/// The notification that acknowledges a subscription.
pub const ACKNOWLEDGED: &str = "notifications/subscriptions/acknowledged";

/// The `_meta` key a frame names its subscription under.
pub const SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// The three list-changed categories, and the notification each becomes.
const KINDS: [(&str, &str); 3] = [
    ("toolsListChanged", "notifications/tools/list_changed"),
    ("promptsListChanged", "notifications/prompts/list_changed"),
    (
        "resourcesListChanged",
        "notifications/resources/list_changed",
    ),
];

/// What a caller asked for, and what it is given: the subscription filter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`.
    pub lists: [bool; 3],
    /// `resourceSubscriptions`; `None` = the category is not in it.
    pub resources: Option<Vec<String>>,
}

impl Filter {
    /// The filter as the wire carries it.
    #[must_use]
    pub fn render(&self) -> Value {
        let mut out = Map::new();
        for (on, (key, _)) in self.lists.iter().zip(KINDS) {
            if *on {
                out.insert(key.to_string(), Value::Bool(true));
            }
        }
        if let Some(uris) = &self.resources {
            out.insert("resourceSubscriptions".to_string(), json!(uris));
        }
        Value::Object(out)
    }

    /// Read a requested filter; a shape the protocol does not define reads as no category.
    fn read(notifications: Option<&Value>) -> Self {
        let Some(n) = notifications.and_then(Value::as_object) else {
            return Filter::default();
        };
        let mut lists = [false; 3];
        for (slot, (key, _)) in lists.iter_mut().zip(KINDS) {
            match n.get(key) {
                None => {}
                Some(Value::Bool(b)) => *slot = *b,
                Some(_) => return Filter::default(),
            }
        }
        let resources = match n.get("resourceSubscriptions") {
            None => None,
            Some(Value::Array(a)) => {
                let mut seen = BTreeSet::new();
                let mut uris = Vec::new();
                for u in a {
                    let Some(u) = u.as_str() else {
                        return Filter::default();
                    };
                    if seen.insert(u) {
                        uris.push(u.to_string());
                        if uris.len() > MAX_SUBSCRIBED_URIS {
                            break;
                        }
                    }
                }
                Some(uris)
            }
            Some(_) => return Filter::default(),
        };
        Filter { lists, resources }
    }
}

/// Whether the caller's permission still stands this frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// It stands.
    Live,
    /// The host could not re-confirm permission; this is not an identity revocation.
    Unavailable,
    /// It lapsed, for this reason: the stream ends on this frame, saying so.
    Lapsed {
        /// The sentence.
        message: String,
        /// The machine reason.
        reason: String,
    },
}

/// Where the stream is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The acknowledgement is owed, and owed first.
    Acknowledge,
    /// Acknowledged; watching the generation.
    Watch { generation: u64, seen: [u64; 3] },
    /// The final frame went: the next step closes it.
    Ended,
}

/// What one step came to.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Frames to write, in order; the stream goes on.
    Frames(Vec<Value>),
    /// Nothing happened for a keepalive's while: say it is alive.
    Keepalive,
    /// Nothing to say yet.
    Quiet,
    /// The last frames to write; the stream ends after them.
    End(Vec<Value>),
    /// The stream is over.
    Closed,
}

/// ONE SUBSCRIPTION.
#[derive(Debug, Clone)]
pub struct Listen {
    /// The listen request's own id: the subscription's only durable name.
    pub id: Value,
    accepted: Filter,
    meta: Value,
    phase: Phase,
    opened_ns: u64,
    last_write_ns: u64,
}

/// A refusal envelope for an invalid listen request.
fn invalid(id: &Value, message: &str) -> Value {
    error_body(id.clone(), crate::codec::CODE_INVALID_PARAMS, message, None)
}

impl Listen {
    /// Whether this subscription accepted this resource URI.
    pub(crate) fn watches_resource(&self, uri: &str) -> bool {
        self.accepted
            .resources
            .as_ref()
            .is_some_and(|uris| uris.iter().any(|u| u == uri))
    }
    /// OPEN one subscription for `params` under `id` at `now_ns`: the requested filter read,
    pub fn open(
        params: Option<&Value>,
        id: Value,
        now_ns: u64,
        entitled: impl Fn(&str) -> bool,
    ) -> Result<Self, Value> {
        let requested = Filter::read(params.and_then(|p| p.get("notifications")));
        if let Some(uris) = &requested.resources {
            if uris.len() > MAX_SUBSCRIBED_URIS {
                return Err(invalid(
                    &id,
                    &format!(
                        "`params.notifications.resourceSubscriptions` names more than \
                         {MAX_SUBSCRIBED_URIS} distinct uris; a `subscriptions/listen` call may \
                         watch at most {MAX_SUBSCRIBED_URIS} at once. Open a second subscription \
                         for the rest."
                    ),
                ));
            }
        }
        let accepted = Filter {
            lists: requested.lists,
            resources: requested
                .resources
                .map(|uris| uris.into_iter().filter(|u| entitled(u)).collect::<Vec<_>>())
                .filter(|kept| !kept.is_empty()),
        };
        if !accepted.lists.iter().any(|on| *on) && accepted.resources.is_none() {
            return Err(invalid(
                &id,
                "`params.notifications` opts in to no category this server delivers for you. \
                 busbar delivers `toolsListChanged`, `promptsListChanged`, \
                 `resourcesListChanged`, and `resourceSubscriptions` for uris your grant reaches \
                 — a subscription naming only resources you cannot read is a stream with nothing \
                 to say.",
            ));
        }
        let meta = json!({ SUBSCRIPTION_ID: id });
        Ok(Listen {
            id,
            accepted,
            meta,
            phase: Phase::Acknowledge,
            opened_ns: now_ns,
            last_write_ns: now_ns,
        })
    }

    /// One notification tagged with this subscription.
    fn notification(&self, method: &str, extra: Value) -> Value {
        let mut params = match extra {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        params.insert("_meta".to_string(), self.meta.clone());
        json!({ "jsonrpc": "2.0", "method": method, "params": Value::Object(params) })
    }

    /// The revision's own graceful end, correlated to the request that opened the stream.
    fn complete(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": self.id,
            "result": { "resultType": "complete", "_meta": self.meta },
        })
    }

    /// THE NEXT STEP at `now_ns`, over the live `catalogue` under the caller's grants `admit`,
    pub fn step(
        &mut self,
        catalogue: &Catalogue,
        admit: &impl Fn(&str, &str) -> bool,
        standing: &Standing,
        updates: &[(String, String)],
        now_ns: u64,
    ) -> Step {
        self.step_visible(catalogue, admit, &|_| false, standing, updates, now_ns)
    }

    /// The next step with the same trust filter used by this caller's `tools/list`.
    pub fn step_visible(
        &mut self,
        catalogue: &Catalogue,
        admit: &impl Fn(&str, &str) -> bool,
        hidden: &impl Fn(&crate::catalogue::ToolEntry) -> bool,
        standing: &Standing,
        updates: &[(String, String)],
        now_ns: u64,
    ) -> Step {
        if self.phase == Phase::Ended {
            return Step::Closed;
        }
        if *standing == Standing::Unavailable {
            self.phase = Phase::Ended;
            return Step::End(vec![error_body(
                self.id.clone(),
                crate::codec::CODE_INTERNAL,
                "the host could not re-confirm this subscription's permission",
                Some(json!({"reason":"standing_unavailable"})),
            )]);
        }
        if let Standing::Lapsed { message, reason } = standing {
            self.phase = Phase::Ended;

            let data = Some(json!({ "reason": reason }));
            return Step::End(vec![error_body(
                self.id.clone(),
                INVALID_REQUEST,
                message,
                data,
            )]);
        }
        if now_ns.saturating_sub(self.opened_ns) >= MAX_LIFETIME_NS {
            self.phase = Phase::Ended;
            return Step::End(vec![self.complete()]);
        }
        let generation = catalogue.generation();
        match &mut self.phase {
            Phase::Acknowledge => {
                let seen = change_keys_visible(catalogue, admit, hidden);
                self.phase = Phase::Watch { generation, seen };
                self.last_write_ns = now_ns;
                let ack = self.notification(
                    ACKNOWLEDGED,
                    json!({ "notifications": self.accepted.render() }),
                );
                Step::Frames(vec![ack])
            }
            Phase::Watch {
                generation: at,
                seen,
            } => {
                let mut changed = Vec::new();
                let fresh = if self.accepted.lists.iter().any(|on| *on) {
                    change_keys_visible(catalogue, admit, hidden)
                } else {
                    *seen
                };
                if *at != generation || fresh != *seen {
                    *at = generation;
                    for (i, (_, method)) in KINDS.into_iter().enumerate() {
                        if fresh[i] != seen[i] && self.accepted.lists[i] {
                            changed.push(method);
                        }
                    }
                    *seen = fresh;
                }
                let mut out: Vec<Value> = changed
                    .into_iter()
                    .map(|m| self.notification(m, json!({})))
                    .collect();

                if let Some(uris) = &self.accepted.resources {
                    for (server, uri) in updates {
                        if !uris.iter().any(|u| u == uri) {
                            continue;
                        }
                        let entitled = matches!(
                            catalogue.resource_by_uri(admit, uri),
                            Lookup::One(entry) if entry.server == *server
                        );
                        if entitled {
                            out.push(self.notification(
                                "notifications/resources/updated",
                                json!({ "uri": uri }),
                            ));
                        }
                    }
                }
                if !out.is_empty() {
                    self.last_write_ns = now_ns;
                    return Step::Frames(out);
                }
                if now_ns.saturating_sub(self.last_write_ns) >= KEEPALIVE_NS {
                    self.last_write_ns = now_ns;
                    return Step::Keepalive;
                }
                Step::Quiet
            }
            Phase::Ended => Step::Closed,
        }
    }
}

/// A change key over one grant-scoped catalogue slice: FNV-1a, trusted for nothing (a collision
fn change_key(parts: &[Vec<u8>]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for byte in (part.len() as u64).to_le_bytes().iter().chain(part.iter()) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// The three keys of the complete rendered lists one caller can see.
#[must_use]
pub fn change_keys(catalogue: &Catalogue, admit: &impl Fn(&str, &str) -> bool) -> [u64; 3] {
    change_keys_visible(catalogue, admit, &|_| false)
}

fn change_keys_visible(
    catalogue: &Catalogue,
    admit: &impl Fn(&str, &str) -> bool,
    hidden: &impl Fn(&crate::catalogue::ToolEntry) -> bool,
) -> [u64; 3] {
    let id = Value::Null;
    [
        change_key(&[catalogue.tools_list(&id, admit, hidden)]),
        change_key(&[catalogue.prompts_list(&id, admit)]),
        change_key(&[
            catalogue.resources_list(&id, admit),
            catalogue.resource_templates_list(&id, admit),
        ]),
    ]
}

#[cfg(test)]
#[path = "tests/subscribe_tests.rs"]
mod tests;
