// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Session-scoped Apps catalogue projection and governed dynamic resources/read.
use super::*;
use crate::apps::{self, Profile};
use crate::client::jsonrpc::OutboundRequest;
use crate::connections::DiscoveryKey;

#[derive(Clone)]
pub(super) struct Mapping {
    owner: String,
    session: String,
    pub(super) server: String,
    tool: String,
    original: String,
    published: String,
    key: DiscoveryKey,
}
impl Mapping {
    pub(super) fn session(&self) -> &str {
        &self.session
    }
    pub(super) fn key_connection(&self) -> &crate::connections::ConnectionKey {
        &self.key.connection
    }
}
pub(super) struct Read {
    mapping: Mapping,
    negotiating: door_sessions::Negotiating,
    bytes: Vec<u8>,
    status: u32,
    fields: Vec<(String, String)>,
}
pub(super) fn route(
    plane: &McpDoor,
    disposition: &Disposition,
    value: Option<&Value>,
) -> Option<Mapping> {
    if !matches!(disposition, Disposition::Request { row, .. } if row.op == crate::tool_ops::OP_RESOURCE_READ)
    {
        return None;
    }
    plane
        .app_resources
        .get(&value?.pointer("/params/uri")?.as_str()?.to_owned())
}
pub(super) fn mapping(plane: &McpDoor, unit: &CallUnit) -> Option<Mapping> {
    if !matches!(&unit.disposition, Disposition::Request { row, .. } if row.op == crate::tool_ops::OP_RESOURCE_READ)
    {
        return None;
    }
    plane
        .app_resources
        .get(&unit.params.as_ref()?.get("uri")?.as_str()?.to_owned())
}
pub(super) fn refuse(unit: &mut CallUnit, message: &str) -> Step {
    let id = match &unit.disposition {
        Disposition::Request { id, .. } => id.clone(),
        _ => Value::Null,
    };
    let r = crate::call::error(403, &id, crate::codec::CODE_REFUSED, message.into(), None);
    unit.pending = Some(Pending::answer(
        r.status,
        r.body(),
        unit.framing.as_ref(),
        &[],
    ));
    Step::Write
}
fn emit(unit: &mut CallUnit, request: OutboundRequest) -> Step {
    unit.pending = Some(Pending::far(crate::call::OutboundCall {
        verb: "POST",
        target: crate::call::path_of(&request.url),
        fields: request.headers,
        body: request.body,
    }));
    Step::Write
}
fn visible(
    profile: &Profile,
    cfg: &crate::apps::AppsCfg,
    entry: &crate::catalogue::ToolEntry,
) -> bool {
    profile.effective(cfg).enabled()
        || apps::model_visible(entry.meta.as_ref(), cfg.allow_legacy_resource_meta)
}
fn uri_for(session: &str, key: &DiscoveryKey, original: &str) -> String {
    // The unpredictable session identity salts the hash; public URIs reveal no principal or member.
    let tuple = serde_json::json!(["mcp-apps-uri-v1", session, key, original]);
    format!(
        "ui://busbar/{}",
        busbar_contract::redacted::sha256_hex(crate::trust::canonical_json(&tuple).as_bytes())
    )
}
pub(super) fn list(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    held: &Held,
    hidden: &std::collections::BTreeSet<String>,
) -> Step {
    let id = match &unit.disposition {
        Disposition::Request { id, .. } => id.clone(),
        _ => Value::Null,
    };
    let session = door_sessions::session_of(&unit.session);
    let now = wall_ms(plane.services, ticket, &mut unit.issued).unwrap_or(u64::MAX);
    let mut tools = Vec::new();
    let entries = held.catalogue.tools_for(&admit(&unit.entitled));
    for entry in entries {
        let Some(def) = held.section.servers.get(&entry.server) else {
            continue;
        };
        if hidden.contains(&entry.namespaced) || !visible(&unit.apps_profile, &def.apps, entry) {
            continue;
        }
        if def.apps.enabled {
            let seen = door_connections::list_for(
                plane,
                caller,
                &entry.server,
                now,
                held,
                &unit.apps_profile,
            );
            if !matches!(
                trust_of(plane, ticket, &mut unit.issued, entry, &seen),
                crate::call::Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_NONE)
            ) {
                continue;
            }
        }
        let mut rendered = entry.render();
        let ui = match apps::tool_meta(entry.meta.as_ref(), def.apps.allow_legacy_resource_meta) {
            Ok(ui) => ui,
            Err(_) => continue,
        };
        if let Some(mut ui) = ui {
            if !unit.apps_profile.effective(&def.apps).enabled() {
                if let Some(meta) = rendered.get_mut("_meta").and_then(Value::as_object_mut) {
                    meta.remove("ui");
                    meta.remove("ui/resourceUri");
                }
            } else {
                if let Some(original) = ui
                    .get("resourceUri")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                {
                    let Some(session) = session.as_deref() else {
                        continue;
                    };
                    let Some(key) = door_connections::scoped_key(
                        plane,
                        caller,
                        &entry.server,
                        now,
                        held,
                        &unit.apps_profile,
                    ) else {
                        continue;
                    };
                    let published = uri_for(session, &key, &original);
                    let mapping = Mapping {
                        owner: caller.into(),
                        session: session.into(),
                        server: entry.server.clone(),
                        tool: entry.namespaced.clone(),
                        original,
                        published: published.clone(),
                        key,
                    };
                    let inserted = plane.app_resources.with_all(|map| {
                        if map.len() >= 4096 && !map.contains_key(&published) {
                            return false;
                        }
                        if map.get(&published).is_some_and(|existing| {
                            existing.owner != mapping.owner
                                || existing.session != mapping.session
                                || existing.server != mapping.server
                                || existing.original != mapping.original
                                || existing.key != mapping.key
                        }) {
                            return false;
                        }
                        map.insert(published.clone(), mapping);
                        true
                    });
                    if !inserted {
                        return refuse(unit, "The bounded Apps resource map is full or ambiguous.");
                    }
                    ui["resourceUri"] = published.into();
                }
                rendered["_meta"]["ui"] = ui;
                if let Some(meta) = rendered.get_mut("_meta").and_then(Value::as_object_mut) {
                    meta.remove("ui/resourceUri");
                }
            }
        }
        tools.push(rendered);
    }
    unit.pending = Some(Pending::answer(
        200,
        crate::catalogue::complete(&id, crate::catalogue::cache_hints(serde_json::json!({"tools":tools}))),
        unit.framing.as_ref(),
        &[],
    ));
    Step::Write
}
fn authorized(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    mapping: &Mapping,
) -> bool {
    let Some(held) = unit.held.clone() else {
        return false;
    };
    let Some(now) = wall_ms(plane.services, ticket, &mut unit.issued) else {
        return false;
    };
    if plane
        .current()
        .is_none_or(|h| h.catalogue.generation() != mapping.key.approval_revision)
        || !door_sessions::session_live(plane, &mapping.session, caller, now)
        || plane
            .app_resources
            .get(&mapping.published)
            .is_none_or(|current| {
                current.key != mapping.key || current.original != mapping.original
            })
    {
        return false;
    }

    if mapping.owner != caller
        || door_sessions::session_of(&unit.session).as_deref() != Some(&mapping.session)
        || door_connections::scoped_key(
            plane,
            caller,
            &mapping.server,
            now,
            &held,
            &unit.apps_profile,
        )
        .as_ref()
            != Some(&mapping.key)
    {
        return false;
    }
    let Some(def) = held.section.servers.get(&mapping.server) else {
        return false;
    };
    if !unit.apps_profile.effective(&def.apps).enabled()
        || !def.apps.resources.contains_key(&mapping.original)
    {
        return false;
    }
    let Some(entry) = held.catalogue.tool(&mapping.tool) else {
        return false;
    };
    unit.entitled
        .remove(&format!("{}:{}", statement::SCOPE, mapping.server));
    unit.entitled
        .remove(&format!("{}:{}", statement::SCOPE_TOOL, mapping.tool));
    ask_entitlements(
        plane.services,
        ticket,
        unit,
        &[
            (statement::SCOPE, &mapping.server),
            (statement::SCOPE_TOOL, &mapping.tool),
        ],
    );
    if !crate::catalogue::granted(&admit(&unit.entitled), &mapping.server, &mapping.tool) {
        return false;
    }
    let list = door_connections::list_for(
        plane,
        caller,
        &mapping.server,
        now,
        &held,
        &unit.apps_profile,
    );
    matches!(
        trust_of(plane, ticket, &mut unit.issued, entry, &list),
        crate::call::Trust::Verdict(busbar_contract::abi::host::service::DISTRUST_NONE)
    )
}
pub(super) fn preflight(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let mapping = mapping(plane, unit)?;
    if mapping.owner != caller
        || door_sessions::session_of(&unit.session).as_deref() != Some(&mapping.session)
    {
        return Some(refuse(unit, "UI resource belongs to another session."));
    }
    ask_entitlements(
        plane.services,
        ticket,
        unit,
        &[
            (statement::SCOPE, &mapping.server),
            (statement::SCOPE_TOOL, &mapping.tool),
        ],
    );
    if !crate::catalogue::granted(&admit(&unit.entitled), &mapping.server, &mapping.tool) {
        return Some(refuse(unit, "UI resource is not granted to this caller."));
    }
    None
}

pub(super) fn answer(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let is_ui = matches!(&unit.disposition, Disposition::Request { row, .. } if row.op == crate::tool_ops::OP_RESOURCE_READ)
        && unit
            .params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .is_some_and(|u| u.starts_with("ui://"));
    if !is_ui
        || unit
            .held
            .as_ref()
            .is_none_or(|h| !h.section.servers.values().any(|d| d.apps.enabled))
    {
        return None;
    }
    let Some(mapping) = mapping(plane, unit) else {
        return Some(refuse(unit, "Unknown session UI resource."));
    };
    if !authorized(plane, ticket, caller, unit, &mapping) {
        return Some(refuse(
            unit,
            "UI resource is not currently authorized in this session.",
        ));
    }
    if unit.app_read.is_some() {
        return Some(Step::Taken);
    }
    let held = unit.held.as_ref()?;
    let def = held.section.servers.get(&mapping.server)?;
    let id = match &unit.disposition {
        Disposition::Request { id, .. } => id.clone(),
        _ => return None,
    };
    let params = serde_json::json!({"uri":mapping.original, "_meta": {crate::codec::META_PROTOCOL_VERSION: crate::codec::PROTOCOL_VERSION, crate::codec::META_CLIENT_CAPABILITIES: unit.apps_profile.effective(&def.apps).capabilities()}});
    let body = busbar_contract::jsonrpc::request_bytes(
        &crate::codec::json(&id),
        "resources/read",
        Some(&crate::codec::json(&params)),
    );
    let original = crate::client::jsonrpc::envelope(
        &def.url,
        "resources/read",
        Some(&mapping.original),
        body,
        None,
    );
    let negotiating = door_sessions::Negotiating::begin(
        plane,
        &mapping.server,
        &mapping.key.session_key(),
        original,
    );
    let Some(request) = negotiating.first_request().cloned() else {
        return Some(refuse(
            unit,
            "UI resources require a supported HTTP upstream.",
        ));
    };
    unit.app_read = Some(Read {
        mapping,
        negotiating,
        bytes: Vec::new(),
        status: 0,
        fields: Vec::new(),
    });
    Some(emit(unit, request))
}
pub(super) fn far(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    input: Lent<'_, OnPieceIn>,
) -> Option<Step> {
    let state = unit.app_read.as_mut()?;
    if input.flags() & PIECE_HAS_STATUS != 0 {
        state.status = input.status_code();
        state.fields = input
            .head_fields()
            .iter()
            .filter_map(|f| {
                Some((
                    f.name().as_str().ok()?.to_owned(),
                    f.value().as_str().ok()?.to_owned(),
                ))
            })
            .collect();
    }
    if state
        .bytes
        .len()
        .saturating_add(input.bytes().bytes().len())
        > REPLY_MAX
    {
        unit.app_read = None;
        return Some(refuse(
            unit,
            "UI upstream response exceeds the wire byte bound.",
        ));
    }
    state.bytes.extend_from_slice(input.bytes().bytes());
    if input.flags() & PIECE_LAST == 0 {
        return Some(Step::Taken);
    }
    let mut state = unit.app_read.take()?;
    if !authorized(plane, ticket, caller, unit, &state.mapping) {
        return Some(refuse(
            unit,
            "UI resource authorization changed during the read.",
        ));
    }
    match state.negotiating.governed_answer(
        plane,
        &state.mapping.server,
        state.status as u16,
        std::mem::take(&mut state.fields),
        std::mem::take(&mut state.bytes),
    ) {
        door_sessions::Governed::Send(request) => {
            unit.app_read = Some(state);
            Some(emit(unit, request))
        }
        door_sessions::Governed::Done(door_sessions::Negotiated::Answer(
            status,
            body,
            sse,
            sent,
        )) if (200..300).contains(&status) => {
            let id = match &unit.disposition {
                Disposition::Request { id, .. } => id.clone(),
                _ => Value::Null,
            };
            let sent = sent.map(Value::from).unwrap_or_else(|| id.clone());
            let body = if sse {
                crate::call::answer_body(&body, true, &sent)
            } else {
                body
            };
            let crate::client::jsonrpc::RpcOutcome::Result(mut result) =
                crate::client::jsonrpc::parse_response_id(&body, &sent)
            else {
                return Some(refuse(unit, "UI resource returned an invalid result."));
            };
            let cfg = &unit
                .held
                .as_ref()?
                .section
                .servers
                .get(&state.mapping.server)?
                .apps;
            if let Err(reason) = apps::resource_result(
                &mut result,
                &state.mapping.original,
                &state.mapping.published,
                cfg,
            ) {
                return Some(refuse(unit, &reason));
            }
            unit.pending = Some(Pending::answer(
                200,
                crate::catalogue::complete(&id, crate::catalogue::cache_hints(result)),
                unit.framing.as_ref(),
                &[],
            ));
            Some(Step::Write)
        }
        _ => Some(refuse(unit, "UI resource read failed.")),
    }
}

/// Rewrite only protocol-defined resource references, never text, HTML or arbitrary tool data.
pub(super) fn rewrite_reply(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let Some(held) = unit.held.clone() else {
        return Ok(body);
    };
    let Some(server) = unit.member.as_deref() else {
        return Ok(body);
    };
    let Some(def) = held.section.servers.get(server) else {
        return Ok(body);
    };
    if !def.apps.enabled {
        return Ok(body);
    }
    let enabled = unit.apps_profile.effective(&def.apps).enabled();
    let mut wire = crate::codec::wire_json::parse(&body).map_err(|_| "Invalid Apps tool reply")?;
    let Some(result) = wire.get_mut("result") else {
        return Ok(body);
    };
    let session = door_sessions::session_of(&unit.session).unwrap_or_default();
    let available: Vec<_> = plane.app_resources.with_all(|m| {
        m.values()
            .filter(|r| r.owner == caller && r.session == session && r.server == server)
            .cloned()
            .collect()
    });
    let mut rewrite = |uri: &mut Value| -> Result<(), String> {
        let Some(original) = uri.as_str().filter(|u| u.starts_with("ui://")) else {
            return Ok(());
        };
        let resource = available
            .iter()
            .find(|r| r.original == original)
            .ok_or("Unmapped UI reference in tool reply")?;
        if !authorized(plane, ticket, caller, unit, resource) {
            return Err("UI reference is no longer authorized".into());
        }
        *uri = resource.published.clone().into();
        Ok(())
    };
    if let Some(meta) = result.get_mut("_meta").and_then(Value::as_object_mut) {
        if !enabled {
            meta.remove("ui");
            meta.remove("ui/resourceUri");
        } else {
            if meta.contains_key("ui/resourceUri") {
                return Err("Flat result UI metadata is unsupported".into());
            }
            if let Some(uri) = meta.get_mut("ui").and_then(|u| u.get_mut("resourceUri")) {
                rewrite(uri)?;
            }
        }
    }
    if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
        if !enabled {
            content.retain(|c| {
                !c.get("uri")
                    .or_else(|| c.pointer("/resource/uri"))
                    .and_then(Value::as_str)
                    .is_some_and(|u| u.starts_with("ui://"))
            });
        } else {
            for item in content {
                match item.get("type").and_then(Value::as_str) {
                    Some("resource_link") => {
                        if let Some(uri) = item.get_mut("uri") {
                            rewrite(uri)?;
                        }
                    }
                    Some("resource") => {
                        if let Some(uri) = item.pointer_mut("/resource/uri") {
                            rewrite(uri)?;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(crate::codec::json(&wire))
}

#[cfg(test)]
#[path = "tests/door_apps.rs"]
mod tests;
