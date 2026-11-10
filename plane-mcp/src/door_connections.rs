// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-credential consent and governed OAuth/discovery. `caller_ref` is the host's verified
//! credential identity; a caller-supplied clientInfo or client_id never establishes ownership.
use super::*;
use crate::connections::{
    ConnectionKey, Connections, DiscoveryKey, ExchangePermit, PublicConnection, RefreshPermit,
    Status,
};
use busbar_contract::abi::sdk::cred::{Cred, FormBody, Seal, SealedWrite};
use busbar_contract::abi::sdk::services::OutboundScope;
use std::task::Poll;

pub(super) struct Unit {
    key: ConnectionKey,
    public: PublicConnection,
    scope_url: String,
    token_url: String,
    phase: Phase,
    handle: Option<u32>,
    status: u32,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    fields: Vec<(String, String)>,
}
enum Permit {
    Authorize(ExchangePermit),
    Refresh(RefreshPermit),
}
enum Phase {
    Prepare {
        permit: Permit,
        body: SealedWrite,
        token_url: String,
    },
    Exchange(Option<Permit>),
    Publish {
        permit: Option<Permit>,
        seal: Seal,
        expiry: u64,
        refresh: Option<SealedWrite>,
    },
    Revoke {
        access_done: bool,
        refresh_revision: u64,
    },
    RefreshBind {
        permit: Option<RefreshPermit>,
        revision: u64,
    },
    Bind,
    Discover {
        negotiating: Box<door_sessions::Negotiating>,
        pages: crate::client::jsonrpc::ToolPages,
    },
    Bound,
}
fn table<R>(plane: &McpDoor, f: impl FnOnce(&mut Connections) -> R) -> R {
    plane
        .connections
        .with_all(|all| f(all.entry(()).or_insert_with(|| Connections::new(4096))))
}
fn key(caller: &str, server: &str) -> ConnectionKey {
    ConnectionKey {
        user: caller.into(),
        upstream: server.into(),
        downstream_client: caller.into(),
    }
}
fn custom(unit: &CallUnit) -> Option<&str> {
    match &unit.disposition {
        Disposition::Request { row, .. } if row.method.starts_with("connections/") => {
            Some(row.method)
        }
        _ => None,
    }
}
pub(super) fn route<'a>(disposition: &Disposition, value: Option<&'a Value>) -> Option<&'a str> {
    let Disposition::Request { row, .. } = disposition else {
        return None;
    };
    row.method.starts_with("connections/").then_some(())?;
    value?.pointer("/params/server")?.as_str()
}
fn respond(unit: &mut CallUnit, result: Value) -> Step {
    let id = match &unit.disposition {
        Disposition::Request { id, .. } => id.clone(),
        _ => Value::Null,
    };
    let body = busbar_contract::jsonrpc::result_bytes(
        &crate::codec::json(&id),
        &crate::codec::json(&result),
    );
    unit.pending = Some(Pending::answer(200, body, unit.framing.as_ref(), &[]));
    Step::Write
}
fn refused(unit: &mut CallUnit, message: &str) -> Step {
    let id = match &unit.disposition {
        Disposition::Request { id, .. } => Some(id.clone()),
        _ => None,
    };
    let r = crate::tool_arrival::Refusal {
        status: 403,
        id,
        code: crate::codec::CODE_REFUSED,
        message: message.into(),
        data: None,
    };
    unit.pending = Some(Pending::answer(
        r.status,
        r.body(),
        unit.framing.as_ref(),
        &[],
    ));
    Step::Write
}
fn scope<'a>(state: &'a Unit, need: u32, url: &'a str) -> OutboundScope<'a> {
    OutboundScope {
        need,
        member: &state.key.upstream,
        resource: url,
        connection: &state.public.id,
    }
}
fn emit(unit: &mut CallUnit, request: crate::client::jsonrpc::OutboundRequest) -> Step {
    unit.pending = Some(Pending::far(crate::call::OutboundCall {
        verb: "POST",
        target: crate::call::path_of(&request.url),
        fields: request.headers,
        body: request.body,
    }));
    Step::Write
}
fn bound_key(plane: &McpDoor, caller: &str, server: &str, now: u64) -> Option<DiscoveryKey> {
    table(plane, |t| t.discovery_key(&key(caller, server), now).ok())
}
pub(super) fn list(plane: &McpDoor, caller: &str, server: &str, now: u64) -> PublishedList {
    bound_key(plane, caller, server, now)
        .and_then(|k| plane.connection_lists.get(&k))
        .unwrap_or_default()
}
pub(super) fn enabled(held: &Held, server: &str) -> bool {
    matches!(
        held.section.effective_upstream_credentials(server),
        Some(busbar_contract::config::UpstreamCreds::Connection)
    )
}

pub(super) fn answer(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
) -> Option<Step> {
    let method = custom(unit).map(str::to_owned);
    let held = unit.held.clone()?;
    let server = if method.is_some() {
        match unit
            .params
            .as_ref()
            .and_then(|p| p.get("server"))
            .and_then(Value::as_str)
        {
            Some(server) => server.to_owned(),
            None => return Some(refused(unit, "A configured server is required.")),
        }
    } else {
        let Disposition::Request { row, .. } = &unit.disposition else {
            return None;
        };
        if row.op != crate::tool_ops::OP_TOOL_CALL {
            return None;
        }
        let name = unit.params.as_ref()?.get("name")?.as_str()?;
        held.catalogue.tool(name)?.server.clone()
    };
    if !enabled(&held, &server) {
        return method.map(|_| refused(unit, "This member does not use per-user connections."));
    }
    if caller.is_empty() {
        return Some(refused(
            unit,
            "An authenticated credential identity is required.",
        ));
    }
    let def = held.section.servers.get(&server)?;
    let oauth = def.oauth.as_ref()?;
    let Some(services) = plane.services else {
        return Some(refused(unit, "Connection host services are unavailable."));
    };
    let Some(now) = wall_ms(Some(services), ticket, &mut unit.issued) else {
        return Some(refused(unit, "The host clock is unavailable."));
    };
    ask_entitlements(Some(services), ticket, unit, &[(statement::SCOPE, &server)]);
    if !admit(&unit.entitled)(statement::SCOPE, &server) {
        return Some(refused(unit, "The member is not granted to this caller."));
    }
    if unit.connection.is_none() {
        let k = key(caller, &server);
        if method.as_deref() == Some("connections/authorize") {
            if unit
                .params
                .as_ref()
                .and_then(|p| p.get("consent"))
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Some(refused(unit,"Explicit consent=true is required for the configured issuer, resource, client and scopes."));
            }
            let mut entropy = [0; 64];
            if services
                .random_fill(
                    door_tasks::handle(ticket, &mut unit.issued, &mut None),
                    &mut entropy,
                )
                .is_err()
            {
                return Some(refused(
                    unit,
                    "Secure authorization entropy is unavailable.",
                ));
            }
            let result = table(plane, |t| {
                if t.get(&k).is_some_and(|c| c.status != Status::Revoked) {
                    return Err(crate::connections::Error::NotActive);
                }
                t.grant_consent(k.clone(), oauth.binding(), oauth.scopes.clone())?;
                t.begin_authorization(
                    &k,
                    entropy[..32].try_into().unwrap(),
                    entropy[32..].try_into().unwrap(),
                    now,
                    now.saturating_add(300_000),
                )
            });
            let Ok(auth) = result else {
                return Some(refused(
                    unit,
                    "Revoke the existing connection before authorizing again.",
                ));
            };
            plane.connection_config.insert(
                k.clone(),
                (
                    def.url.clone(),
                    oauth.token_endpoint.clone(),
                    oauth.authorization_endpoint.clone(),
                ),
            );
            let mut url = url::Url::parse(&oauth.authorization_endpoint).ok()?;
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &auth.binding.client_id)
                .append_pair("redirect_uri", &auth.binding.redirect_uri)
                .append_pair("resource", &auth.binding.resource)
                .append_pair(
                    "scope",
                    &auth.scopes.iter().cloned().collect::<Vec<_>>().join(" "),
                )
                .append_pair("state", &auth.state)
                .append_pair("code_challenge", &auth.code_challenge)
                .append_pair("code_challenge_method", "S256");
            return Some(respond(
                unit,
                serde_json::json!({"authorization_url":url.as_str(),"issuer":oauth.issuer,"resource":oauth.resource,"scopes":oauth.scopes}),
            ));
        }
        let Some(public) = table(plane, |t| t.get(&k).cloned()) else {
            return Some(refused(unit, "Authorize this upstream connection first."));
        };
        if method.as_deref() != Some("connections/revoke")
            && (public.binding != oauth.binding()
                || public.scopes != oauth.scopes
                || plane.connection_config.get(&k)
                    != Some((
                        def.url.clone(),
                        oauth.token_endpoint.clone(),
                        oauth.authorization_endpoint.clone(),
                    )))
        {
            return Some(refused(
                unit,
                "Connection configuration changed; revoke and authorize again.",
            ));
        }
        let phase = match method.as_deref() {
            Some("connections/callback") => {
                let Some(params) = unit.params.as_mut() else {
                    return Some(refused(unit, "Missing callback parameters."));
                };
                let state = params
                    .get("state")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let mut binding = oauth.binding();
                binding.issuer = params
                    .get("iss")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let Some(code) = params
                    .get_mut("code")
                    .and_then(Cred::take)
                    .filter(|c| !c.is_empty())
                else {
                    return Some(refused(unit, "Missing authorization code."));
                };
                let permit = table(plane, |t| t.consume_callback(&k, &state, &binding, now));
                let Ok(permit) = permit else {
                    return Some(refused(
                        unit,
                        "Invalid, expired, or consumed authorization callback.",
                    ));
                };
                let mut verifier = Value::String(permit.verifier().to_owned());
                let verifier = Cred::take(&mut verifier)?.require_secure();
                let body = FormBody::new()
                    .public("grant_type", "authorization_code")
                    .public("client_id", &binding.client_id)
                    .public("redirect_uri", &binding.redirect_uri)
                    .public("resource", &binding.resource)
                    .sealed("code", &code.require_secure())
                    .sealed("code_verifier", &verifier)
                    .encoded()
                    .ok()?;
                Phase::Prepare {
                    permit: Permit::Authorize(permit),
                    body,
                    token_url: oauth.token_endpoint.clone(),
                }
            }
            Some("connections/refresh") => {
                let Some(revision) = plane.connection_refresh.get(&k) else {
                    return Some(refused(
                        unit,
                        "No refresh credential is retained; authorize again.",
                    ));
                };
                let Ok(permit) = table(plane, |t| {
                    t.begin_refresh(&k, now, now.saturating_add(300_000))
                }) else {
                    return Some(refused(
                        unit,
                        "Refresh is already pending or consent is not active.",
                    ));
                };
                Phase::RefreshBind {
                    permit: Some(permit),
                    revision,
                }
            }
            Some("connections/revoke") => {
                if table(plane, |t| t.revoke(&k)).is_err() {
                    return Some(refused(unit, "Connection cannot be revoked."));
                }
                let refresh_revision = plane.connection_refresh.get(&k).unwrap_or(0);
                plane
                    .connection_lists
                    .with_all(|lists| lists.retain(|d, _| d.connection != k));
                plane
                    .connection_checked
                    .with_all(|checks| checks.retain(|d, _| d.connection != k));
                Phase::Revoke {
                    access_done: false,
                    refresh_revision,
                }
            }
            _ => {
                if bound_key(plane, caller, &server, now).is_none() {
                    return Some(refused(
                        unit,
                        "The upstream connection is absent, expired, or revoked.",
                    ));
                }
                Phase::Bind
            }
        };
        let (scope_url, token_url, _) = plane.connection_config.get(&k).unwrap_or_else(|| {
            (
                def.url.clone(),
                oauth.token_endpoint.clone(),
                oauth.authorization_endpoint.clone(),
            )
        });
        unit.connection = Some(Unit {
            key: k,
            public,
            scope_url,
            token_url,
            phase,
            handle: None,
            status: 0,
            bytes: zeroize::Zeroizing::new(Vec::new()),
            fields: Vec::new(),
        });
    }
    let mut state = unit.connection.take()?;
    let handle = door_tasks::handle(ticket, &mut unit.issued, &mut state.handle);
    let result = match &mut state.phase {
        Phase::Prepare {
            body, token_url, ..
        } => {
            let scope = OutboundScope {
                need: statement::NEED_TOKEN,
                member: &state.key.upstream,
                resource: token_url,
                connection: &state.public.id,
            };
            match services.outbound_prepare(handle, scope, now / 1000 + 300, body) {
                Poll::Pending => Some(Step::Pending),
                Poll::Ready(Err(_)) => Some(refused(
                    unit,
                    "The host refused protected token exchange custody.",
                )),
                Poll::Ready(Ok(())) => {
                    let old = std::mem::replace(&mut state.phase, Phase::Bound);
                    let Phase::Prepare {
                        permit, token_url, ..
                    } = old
                    else {
                        unreachable!()
                    };
                    state.phase = Phase::Exchange(Some(permit));
                    state.handle = None;
                    unit.pending = Some(Pending {
                        need: statement::NEED_TOKEN + 1,
                        request: Some(("POST", crate::call::path_of(&token_url))),
                        fields: vec![(
                            CONTENT_TYPE.into(),
                            "application/x-www-form-urlencoded".into(),
                        )],
                        ..Pending::default()
                    });
                    Some(Step::Write)
                }
            }
        }
        Phase::RefreshBind { revision, .. } => {
            let refresh_id = format!("{}:refresh", state.public.id);
            let scope = OutboundScope {
                need: statement::NEED_TOKEN,
                member: &state.key.upstream,
                resource: &oauth.token_endpoint,
                connection: &refresh_id,
            };
            match services.outbound_bind(handle, scope, *revision) {
                Poll::Pending => Some(Step::Pending),
                Poll::Ready(Err(_)) => Some(refused(unit, "The host refused refresh custody.")),
                Poll::Ready(Ok(_)) => {
                    let Phase::RefreshBind { permit, .. } = &mut state.phase else {
                        unreachable!()
                    };
                    state.phase = Phase::Exchange(Some(Permit::Refresh(permit.take().unwrap())));
                    state.handle = None;
                    unit.pending = Some(Pending {
                        need: statement::NEED_TOKEN + 1,
                        request: Some(("POST", crate::call::path_of(&oauth.token_endpoint))),
                        fields: vec![(
                            CONTENT_TYPE.into(),
                            "application/x-www-form-urlencoded".into(),
                        )],
                        ..Pending::default()
                    });
                    Some(Step::Write)
                }
            }
        }
        Phase::Publish {
            seal,
            expiry,
            refresh,
            ..
        } => {
            if let Some(body) = refresh.as_ref() {
                let refresh_id = format!("{}:refresh", state.public.id);
                let scope = OutboundScope {
                    need: statement::NEED_TOKEN,
                    member: &state.key.upstream,
                    resource: &oauth.token_endpoint,
                    connection: &refresh_id,
                };
                let expected = plane.connection_refresh.get(&state.key).unwrap_or(0);
                match services.outbound_publish_body(
                    handle,
                    scope,
                    expected,
                    now / 1000 + 30 * 24 * 3600,
                    body,
                ) {
                    Poll::Pending => {
                        unit.connection = Some(state);
                        return Some(Step::Pending);
                    }
                    Poll::Ready(Err(_)) => {
                        unit.connection = Some(state);
                        return Some(refused(
                            unit,
                            "The host refused refresh credential publication.",
                        ));
                    }
                    Poll::Ready(Ok(revision)) => {
                        plane.connection_refresh.insert(state.key.clone(), revision);
                        *refresh = None;
                        state.handle = None;
                        unit.connection = Some(state);
                        return answer(plane, ticket, caller, unit);
                    }
                }
            }

            let scope = OutboundScope {
                need: statement::NEED_UPSTREAM,
                member: &state.key.upstream,
                resource: &state.scope_url,
                connection: &state.public.id,
            };
            match services.outbound_publish(
                handle,
                scope,
                state.public.revision,
                *expiry / 1000,
                "authorization",
                seal,
            ) {
                Poll::Pending => Some(Step::Pending),
                Poll::Ready(Err(_)) => {
                    Some(refused(unit, "The host refused credential publication."))
                }
                Poll::Ready(Ok(revision)) => {
                    let Phase::Publish { permit, expiry, .. } = &mut state.phase else {
                        unreachable!()
                    };
                    let completed = table(plane, |t| match permit.take().unwrap() {
                        Permit::Authorize(p) => t.complete_authorization(p, now, *expiry),
                        Permit::Refresh(p) => t.complete_refresh(p, now, *expiry),
                    });
                    match completed {
                        Ok(public) if public.revision == revision => {
                            plane
                                .connection_lists
                                .with_all(|lists| lists.retain(|d, _| d.connection != state.key));
                            plane
                                .connection_checked
                                .with_all(|checks| checks.retain(|d, _| d.connection != state.key));
                            state.phase = Phase::Bound;
                            Some(respond(unit, serde_json::to_value(public).ok()?))
                        }
                        _ => {
                            state.public.revision = revision;
                            state.phase = Phase::Revoke {
                                access_done: false,
                                refresh_revision: plane
                                    .connection_refresh
                                    .get(&state.key)
                                    .unwrap_or(0),
                            };
                            state.handle = None;
                            unit.connection = Some(state);
                            return answer(plane, ticket, caller, unit);
                        }
                    }
                }
            }
        }
        Phase::Revoke {
            access_done,
            refresh_revision,
        } => {
            let refresh_id = format!("{}:refresh", state.public.id);
            let scope = if *access_done {
                OutboundScope {
                    need: statement::NEED_TOKEN,
                    member: &state.key.upstream,
                    resource: &state.token_url,
                    connection: &refresh_id,
                }
            } else {
                OutboundScope {
                    need: statement::NEED_UPSTREAM,
                    member: &state.key.upstream,
                    resource: &state.scope_url,
                    connection: &state.public.id,
                }
            };
            let revision = if *access_done {
                *refresh_revision
            } else {
                state.public.revision
            };
            match services.outbound_revoke(handle, scope, revision) {
                Poll::Pending => Some(Step::Pending),
                Poll::Ready(Err(_)) => Some(refused(
                    unit,
                    "Local consent is revoked; host revocation could not be confirmed.",
                )),
                Poll::Ready(Ok(_)) if !*access_done => {
                    *access_done = true;
                    state.handle = None;
                    unit.connection = Some(state);
                    return answer(plane, ticket, caller, unit);
                }
                Poll::Ready(Ok(_)) => {
                    plane.connection_refresh.remove(&state.key);
                    Some(respond(unit, serde_json::json!({"revoked":true})))
                }
            }
        }
        Phase::Bind => match services.outbound_bind(
            handle,
            scope(&state, statement::NEED_UPSTREAM, &state.scope_url),
            state.public.revision,
        ) {
            Poll::Pending => Some(Step::Pending),
            Poll::Ready(Err(_)) => Some(refused(unit, "The host refused this connection binding.")),
            Poll::Ready(Ok(_)) => {
                state.handle = None;
                let discovery = bound_key(plane, caller, &server, now)?;
                let ttl = busbar_contract::duration::parse_duration_secs(
                    def.verify_ttl
                        .as_deref()
                        .unwrap_or(crate::tools_config::DEFAULT_MCP_VERIFY_TTL),
                )
                .unwrap_or(0)
                .saturating_mul(1000);
                let fresh = plane
                    .connection_checked
                    .get(&discovery)
                    .is_some_and(|at| ttl > 0 && now >= at && now - at < ttl);
                if method.as_deref() == Some("connections/discover")
                    || !fresh
                    || plane.connection_lists.get(&discovery).is_none()
                {
                    let original = list_request(&held, &server, def);
                    let n = door_sessions::Negotiating::begin(
                        plane,
                        &server,
                        &discovery.session_key(),
                        original,
                    );
                    let request = n.first_request()?.clone();
                    state.phase = Phase::Discover {
                        negotiating: Box::new(n),
                        pages: crate::client::jsonrpc::ToolPages::default(),
                    };
                    Some(emit(unit, request))
                } else {
                    state.phase = Phase::Bound;
                    None
                }
            }
        },
        Phase::Bound => None,
        Phase::Exchange(_) | Phase::Discover { .. } => Some(Step::Taken),
    };
    unit.connection = Some(state);
    result
}

#[derive(serde::Deserialize)]
struct TokenReply {
    access_token: Cred,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
    #[serde(default)]
    refresh_token: Option<Cred>,
}

pub(super) fn far(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    input: Lent<'_, OnPieceIn>,
) -> Option<Step> {
    let state = unit.connection.as_mut()?;
    if !matches!(state.phase, Phase::Exchange(_) | Phase::Discover { .. }) {
        return None;
    }
    if input.flags() & PIECE_HAS_STATUS != 0 {
        state.status = input.status_code();
        state.fields = input
            .head_fields()
            .iter()
            .filter_map(|f| {
                Some((
                    f.name().as_str().ok()?.to_string(),
                    f.value().as_str().ok()?.to_string(),
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
        state.bytes.fill(0);
        state.bytes.clear();
        state.phase = Phase::Bound;
        return Some(refused(
            unit,
            "The upstream response exceeds the response bound.",
        ));
    }
    state.bytes.extend_from_slice(input.bytes().bytes());
    if input.flags() & PIECE_LAST == 0 {
        return Some(Step::Taken);
    }
    let mut state = unit.connection.take()?;
    match &mut state.phase {
        Phase::Exchange(permit) => {
            let reply = busbar_contract::abi::sdk::cred::json_reply::<TokenReply>(&state.bytes);
            state.bytes.fill(0);
            state.bytes.clear();
            let Ok(reply) = reply else {
                return Some(failed(plane, unit, state, "Invalid OAuth token response."));
            };
            let scopes_ok = reply.scope.as_ref().is_none_or(|s| {
                s.split_whitespace()
                    .all(|s| state.public.scopes.contains(s))
            });
            if !(200..300).contains(&state.status)
                || !reply.token_type.eq_ignore_ascii_case("bearer")
                || reply.access_token.is_empty()
                || reply.expires_in == 0
                || !scopes_ok
            {
                return Some(failed(
                    plane,
                    unit,
                    state,
                    "OAuth token response does not satisfy the consent binding.",
                ));
            }
            let now = wall_ms(plane.services, ticket, &mut unit.issued)?;
            let Some(expiry) = reply
                .expires_in
                .checked_mul(1000)
                .and_then(|ttl| now.checked_add(ttl))
            else {
                return Some(failed(plane, unit, state, "Invalid access token expiry."));
            };
            let refresh = reply
                .refresh_token
                .map(|token| {
                    let oauth = unit
                        .held
                        .as_ref()
                        .and_then(|h| h.section.servers.get(&state.key.upstream))
                        .and_then(|d| d.oauth.as_ref())
                        .expect("connection has configured OAuth");
                    FormBody::new()
                        .public("grant_type", "refresh_token")
                        .public("client_id", &oauth.client_id)
                        .public("resource", &oauth.resource)
                        .sealed("refresh_token", &token.require_secure())
                        .encoded()
                })
                .transpose()
                .ok()?;
            state.phase = Phase::Publish {
                permit: permit.take(),
                seal: reply.access_token.require_secure().bearer(),
                expiry,
                refresh,
            };
            state.handle = None;
            unit.connection = Some(state);
            answer(plane, ticket, caller, unit)
        }
        Phase::Discover { negotiating, pages } => {
            let answer = negotiating.governed_answer(
                plane,
                &state.key.upstream,
                state.status as u16,
                std::mem::take(&mut state.fields),
                std::mem::take(&mut *state.bytes),
            );
            match answer {
                door_sessions::Governed::Send(request) => {
                    unit.connection = Some(state);
                    Some(emit(unit, request))
                }
                door_sessions::Governed::Done(door_sessions::Negotiated::Answer(
                    status,
                    body,
                    sse,
                    sent,
                )) => {
                    let id = Value::from(sent.unwrap_or(CONNECT_REQUEST_ID));
                    let body = if sse {
                        crate::call::answer_body(&body, true, &id)
                    } else {
                        body
                    };
                    let crate::client::jsonrpc::RpcOutcome::Result(result) =
                        crate::client::jsonrpc::parse_response_id(&body, &id)
                    else {
                        return Some(failed(
                            plane,
                            unit,
                            state,
                            "Discovery returned no valid tools result.",
                        ));
                    };
                    if !(200..300).contains(&status) {
                        return Some(failed(
                            plane,
                            unit,
                            state,
                            "Discovery was refused by the upstream.",
                        ));
                    }
                    match pages.take(result) {
                        Ok(crate::client::jsonrpc::Paged::Next(cursor)) => {
                            let held = unit.held.clone()?;
                            let def = held.section.servers.get(&state.key.upstream)?;
                            let original = list_request(&held, &state.key.upstream, def);
                            let request =
                                crate::client::jsonrpc::next_list_request(&original, &cursor)
                                    .ok()?;
                            let now = wall_ms(plane.services, ticket, &mut unit.issued)?;
                            let key = bound_key(plane, caller, &state.key.upstream, now)?;
                            **negotiating = door_sessions::Negotiating::begin(
                                plane,
                                &state.key.upstream,
                                &key.session_key(),
                                request,
                            );
                            let request = negotiating.first_request()?.clone();
                            unit.connection = Some(state);
                            Some(emit(unit, request))
                        }
                        Ok(crate::client::jsonrpc::Paged::Done(result)) => {
                            let now = wall_ms(plane.services, ticket, &mut unit.issued)?;
                            let Some(k) = bound_key(plane, caller, &state.key.upstream, now) else {
                                return Some(failed(
                                    plane,
                                    unit,
                                    state,
                                    "The connection expired or was revoked during discovery.",
                                ));
                            };
                            let response = busbar_contract::abi::sdk::exchange::ExchangeResponse {
                                status,
                                reason: None,
                                fields: Vec::new(),
                                body: busbar_contract::jsonrpc::result_bytes(
                                    &crate::codec::json(&Value::from(CONNECT_REQUEST_ID)),
                                    &crate::codec::json(&result),
                                ),
                            };
                            let sighting = sighting_of(Ok(response), CONNECT_REQUEST_ID);
                            plane.connection_checked.insert(k.clone(), now);
                            plane.connection_lists.insert(
                                k,
                                PublishedList {
                                    generation: state.public.revision,
                                    sighting,
                                },
                            );
                            state.phase = Phase::Bound;
                            unit.connection = Some(state);
                            if custom(unit).is_some() {
                                Some(respond(unit, serde_json::json!({"discovered":true})))
                            } else {
                                Some(Step::Taken)
                            }
                        }
                        Err(_) => Some(refused(
                            unit,
                            "Invalid or excessive paginated tool discovery.",
                        )),
                    }
                }
                _ => Some(refused(unit, "Governed upstream discovery failed.")),
            }
        }
        _ => None,
    }
}

pub(super) fn ready(unit: &CallUnit) -> bool {
    unit.connection
        .as_ref()
        .is_some_and(|c| matches!(c.phase, Phase::Bound))
}
pub(super) fn partition(
    plane: &McpDoor,
    ticket: Ticket,
    caller: &str,
    unit: &mut CallUnit,
    member: &str,
) -> Option<String> {
    let now = wall_ms(plane.services, ticket, &mut unit.issued)?;
    bound_key(plane, caller, member, now).map(|k| k.session_key())
}

fn cleanup_state(plane: &McpDoor, state: Unit) {
    let permit = match state.phase {
        Phase::Prepare { permit, .. } => Some(permit),
        Phase::Exchange(permit) | Phase::Publish { permit, .. } => permit,
        Phase::RefreshBind { permit, .. } => permit.map(Permit::Refresh),
        _ => None,
    };
    if let Some(Permit::Refresh(permit)) = permit {
        let _ = table(plane, |t| t.fail_refresh(permit));
    }
}
fn failed(plane: &McpDoor, unit: &mut CallUnit, state: Unit, message: &str) -> Step {
    cleanup_state(plane, state);
    refused(unit, message)
}
pub(super) fn cleanup(plane: &McpDoor, unit: &mut CallUnit) {
    if let Some(state) = unit.connection.take() {
        cleanup_state(plane, state)
    }
}

#[cfg(test)]
#[path = "tests/connection_runtime_tests.rs"]
mod tests;
