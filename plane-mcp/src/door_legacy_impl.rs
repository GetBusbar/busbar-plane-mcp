// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

include!("legacy_wire.rs");
use super::McpDoor;
use busbar_contract::abi::plane::PlaneDriveOut;
use busbar_contract::abi::sdk::{Instance, Out};

/// Wakes every call in `woken`.
fn wake_all(plane: &McpDoor, woken: Vec<Ticket>) {
    if let Some(wake) = plane.wake.as_ref() {
        for t in woken {
            wake.wake(t);
        }
    }
}

/// Whether streams or child-work cleanup need maintenance on the instance's driver.
pub(super) fn any(plane: &McpDoor) -> bool {
    !plane.legacy.is_empty()
        || !plane.relays.is_empty()
        || plane.legacy_seq.with_all(|state| {
            state
                .get(&())
                .is_some_and(|driver| driver.retirement.queued())
        })
}

/// THE DRIVER'S PART, on the instance's driver ticket (`drive`): every held stream read as far as
/// it goes, child work whose state lapsed settled, and every waiting call reached woken. A dead stream no call
/// waits on any more is let go. Pending operations retain their handles. A terminal handle is
/// acknowledged through the SDK and reused only after the host confirms its result was retired.
pub(super) fn drive(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    owner: HostCtx,
    extensions: &[u8],
) -> Result<bool, Error> {
    if !any(plane) {
        return Ok(false);
    }
    let Some(host) = plane.host.as_ref() else {
        return Ok(false);
    };
    let driver = instance.ticket();
    let cycle = plane.driver.get(&()).map_or(0, |(_, now)| now);
    let held = plane.current();
    let grants_of = |member: &str| {
        held.as_ref()
            .and_then(|h| h.section.servers.get(member))
            .map(|d| d.grants)
            .unwrap_or_default()
    };
    let mut woken = Vec::new();
    let mut announced = Announced::new();
    let result = plane.legacy_seq.with_all(|states| {
        let state = states.entry(()).or_default();
        state.begin(owner, driver, extensions)?;
        plane.legacy.with_all(|m| {
            for link in m.values_mut() {
                let grants = grants_of(&link.member);
                link.drive(
                    (host, driver, cycle),
                    state,
                    grants,
                    &mut woken,
                    &mut announced,
                );
            }
            m.retain(|_, l| {
                l.dead.is_none()
                    || l.retiring()
                    || !l.waiters.is_empty()
                    || !l.answers.is_empty()
                    || !l.failed.is_empty()
            });
        });
        let cleanup_pending = super::door_relay_cleanup::drive(plane, driver, state);
        if let Some(error) = state.failure {
            return Err(error);
        }
        Ok(pending(plane) || cleanup_pending || state.retirement.queued())
    });
    for announcement in announced {
        match announcement {
            Announcement::Resource(server, uri) => {
                super::door_sessions::announce(plane, &server, &uri)
            }
            Announcement::ListChanged(server) => super::door_sessions::list_changed(
                plane,
                &server,
                (cycle != 0).then_some(cycle / 1_000_000),
            ),
        }
    }
    wake_all(plane, woken);
    result
}

pub(super) fn acknowledge(
    plane: &McpDoor,
    out: &mut Out<'_, PlaneDriveOut>,
) -> Result<bool, Error> {
    plane.legacy_seq.with_all(|states| {
        let Some(state) = states.get_mut(&()) else {
            return Ok(false);
        };

        if let Some(ack) = state.retirement.acknowledgement(0)? {
            out.completion_ack(&plane.inspection_leases, &ack)?;
        }
        Ok(state.retirement.queued())
    })
}

fn pending(plane: &McpDoor) -> bool {
    plane.legacy.with_all(|links| {
        links.values().any(|link| {
            link.handle.is_some()
                || link
                    .replying
                    .as_ref()
                    .is_some_and(|reply| reply.handle.is_some())
        })
    })
}

/// `dropped` replies a call took from the stream of `key` but has no answer to audit them on: counted
/// on the stream again, for the next call's answer.
pub(super) fn recount(plane: &McpDoor, key: &str, dropped: u32) {
    if dropped == 0 {
        return;
    }
    plane.legacy.with(&key.to_string(), |l| {
        if let Some(l) = l {
            l.dropped = l.dropped.saturating_add(dropped).min(MAX_DROPPED_AUDITED);
        }
    });
}

/// The op on `ticket` was cancelled: no call waits there any more, an answer still to come for it
/// is a reply no call waits for, and one already read for it is dropped. A cancelled call that was
/// running the stream's `initialize` hands it back: the next call runs it, and the calls parked
/// behind it are woken to.
pub(super) fn cancelled(plane: &McpDoor, ticket: Ticket) {
    let woken = plane.legacy.with_all(|m| {
        let mut woken = Vec::new();
        for l in m.values_mut() {
            let gone: Vec<String> = l
                .waiters
                .iter()
                .filter(|(_, t)| **t == ticket)
                .map(|(id, _)| id.clone())
                .collect();
            for id in gone {
                l.waiters.remove(&id);
                l.notes.remove(&id);
                l.notes_bytes.remove(&id);
            }
            l.answers.retain(|id, (t, _)| {
                let mine = *t == ticket;
                if mine {
                    l.notes.remove(id);
                    l.notes_bytes.remove(id);
                }
                !mine
            });
            l.parked.retain(|t| *t != ticket);
            l.failed.retain(|t| *t != ticket);
            if l.init == Init::Running && l.init_by == Some(ticket) {
                l.init = Init::Idle;
                l.init_by = None;
                woken.append(&mut l.parked);
            }
            if l.dead.is_some() && l.answers.is_empty() {
                woken.append(&mut l.parked);
            }
        }
        woken
    });
    wake_all(plane, woken);
}

/// The initialization work owned by one call, retained before a POST can pend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum CallInit {
    #[default]
    Waiting,
    Posting,
    Answer,
    Notifying,
    Done,
}

/// One call's place on a held stream, parked on its unit across PENDING entries.
#[derive(Debug, Default)]
pub(super) struct Calling {
    /// The link it began on.
    generation: u64,
    /// The id it carries, once allocated.
    id: Option<u64>,
    /// Its own POST was taken.
    posted: bool,
    /// This call's owned initialization phase, including a pending first POST.
    init: CallInit,
}

/// What a call came to: the answer under the id it carried (an event stream, its progress and the
/// link's log records ahead of the answer, when the server said any: the `bool`), the replies dropped
/// on its link since the last answer, or why it failed.
pub(super) type Called = Result<(Vec<u8>, bool, u64, u32), String>;

/// The answer `body`, with `frames` ahead of it as one event stream when there are any: `(bytes,
/// is an event stream)`.
fn framed_answer(body: Vec<u8>, frames: Vec<Value>) -> (Vec<u8>, bool) {
    if frames.is_empty() {
        return (body, false);
    }

    match crate::framing::event_stream(&body, &frames) {
        Some(stream) => (stream, true),
        None => (body, false),
    }
}

/// A CALL OVER THE HELD STREAM of `key` (a member and a caller binding), on the call's own ticket:
/// the stream opened if none is, its `initialize` run by the first call that finds none done, the
/// call's request POSTed to the message address under an id of the stream's, and its answer taken
/// once the driver read it. PENDING meanwhile.
pub(super) fn call(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    binding: (&str, &str),
    original: &OutboundRequest,
    state: &mut Option<Calling>,
    timing: (u32, u64),
) -> Poll<Called> {
    call_using(
        instance.ticket(),
        plane,
        binding,
        original,
        state,
        timing,
        |where_, request, timeout| post(instance, plane, where_, request, timeout),
    )
}

/// Legacy call orchestration with the POST exchange supplied by the caller.
#[allow(clippy::too_many_arguments)]
fn call_using(
    ticket: Ticket,
    plane: &McpDoor,
    (key, member): (&str, &str),
    original: &OutboundRequest,
    state: &mut Option<Calling>,
    (base, timeout_ms): (u32, u64),
    mut post: impl FnMut((u32, &str), &OutboundRequest, u64) -> Poll<Result<(), String>>,
) -> Poll<Called> {
    if state.is_none() {
        let now = plane.driver.get(&()).map_or(0, |(_, now)| now);
        let mut retired = Vec::new();
        let opened = plane.legacy.with_all(|m| {
            if let Some(link) = m.get_mut(key).filter(|link| link.url != original.url) {
                link.die(
                    "the registered MCP endpoint changed; this legacy stream is no longer used",
                    &mut retired,
                );
            }
            if let Some(previous) = m.get_mut(key).filter(|link| {
                link.dead.is_some()
                    && (!link.answers.is_empty() || !link.failed.is_empty() || link.retiring())
            }) {
                if !previous.parked.contains(&ticket) {
                    previous.parked.push(ticket);
                }
                return Ok(None);
            }
            let usable = m.get(key).is_some_and(|l| l.dead.is_none());
            if !usable {
                let live = m.values().filter(|l| l.dead.is_none()).count();
                if !m.contains_key(key) && live >= MAX_LINKS {
                    let mut woken = Vec::new();
                    match m.values_mut().find(|l| l.idle()) {
                        Some(idle) => idle.die(IDLE, &mut woken),
                        None => {
                            return Err(format!(
                                "MCP server `{member}`: busbar already holds {MAX_LINKS} \
                                 2024-11-05 event streams, each in use by a call, and opens no \
                                 more until one is let go"
                            ));
                        }
                    }
                }

                let generation = next_generation()?;
                let stale = m.remove(key).map_or_else(Vec::new, |old| {
                    let mut stale = old.stale;
                    stale.extend(old.stream);
                    stale.extend(old.replying.and_then(|r| r.stream));
                    stale
                });
                let mut link = Link::new(generation, &original.url, member, original);
                link.stale = stale;
                m.insert(key.to_string(), link);
            }
            Ok(m.get_mut(key).map(|l| {
                if now != 0 {
                    l.last_used = now;
                }
                l.generation
            }))
        });
        wake_all(plane, retired);
        let generation = match opened {
            Ok(Some(generation)) => generation,
            Ok(None) => {
                super::door_listen::wake_driver(plane);
                return Poll::Pending;
            }
            Err(why) => return Poll::Ready(Err(why)),
        };
        *state = Some(Calling {
            generation,
            ..Calling::default()
        });
        super::door_listen::wake_driver(plane);
    }
    let st = state.as_mut().expect("set above");
    loop {
        let next = plane.legacy.with(&key.to_string(), |l| {
            let Some(l) = l.filter(|l| l.generation == st.generation) else {
                return Next::Fail(STREAM_CLOSED.to_string());
            };
            if let Some(id) = st.id {
                let text = Value::from(id).to_string();
                if let Some((_, body)) = l.answers.remove(&text) {
                    let mut frames = l.notes.remove(&text).unwrap_or_default();
                    l.notes_bytes.remove(&text);
                    frames.append(&mut l.logs);
                    l.logs_bytes = 0;
                    let woken = if l.dead.is_some() && l.answers.is_empty() {
                        std::mem::take(&mut l.parked)
                    } else {
                        Vec::new()
                    };
                    return Next::Answered(body, frames, id, std::mem::take(&mut l.dropped), woken);
                }
            }
            if let Some(why) = &l.dead {
                l.failed.retain(|t| *t != ticket);
                if let Some(id) = st.id {
                    l.waiters.remove(&Value::from(id).to_string());
                }
                return Next::Fail(why.clone());
            }
            let Some(address) = l.address.clone() else {
                if !l.parked.contains(&ticket) {
                    l.parked.push(ticket);
                }
                return Next::Wait;
            };
            match (l.init, st.init) {
                (Init::Idle, CallInit::Waiting) => {
                    l.init = Init::Running;
                    l.init_by = Some(ticket);
                    st.init = CallInit::Posting;
                    l.waiters
                        .insert(Value::from(INITIALIZE_ID).to_string(), ticket);
                    Next::PostInit(address)
                }
                (Init::Running, CallInit::Posting) if l.init_by == Some(ticket) => {
                    Next::PostInit(address)
                }
                (Init::Running, CallInit::Answer) if l.init_by == Some(ticket) => {
                    let text = Value::from(INITIALIZE_ID).to_string();
                    match l.answers.remove(&text) {
                        Some((_, body)) => Next::Initialized(body),
                        None => Next::Wait,
                    }
                }
                (Init::Running, CallInit::Notifying) if l.init_by == Some(ticket) => {
                    Next::PostInitialized(address)
                }
                (Init::Running, _) | (Init::Idle, _) => {
                    if !l.parked.contains(&ticket) {
                        l.parked.push(ticket);
                    }
                    Next::Wait
                }
                (Init::Done, _) if st.posted => Next::Wait,
                (Init::Done, _) => {
                    let id = match st.id {
                        Some(id) => id,
                        None => {
                            let id = l.next_id;
                            l.next_id = l.next_id.saturating_add(1);
                            if !l.wait(id, ticket) {
                                return Next::Fail(format!(
                                    "MCP server `{member}`: its 2024-11-05 event stream already \
                                     waits on {MAX_WAITING} calls"
                                ));
                            }
                            st.id = Some(id);
                            id
                        }
                    };
                    Next::PostCall(address, id)
                }
            }
        });
        match next {
            Next::Answered(body, frames, id, dropped, woken) => {
                wake_all(plane, woken);
                *state = None;
                let (body, sse) = framed_answer(body, frames);
                return Poll::Ready(Ok((body, sse, id, dropped)));
            }
            Next::Fail(why) => {
                *state = None;
                return Poll::Ready(Err(why));
            }
            Next::Wait => return Poll::Pending,
            Next::PostInit(address) => {
                let request =
                    initialize_request(original, &address, Revision::R2024_11_05, super::VERSION);
                match post((base, member), &request, timeout_ms) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => st.init = CallInit::Answer,
                    Poll::Ready(Err(why)) => {
                        *state = None;
                        return Poll::Ready(Err(fail_link(plane, key, ticket, &why)));
                    }
                }
            }
            Next::Initialized(body) => {
                if let crate::client::jsonrpc::RpcOutcome::Error { code, message } =
                    crate::client::jsonrpc::parse_response(&body, INITIALIZE_ID)
                {
                    let why = format!(
                        "MCP server `{member}` refused legacy `initialize` with JSON-RPC {code}: {}",
                        message.escape_debug()
                    );
                    *state = None;
                    return Poll::Ready(Err(fail_link(plane, key, ticket, &why)));
                }
                if offered_revision(&body) != Some(Revision::R2024_11_05) {
                    let why = format!(
                        "MCP server `{member}` answered `initialize` on its 2024-11-05 event \
                         stream with a revision busbar does not carry there"
                    );
                    *state = None;
                    return Poll::Ready(Err(fail_link(plane, key, ticket, &why)));
                }
                st.init = CallInit::Notifying;
            }
            Next::PostInitialized(address) => {
                let request =
                    initialized_notification(original, &address, Revision::R2024_11_05, None);
                match post(
                    (base.saturating_add(POST_SPAN), member),
                    &request,
                    timeout_ms,
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => {
                        st.init = CallInit::Done;
                        let woken = plane.legacy.with(&key.to_string(), |l| {
                            l.map(|l| {
                                l.init = Init::Done;
                                l.init_by = None;
                                std::mem::take(&mut l.parked)
                            })
                            .unwrap_or_default()
                        });
                        wake_all(plane, woken);
                    }
                    Poll::Ready(Err(why)) => {
                        *state = None;
                        return Poll::Ready(Err(fail_link(plane, key, ticket, &why)));
                    }
                }
            }
            Next::PostCall(address, id) => {
                let request =
                    lower_request(original, &address, Revision::R2024_11_05, None, Some(id));
                plane.legacy.with(&key.to_string(), |link| {
                    if let Some(link) = link.filter(|link| link.generation == st.generation) {
                        link.fields.clone_from(&request.headers);
                    }
                });
                match post(
                    (base.saturating_add(POST_SPAN.saturating_mul(2)), member),
                    &request,
                    timeout_ms,
                ) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(())) => st.posted = true,
                    Poll::Ready(Err(why)) => {
                        plane.legacy.with(&key.to_string(), |l| {
                            if let Some(l) = l.filter(|l| l.generation == st.generation) {
                                let id = id.to_string();
                                l.waiters.remove(&id);
                                l.answers.remove(&id);
                                l.notes.remove(&id);
                                l.notes_bytes.remove(&id);
                            }
                        });
                        *state = None;
                        return Poll::Ready(Err(why));
                    }
                }
            }
        }
    }
}

/// What a call does next, decided under the link's lock.
enum Next {
    Answered(Vec<u8>, Vec<Value>, u64, u32, Vec<Ticket>),
    Fail(String),
    Wait,
    PostInit(String),
    Initialized(Vec<u8>),
    PostInitialized(String),
    PostCall(String, u64),
}

/// The link of `key` failed for `why`: every call on it is woken to read it.
fn fail_link(plane: &McpDoor, key: &str, ticket: Ticket, why: &str) -> String {
    let mut woken = Vec::new();
    plane.legacy.with(&key.to_string(), |l| {
        if let Some(l) = l {
            l.die(why, &mut woken);
            l.failed.retain(|t| *t != ticket);
        }
    });
    wake_all(plane, woken);
    why.to_string()
}

/// ONE POST to the message address on the call's ticket: taken when the server answered it 2xx (the
/// answer itself arrives on the stream).
fn post(
    instance: &Instance<'_, McpDoor>,
    plane: &McpDoor,
    (base, member): (u32, &str),
    request: &OutboundRequest,
    timeout_ms: u64,
) -> Poll<Result<(), String>> {
    let polled = super::exchange_at(
        instance,
        plane.host.as_ref(),
        base,
        &request.url,
        member,
        || super::door_sessions::exchange_request(request, timeout_ms),
    );
    post_result(polled, member)
}

fn post_result(
    polled: Poll<
        Result<
            busbar_contract::abi::sdk::exchange::ExchangeResponse,
            busbar_contract::abi::sdk::conn::ConnFailure,
        >,
    >,
    member: &str,
) -> Poll<Result<(), String>> {
    match polled {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(r)) if (200..300).contains(&r.status) => Poll::Ready(Ok(())),
        Poll::Ready(Ok(r)) => Poll::Ready(Err(format!(
            "MCP server `{member}` refused a POST to its 2024-11-05 message address (HTTP {})",
            r.status
        ))),
        Poll::Ready(Err(e)) => Poll::Ready(Err(e.to_string())),
    }
}

#[cfg(test)]
#[path = "tests/legacy_link_tests.rs"]
mod tests;

/// Allocate an incarnation that survives removal of a retired link from the instance map.
fn next_generation() -> Result<u64, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_update(
        std::sync::atomic::Ordering::Relaxed,
        std::sync::atomic::Ordering::Relaxed,
        |n| n.checked_add(1),
    )
    .map_err(|_| "legacy MCP link identity space exhausted".to_string())
}
