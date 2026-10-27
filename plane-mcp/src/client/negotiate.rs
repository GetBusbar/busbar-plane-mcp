// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE UPSTREAM CALL, NEGOTIATED: the client ladder as a sans-I/O state machine. [`Negotiator`]
//! carries one stateless request and says, one [`Action`] at a time, what to put on the wire: the
//! request itself; on a refusal `initialize`, `notifications/initialized` and the request lowered
//! into the revision the upstream chose; on a refusal of `initialize`, [`Action::OpenStream`] (the
//! driver carries the call over the `2024-11-05` event stream, `door_legacy`).

use serde_json::Value;

use super::compat::{
    initialize_request, initialized_notification, lower_request, offered_revision, probe_outcome,
    stateless_outcome,
};
use super::jsonrpc::OutboundRequest;
use crate::revision::{self, Revision, StepOutcome};
use crate::tool_sessions::Remembered;

/// What came back from one hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopAnswer {
    /// The response status.
    pub status: u16,
    /// The response head's kept fields, lower-case names.
    pub fields: Vec<(String, String)>,
    /// The body (the last JSON-RPC message of an event-stream answer, as the engine reads it).
    pub body: Vec<u8>,
}

impl HopAnswer {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    const fn ok(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// Why a negotiated call stopped without an answer to hand back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The upstream could not be reached, or answered 5xx, on a step whose failure says nothing
    /// about its revision. The last answer, if any, is carried.
    Unreachable(Option<HopAnswer>),
    /// The upstream's `initialize` answer named a revision this plane cannot carry; the spec's rule
    /// is to disconnect.
    OfferedUnsupported,
}

/// The next thing the driver does.
#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    /// POST `request`, then call [`Negotiator::on_answer`].
    Send {
        /// The request.
        request: OutboundRequest,
    },
    /// Carry the call over the `2024-11-05` event stream.
    OpenStream,
    /// The answer to hand back.
    Finish(HopAnswer),
    /// Stop.
    Fail(Refusal),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    Probe,
    Initialize,
    Initialized {
        revision: Revision,
        session: Option<String>,
    },
    InSession {
        revision: Revision,
        session: Option<String>,
    },
    Done,
}

/// ONE CALL'S NEGOTIATION. See the module header for the driver's side.
#[derive(Debug)]
pub struct Negotiator {
    original: OutboundRequest,
    original_id: Option<Value>,
    client_version: String,
    phase: Phase,
    remembered: Option<Remembered>,
    reinitialized: bool,
    /// The id a request lowered into the REMEMBERED session carries ([`Self::with_session_id`]):
    /// the session's own next id, so no id repeats within one session.
    session_id: Option<u64>,
    /// The id the request sent in a session actually carried, when it is not the original's.
    sent_id: Option<u64>,
}

impl Negotiator {
    /// Carries `original` (a stateless request) to its upstream, starting from what busbar
    /// `remembered` about that upstream. `client_version` names busbar in `initialize`.
    #[must_use]
    pub fn new(
        original: OutboundRequest,
        remembered: Option<Remembered>,
        client_version: &str,
    ) -> Self {
        let original_id = serde_json::from_slice::<Value>(&original.body)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .filter(|v| !v.is_null());
        Self {
            original,
            original_id,
            client_version: client_version.to_string(),
            phase: Phase::Probe,
            remembered,
            reinitialized: false,
            session_id: None,
            sent_id: None,
        }
    }

    /// The id a request lowered into the remembered session carries: that session's next id
    /// (`UpstreamTable::next_id`), never the stateless round's. `None`: the original's id.
    #[must_use]
    pub fn with_session_id(mut self, id: Option<u64>) -> Self {
        self.session_id = id;
        self
    }

    /// The stateless request this negotiation carries.
    #[must_use]
    pub fn original(&self) -> &OutboundRequest {
        &self.original
    }

    /// The id the request this negotiation sent in a session carried, when it is not the
    /// original's: the id its answer is correlated by.
    #[must_use]
    pub fn sent_id(&self) -> Option<u64> {
        self.sent_id
    }

    /// What to keep for the next call to this upstream: the negotiated revision and, on a
    /// session revision, its session. `None` means forget (nothing was learnt, or it was lost).
    #[must_use]
    pub fn remembered(&self) -> Option<Remembered> {
        self.remembered.clone()
    }

    /// The first action.
    pub fn start(&mut self) -> Action {
        match self.remembered.clone() {
            None => self.send(Phase::Probe, self.original.clone()),
            Some(r) if r.revision == Revision::R2026_07_28 => {
                self.send(Phase::Probe, self.original.clone())
            }
            Some(r) if r.revision.is_event_stream_revision() => self.open_stream(),
            Some(r) => self.in_session(r.revision, r.session),
        }
    }

    fn send(&mut self, phase: Phase, request: OutboundRequest) -> Action {
        self.phase = phase;
        Action::Send { request }
    }

    fn in_session(&mut self, revision: Revision, session: Option<String>) -> Action {
        let url = self.original.url.clone();
        let mut request = lower_request(&self.original, &url, revision, session.as_deref());
        // A REQUEST IN A SESSION CARRIES THAT SESSION'S OWN NEXT ID, never the stateless round's
        // that every concurrent call carries: a session revision forbids reusing an id, and a server
        // that maps ids to answers would hand one call's answer to another.
        if let (Some(id), Some(_)) = (self.session_id, self.original_id.as_ref()) {
            if let Ok(mut body) = serde_json::from_slice::<Value>(&request.body) {
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("id".to_string(), Value::from(id));
                    if let Ok(bytes) = serde_json::to_vec(&body) {
                        request.body = bytes;
                        self.sent_id = Some(id);
                    }
                }
            }
        }
        self.send(Phase::InSession { revision, session }, request)
    }

    fn initialize(&mut self) -> Action {
        let request = initialize_request(
            &self.original,
            &self.original.url,
            revision::SESSION_REVISIONS[0],
            &self.client_version,
        );
        self.send(Phase::Initialize, request)
    }

    fn open_stream(&mut self) -> Action {
        self.phase = Phase::Done;
        Action::OpenStream
    }

    fn finish(&mut self, answer: HopAnswer) -> Action {
        self.phase = Phase::Done;
        Action::Finish(answer)
    }

    fn fail(&mut self, refusal: Refusal) -> Action {
        self.phase = Phase::Done;
        Action::Fail(refusal)
    }

    /// Feeds the answer to the last [`Action::Send`]; `None` when there was no answer at all.
    pub fn on_answer(&mut self, answer: Option<HopAnswer>) -> Action {
        let Some(answer) = answer else {
            return self.fail(Refusal::Unreachable(None));
        };
        match self.phase.clone() {
            Phase::Probe => match stateless_outcome(answer.status, &answer.body) {
                StepOutcome::Answered => {
                    self.remembered = Some(Remembered {
                        revision: Revision::R2026_07_28,
                        session: None,
                    });
                    self.finish(answer)
                }
                StepOutcome::Unreachable => self.fail(Refusal::Unreachable(Some(answer))),
                StepOutcome::Refused4xx => {
                    // A remembered stateless upstream that now refuses is renegotiated once.
                    self.remembered = None;
                    self.initialize()
                }
            },
            Phase::Initialize => {
                if answer.ok() {
                    if let Some(r) = offered_revision(&answer.body) {
                        if r.is_event_stream_revision() {
                            return self.fail(Refusal::OfferedUnsupported);
                        }
                        let session = answer.field(crate::adapt::H_SESSION_ID).map(str::to_string);
                        let url = self.original.url.clone();
                        let request =
                            initialized_notification(&self.original, &url, r, session.as_deref());
                        return self.send(
                            Phase::Initialized {
                                revision: r,
                                session,
                            },
                            request,
                        );
                    }
                }
                match probe_outcome(answer.status, &answer.body) {
                    StepOutcome::Unreachable => self.fail(Refusal::Unreachable(Some(answer))),
                    StepOutcome::Refused4xx => self.open_stream(),
                    StepOutcome::Answered => self.fail(Refusal::OfferedUnsupported),
                }
            }
            Phase::Initialized { revision, session } => {
                if !answer.ok() {
                    return self.fail(Refusal::Unreachable(Some(answer)));
                }
                self.remembered = Some(Remembered {
                    revision,
                    session: session.clone(),
                });
                self.in_session(revision, session)
            }
            Phase::InSession { session, .. } => {
                if answer.status == 404 && session.is_some() && !self.reinitialized {
                    // The upstream's session is gone (ended, expired, or another replica): the
                    // spec's recovery is a fresh `initialize`, once.
                    self.reinitialized = true;
                    self.remembered = None;
                    return self.initialize();
                }
                self.finish(answer)
            }
            Phase::Done => Action::OpenStream,
        }
    }
}

#[cfg(test)]
#[path = "tests/negotiate_tests.rs"]
mod tests;
