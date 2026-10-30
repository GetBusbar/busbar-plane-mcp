// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEP-2663 — THE TASKS EXTENSION on the MCP door, pure: the task's state, its two wire shapes, its
//! lifecycle transitions, the retention sweep and the durable rows a task is kept in (the served
//! engine's `tasks.rs`, ported; the door half that runs a task is `door_tasks`).
//!
//! A `tools/call` on a tool whose operator declared `task_support`, from a caller that declared the
//! extension, is answered with a `CreateTaskResult`; the caller polls `tasks/get` until the task is
//! terminal, the result INLINED. `tasks/update` delivers input; `tasks/cancel` stops it. There is no
//! `tasks/result` and no `tasks/list` (the v2 wire removed both).
//!
//! A tool that RAN and reported a failure is `completed` with `result.isError: true`; `failed` is a
//! PROTOCOL-level error, inlining `error` and never `result`.
//!
//! THE TASK STORE IS HOST RECORDS: the handle is the kernel's; a live task's state and a terminal
//! task's result are written to the plane's records in chunks, so the verbs answer from any node and
//! across a restart. Every live task is indexed under its caller with its run's LEASE
//! ([`TaskLease`]), so the handles a gone process left behind are settled, never exhausting the bound
//! of live work.

use std::collections::BTreeMap;

use busbar_contract::abi::mechanism::ticket::Ticket;
use serde_json::{json, Map, Value};

use crate::ask::CallerAsk;

/// How long a task stays readable through `tasks/get` after it settles (the `ttlMs` every task
/// shape states): the work handles' retention, which the plane's `work: {retain_s}` bounds and
/// whose default is this.
///
/// A POSITIVE value, unlike the catalogue's `ttlMs: 0`, and the difference is not an
/// inconsistency: the catalogue's zero says "this answer may already be stale", a claim about
/// freshness; this one says "the server keeps this row for at least this long", a claim about
/// RETENTION.
pub const TASK_TTL_MS: u64 = 300_000;

/// The poll cadence busbar suggests. Advisory — a client that polls faster is not refused.
pub const TASK_POLL_INTERVAL_MS: u64 = 250;

/// The ceiling on tasks the instance keeps in hand at once: the work handles' live bound, whose
/// default is this. The oldest TERMINAL tasks are dropped first, and a working task is never
/// dropped to make room.
pub const MAX_RETAINED_TASKS: usize = 4096;

/// The ABANDONMENT ceiling on an ACTIVE task: one whose last update is older than this is treated
/// as abandoned by its caller and cancelled (a transition, never a drop), after which the ordinary
/// retention applies. A full day: an `input_required` park waiting on a human legitimately sits
/// for hours, but not for days. Enforced by the create-time sweep (no timer to schedule or leak).
pub const ACTIVE_TASK_ABANDON_MS: u64 = 86_400_000;

/// THE CEILING ON DISTINCT ANSWER KEYS one task retains: `tasks/update` delivers `inputResponses`
/// under keys of the caller's own choosing, so without a ceiling a caller parked in
/// `input_required` could grow one task's map without bound.
pub const MAX_TASK_ANSWERS: usize = 256;

/// The JSON-RPC code a `failed` task inlines: `-32603` (internal error), because what is reported
/// is that busbar could not carry the dispatch to an answer, and the caller has no parameter to
/// correct.
pub const TASK_PROTOCOL_ERROR_CODE: i64 = -32603;

/// How long the continuation's one-time run claim stands: past any live task's abandonment and its
/// retention after, so a task cannot be run twice while its handle can still be found.
pub const RUN_CLAIM_TTL_MS: u64 = ACTIVE_TASK_ABANDON_MS + TASK_TTL_MS;

/// How long the state a task's relayed ask is answered under stands, in seconds: as long as the task
/// may stay parked on its caller ([`ACTIVE_TASK_ABANDON_MS`]), a human's answer included.
pub const TASK_RELAY_TTL_SECS: u64 = ACTIVE_TASK_ABANDON_MS / 1000;

/// The bytes of one result chunk: a plane record holds at most
/// [`busbar_contract::bounded::MAX_RECORD_BYTES`].
pub const RESULT_CHUNK_BYTES: usize = 480;

/// The most chunks one task's result (or its live state) is written in: what one answer's record
/// writes hold (`busbar_contract::abi::plane::check::MAX_RECORDS`, 1024) with the strikes of the
/// state it replaces beside it. The task store is host records: a
/// result longer than this settles the task `failed` in words ([`kept_bytes`]), and a live state
/// longer than this is refused where it would be made; neither is held only in hand.
pub const MAX_RESULT_CHUNKS: usize = 480;

/// Plane records of the task kind, `(key, value)`, in key order.
pub type Records = Vec<(Vec<u8>, Vec<u8>)>;

/// The most bytes a task keeps in the host's records, its result or its live state.
#[must_use]
pub const fn kept_bytes() -> usize {
    RESULT_CHUNK_BYTES * MAX_RESULT_CHUNKS
}

/// THE RUN'S LEASE beyond its server's own `timeout:`: how long a task's run may go unheard from
/// before another process takes its handle as left behind (the process running it gone) and settles
/// it `cancelled`. Taken when the continuation is nested and renewed as each call goes out.
pub const RUN_LEASE_MS: u64 = 300_000;

/// The live-state chunks a settle strikes at the least: what a process that did not write a task's
/// live state strikes of it.
pub const LIVE_STRIKES: u32 = 4;

/// A task's lifecycle state, as the wire spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Running.
    Working,
    /// Parked on input busbar asked its caller for. `tasks/update` is what un-parks it.
    InputRequired,
    /// The tool RAN. Whether it reported success or an error of its own is in `result.isError`.
    Completed,
    /// A PROTOCOL-level failure. Carries `error`, never `result`.
    Failed,
    /// Cancelled by `tasks/cancel` (or abandoned, or the continuation stopped with it running).
    Cancelled,
}

impl Status {
    /// The wire token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Status::Working => "working",
            Status::InputRequired => "input_required",
            Status::Completed => "completed",
            Status::Failed => "failed",
            Status::Cancelled => "cancelled",
        }
    }

    /// The status a token names.
    #[must_use]
    pub fn of_token(token: &str) -> Option<Self> {
        [
            Status::Working,
            Status::InputRequired,
            Status::Completed,
            Status::Failed,
            Status::Cancelled,
        ]
        .into_iter()
        .find(|s| s.token() == token)
    }

    /// Terminal states are the three a task never leaves. `tasks/cancel` on one of them is an
    /// idempotent no-op rather than an error.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(self, Status::Completed | Status::Failed | Status::Cancelled)
    }
}

/// ONE MCP task, as the instance holds it.
#[derive(Clone, Debug, PartialEq)]
pub struct Task {
    /// The `taskId`: the work handle's reference.
    pub id: String,
    /// The principal it was created for. A caller may only ever address its own tasks, and an id
    /// belonging to somebody else is answered as UNKNOWN rather than as forbidden.
    principal: String,
    /// The work handle (process-local) the reference was opened or found as.
    pub handle: u64,
    /// The digest of the call it runs ([`run_digest`]), as its durable row states it.
    digest: String,
    status: Status,
    /// Unix milliseconds, from the kernel's one clock. Rendered ISO-8601 on the wire.
    created_ms: u64,
    updated_ms: u64,
    /// The inlined tool result, present only on `completed`.
    result: Option<Value>,
    /// The inlined protocol error, present only on `failed`.
    error: Option<Value>,
    /// The still-unanswered asks of the current round, in the operator's own order. Answering a key
    /// REMOVES it, which is what makes partial fulfilment observable.
    input_requests: Vec<(String, Value)>,
    /// Everything the caller has answered so far, keyed as the operator keyed the ask.
    answers: Map<String, Value>,
    /// The continuation took the run: the local half of its one-time start.
    pub started: bool,
    /// The continuation's unit and the ticket it is woken on, while it runs.
    pub runner: Option<(u64, Ticket)>,
    /// The terminal state was reached in hand and the durable handle not yet settled with it.
    pub unsettled: bool,
    /// How many result chunks were written for it.
    pub chunks: u32,
    /// The upstream's ask it is parked on, relayed: answered through `tasks/update` and
    /// carried back to the member that asked, never merged into the tool's arguments.
    relay: Option<RelayPark>,
    /// THE ROUND OF ITS OWN ASKS IT IS PARKED ON, and the call its run resumes with: the
    /// continuation ended with the handle live, and the `tasks/update` that answers the round
    /// nests the resume.
    pub asked: Option<(usize, Value)>,
    /// THE ROUND A `tasks/update` ANSWERED and nested the resume of: the one resume this instance
    /// runs, taken once. A `resume` no update nested (the task-run claim is a credentialed route)
    /// finds none, so it can neither skip the operator's rounds nor run the call again.
    resumed: Option<usize>,
    /// How many live-state chunks this instance wrote for it.
    pub live_chunks: u32,
}

/// A TASK PARKED ON ITS UPSTREAM'S ASK: busbar's sealed state (bound to the principal, the tool and
/// the member, nesting the upstream's own), the call the retry runs, the upstream's keys and the
/// caller's answers to them so far.
#[derive(Clone, Debug, PartialEq)]
pub struct RelayPark {
    /// Busbar's sealed state the retry presents.
    pub state: String,
    /// The call the continuation runs (its digest is the task's).
    pub params: Value,
    /// The upstream's `inputRequests` keys, in its order.
    keys: Vec<String>,
    /// The caller's answers, by the upstream's keys.
    pub responses: Map<String, Value>,
}

impl Task {
    /// A working task `id` for `principal`, on work handle `handle`, running the call `digest`
    /// names, created at `now_ms`.
    #[must_use]
    pub fn new(id: &str, principal: &str, handle: u64, digest: &str, now_ms: u64) -> Self {
        Task {
            id: id.to_string(),
            principal: principal.to_string(),
            handle,
            digest: digest.to_string(),
            status: Status::Working,
            created_ms: now_ms,
            updated_ms: now_ms,
            result: None,
            error: None,
            input_requests: Vec::new(),
            answers: Map::new(),
            started: false,
            runner: None,
            unsettled: false,
            chunks: 0,
            relay: None,
            asked: None,
            resumed: None,
            live_chunks: 0,
        }
    }

    /// A task read back from its durable row (`row`) and, for a terminal one, its result
    /// (`terminal`: `{"result": …}` or `{"error": …}`).
    #[must_use]
    pub fn from_row(
        id: &str,
        principal: &str,
        handle: u64,
        row: &WorkRow,
        terminal: Option<&Value>,
    ) -> Self {
        let mut task = Task::new(id, principal, handle, &row.digest, row.created_ms);
        task.status = row.status;
        task.updated_ms = row.updated_ms;
        task.started = true;
        if let Some(t) = terminal {
            task.result = t.get("result").cloned();
            task.error = t.get("error").cloned();
        }
        task
    }

    /// Whether `principal` may address this task.
    #[must_use]
    pub fn owned_by(&self, principal: &str) -> bool {
        self.principal == principal
    }

    /// The key of its index row ([`TaskLease`]) in the plane's records.
    #[must_use]
    pub fn index_key(&self) -> Vec<u8> {
        index_key(&self.principal, &self.id)
    }

    /// THE LIVE STATE its records keep ([`live_parts`]): its status and last update, its
    /// `inputRequests` in order, the answers it holds, the upstream ask and the round of its own
    /// asks it is parked on.
    #[must_use]
    pub fn live(&self) -> Value {
        let requests: Vec<Value> = self
            .input_requests
            .iter()
            .map(|(k, v)| json!([k, v]))
            .collect();
        json!({
            "status": self.status.token(),
            "updated": self.updated_ms,
            "requests": requests,
            "answers": self.answers,
            "relay": self.relay.as_ref().map(|p| json!({
                "state": p.state,
                "params": p.params,
                "keys": p.keys,
                "responses": p.responses,
            })),
            "asked": self.asked.as_ref().map(|(round, params)| json!([round, params])),
        })
    }

    /// The live state its records hold ([`Task::live`]'s document), laid over a task read from its
    /// row; a document that is not one leaves it as it is.
    pub fn take_live(&mut self, live: &Value) {
        let (Some(status), Some(updated)) = (
            live.get("status")
                .and_then(Value::as_str)
                .and_then(Status::of_token),
            live.get("updated").and_then(Value::as_u64),
        ) else {
            return;
        };
        self.status = status;
        self.updated_ms = updated;
        self.input_requests = live
            .get("requests")
            .and_then(Value::as_array)
            .map(|pairs| {
                pairs
                    .iter()
                    .filter_map(|p| {
                        let pair = p.as_array()?;
                        Some((pair.first()?.as_str()?.to_string(), pair.get(1)?.clone()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.answers = live
            .get("answers")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        self.relay = live.get("relay").and_then(|r| {
            Some(RelayPark {
                state: r.get("state")?.as_str()?.to_string(),
                params: r.get("params")?.clone(),
                keys: r
                    .get("keys")?
                    .as_array()?
                    .iter()
                    .filter_map(|k| k.as_str().map(str::to_string))
                    .collect(),
                responses: r.get("responses")?.as_object()?.clone(),
            })
        });
        self.asked = live.get("asked").and_then(|a| {
            let pair = a.as_array()?;
            Some((
                usize::try_from(pair.first()?.as_u64()?).ok()?,
                pair.get(1)?.clone(),
            ))
        });
    }

    /// THE HOST'S WORD over what the instance holds of this task: `host` (read from its rows and
    /// records) replaces it, the instance keeping only its own halves — the run taken here, the unit
    /// running it, a settle still owed, the chunks it wrote.
    pub fn hosted(&mut self, host: Task) {
        let kept = (
            self.started,
            self.runner,
            self.unsettled,
            self.chunks,
            self.live_chunks,
            self.resumed,
        );
        *self = host;
        (
            self.started,
            self.runner,
            self.unsettled,
            self.chunks,
            self.live_chunks,
            self.resumed,
        ) = kept;
    }

    /// THE ROUND OF ITS OWN ASKS A `tasks/update` ANSWERED, taken: the round and the call the resume
    /// it nests runs with. The round is remembered as the one resume this instance will run.
    pub fn answer_round(&mut self) -> Option<(usize, Value)> {
        let answered = self.asked.take();
        if let Some((round, _)) = &answered {
            self.resumed = Some(*round);
        }
        answered
    }

    /// Whether the continuation resuming at `round` for `principal` may run it: the task is that
    /// caller's and working, and `round` is the one a `tasks/update` answered and nested, taken
    /// here once.
    pub fn take_resume(&mut self, principal: &str, round: usize) -> bool {
        let runs = self.owned_by(principal)
            && self.status == Status::Working
            && self.resumed == Some(round);
        if runs {
            self.resumed = None;
        }
        runs
    }

    /// Its status.
    #[must_use]
    pub fn status(&self) -> Status {
        self.status
    }

    /// When it was created and last updated (Unix ms).
    #[must_use]
    pub fn stamps(&self) -> (u64, u64) {
        (self.created_ms, self.updated_ms)
    }

    /// The `DetailedTask` a `tasks/get` answers with, minus the `resultType` the response builder
    /// stamps. `requestState` is ABSENT and its absence is load-bearing: SEP-2663 removed it from
    /// the v2 wire.
    #[must_use]
    pub fn detailed(&self) -> Value {
        let mut obj = self.shape();
        if let Some(result) = &self.result {
            obj.insert("result".into(), result.clone());
        }
        if let Some(error) = &self.error {
            obj.insert("error".into(), error.clone());
        }
        if !self.input_requests.is_empty() {
            let map: Map<String, Value> = self.input_requests.iter().cloned().collect();
            obj.insert("inputRequests".into(), Value::Object(map));
        }
        Value::Object(obj)
    }

    /// The `CreateTaskResult` a `tools/call` answers with — a FLAT `Result & Task` intersection,
    /// carrying none of `result`, `error` or `inputRequests` (those are `tasks/get`'s), and an
    /// EMPTY `content`: the base revision's `CallToolResult` makes `content` required.
    #[must_use]
    pub fn created(&self) -> Value {
        let mut obj = self.shape();
        obj.insert("content".into(), json!([]));
        Value::Object(obj)
    }

    /// The fields both task shapes carry.
    fn shape(&self) -> Map<String, Value> {
        [
            ("taskId", json!(self.id)),
            ("status", json!(self.status.token())),
            ("createdAt", json!(iso8601_ms(self.created_ms))),
            ("lastUpdatedAt", json!(iso8601_ms(self.updated_ms))),
            ("ttlMs", json!(TASK_TTL_MS)),
            ("pollIntervalMs", json!(TASK_POLL_INTERVAL_MS)),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// PARK on a round of asks. Any ask already answered by an earlier `tasks/update` is not
    /// re-asked; a round with nothing left to ask leaves the status alone.
    pub fn park(&mut self, asks: Vec<CallerAsk>, now_ms: u64) {
        if self.status.is_terminal() {
            return;
        }
        self.input_requests = asks
            .into_iter()
            .filter(|a| !self.answers.contains_key(a.key()))
            .map(|a| {
                (
                    a.key().to_string(),
                    json!({ "method": a.method(), "params": a.params() }),
                )
            })
            .collect();
        if !self.input_requests.is_empty() {
            self.status = Status::InputRequired;
            self.updated_ms = now_ms;
        }
    }

    /// Park on the upstream's ask, relayed to the caller: `input_required`, its
    /// `inputRequests` the upstream's own, verbatim and in its order, under busbar's sealed `state`;
    /// the retry runs `params`. A terminal task does not park.
    pub fn park_relay(
        &mut self,
        requests: &Map<String, Value>,
        state: String,
        params: Value,
        now_ms: u64,
    ) {
        if self.status.is_terminal() {
            return;
        }
        self.input_requests = requests
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.relay = Some(RelayPark {
            state,
            params,
            keys: requests.keys().cloned().collect(),
            responses: Map::new(),
        });
        self.status = Status::InputRequired;
        self.updated_ms = now_ms;
    }

    /// THE RELAYED ASK, ANSWERED: taken once every key the upstream asked is answered (the retry
    /// goes to the member with the caller's answers), `None` before, and `None` to any later caller.
    pub fn take_relay(&mut self) -> Option<RelayPark> {
        let park = self.relay.as_ref()?;
        if park.keys.iter().any(|k| !park.responses.contains_key(k)) {
            return None;
        }
        self.relay.take()
    }

    /// Deliver `inputResponses`. Keys the task is not waiting on are IGNORED rather than refused:
    /// only a key the current round asked is kept (an answer may only
    /// supply what was asked for, as the synchronous call's rule says). On a task parked on its
    /// upstream's ask the answers are the upstream's: kept for the retry, never merged into the
    /// tool's arguments.
    ///
    /// Returns `false`, applying NOTHING, when this batch would grow the task's answer map past
    /// [`MAX_TASK_ANSWERS`] DISTINCT keys — refused whole, never truncated. A key already held is a
    /// REPEAT, not new, so re-answering one never counts against the ceiling.
    ///
    /// A TERMINAL task takes no input: the update is acknowledged and changes nothing.
    pub fn deliver(&mut self, responses: &Map<String, Value>, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return true;
        }
        if let Some(park) = self.relay.as_mut() {
            for (key, value) in responses {
                if park.keys.contains(key) {
                    park.responses.insert(key.clone(), value.clone());
                }
            }
        } else {
            let asked: Vec<(&String, &Value)> = responses
                .iter()
                .filter(|(k, _)| self.input_requests.iter().any(|(r, _)| r == *k))
                .collect();
            let new_keys = asked
                .iter()
                .filter(|(k, _)| !self.answers.contains_key(k.as_str()))
                .count();
            if self.answers.len() + new_keys > MAX_TASK_ANSWERS {
                return false;
            }
            for (key, value) in asked {
                self.answers.insert(key.clone(), value.clone());
            }
        }
        self.input_requests
            .retain(|(k, _)| !responses.contains_key(k));
        self.updated_ms = now_ms;
        if self.input_requests.is_empty() && self.status == Status::InputRequired {
            self.status = Status::Working;
        }
        true
    }

    /// Whether every ask of the current round is answered (or the task left `input_required` some
    /// other way).
    #[must_use]
    pub fn answered(&self) -> bool {
        self.input_requests.is_empty() || self.status.is_terminal()
    }

    /// The answers gathered so far, to merge into the tool arguments.
    #[must_use]
    pub fn answers(&self) -> &Map<String, Value> {
        &self.answers
    }

    /// Back to `working` (the asks are answered), unless terminal.
    pub fn set_working(&mut self, now_ms: u64) {
        if !self.status.is_terminal() {
            self.status = Status::Working;
            self.updated_ms = now_ms;
        }
    }

    /// The tool RAN. `result` is its own answer, `isError` and all. Whether this call made the
    /// transition.
    pub fn complete(&mut self, result: Value, now_ms: u64) -> bool {
        let moved = self.end(Status::Completed, now_ms);
        if moved {
            self.result = Some(result);
        }
        moved
    }

    /// A PROTOCOL-level failure: `error` only, never a `result` beside it. Whether this call made
    /// the transition.
    pub fn fail(&mut self, code: i64, message: String, now_ms: u64) -> bool {
        let moved = self.end(Status::Failed, now_ms);
        if moved {
            self.error = Some(json!({ "code": code, "message": message }));
            self.result = None;
        }
        moved
    }

    /// CANCEL. Idempotent on a terminal task, which is the whole of the `tasks/cancel` contract.
    /// Whether THIS call performed the terminal transition.
    pub fn cancel(&mut self, now_ms: u64) -> bool {
        self.end(Status::Cancelled, now_ms)
    }

    /// The move to the terminal `status` at `now_ms`, its asks dropped; whether it made it.
    fn end(&mut self, status: Status, now_ms: u64) -> bool {
        if self.status.is_terminal() {
            return false;
        }
        self.status = status;
        self.input_requests.clear();
        self.relay = None;
        self.updated_ms = now_ms;
        true
    }

    /// A terminal task past its retention.
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool {
        self.status.is_terminal() && now_ms.saturating_sub(self.updated_ms) > TASK_TTL_MS
    }

    /// An ACTIVE task nothing has touched for longer than [`ACTIVE_TASK_ABANDON_MS`].
    #[must_use]
    pub fn is_abandoned(&self, now_ms: u64) -> bool {
        !self.status.is_terminal()
            && now_ms.saturating_sub(self.updated_ms) > ACTIVE_TASK_ABANDON_MS
    }

    /// The task's durable row as it now stands.
    #[must_use]
    pub fn row(&self) -> Vec<u8> {
        WorkRow {
            status: self.status,
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
            digest: self.digest.clone(),
        }
        .bytes()
    }

    /// The terminal value its result chunks carry: `{"result": …}` or `{"error": …}`; `None` for a
    /// task with neither (working, input-required, cancelled).
    #[must_use]
    pub fn terminal(&self) -> Option<Value> {
        match (&self.result, &self.error) {
            (Some(r), _) => Some(json!({ "result": r })),
            (None, Some(e)) => Some(json!({ "error": e })),
            (None, None) => None,
        }
    }
}

/// What one sweep did: the continuations to wake (each saw its task cancelled), the tasks whose
/// handles must be settled with the state they hold, and the result chunks to strike.
#[derive(Debug, Default, PartialEq)]
pub struct Swept {
    /// The tickets of continuations whose task the sweep cancelled.
    pub wake: Vec<Ticket>,
    /// `(handle, task)` of every task that reached its terminal state in hand and is not settled.
    pub settle: Vec<(u64, Task)>,
    /// `(taskId, chunks)` of every dropped task that wrote a result.
    pub strike: Vec<(String, u32)>,
}

/// THE SWEEP, run when a task is created: an ACTIVE task past the abandonment ceiling is first
/// CANCELLED (a transition, never a drop); expired terminal tasks are dropped; and only if that was
/// not enough, the oldest terminal tasks. Never a working one.
pub fn sweep(tasks: &mut BTreeMap<String, Task>, now_ms: u64) -> Swept {
    let mut swept = Swept::default();
    for task in tasks.values_mut() {
        if task.is_abandoned(now_ms) && task.cancel(now_ms) {
            task.unsettled = true;
            if let Some((_, ticket)) = task.runner {
                swept.wake.push(ticket);
            }
        }
        if task.unsettled {
            task.unsettled = false;
            swept.settle.push((task.handle, task.clone()));
        }
    }
    let gone = |t: &Task, swept: &mut Swept| {
        if t.chunks > 0 {
            swept.strike.push((t.id.clone(), t.chunks));
        }
    };
    tasks.retain(|_, t| {
        let keep = !t.is_expired(now_ms);
        if !keep {
            gone(t, &mut swept);
        }
        keep
    });
    if tasks.len() < MAX_RETAINED_TASKS {
        return swept;
    }
    let mut terminal: Vec<(u64, String)> = tasks
        .iter()
        .filter(|(_, t)| t.status.is_terminal())
        .map(|(id, t)| (t.updated_ms, id.clone()))
        .collect();
    terminal.sort_unstable();
    for (_, id) in terminal
        .into_iter()
        .take(tasks.len().saturating_sub(MAX_RETAINED_TASKS) + 1)
    {
        if let Some(t) = tasks.remove(&id) {
            gone(&t, &mut swept);
        }
    }
    swept
}

/// A task's DURABLE ROW, the work handle's record (at most `MAX_WORK_RECORD` bytes): its status,
/// its two stamps, and the digest of the call it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkRow {
    /// Its status.
    pub status: Status,
    /// When it was created (Unix ms).
    pub created_ms: u64,
    /// When it was last updated (Unix ms).
    pub updated_ms: u64,
    /// The digest of the continuation's call ([`run_digest`]).
    pub digest: String,
}

/// The row's version word.
const ROW_V1: &str = "t1";

impl WorkRow {
    /// The row's bytes: `t1|<status>|<created>|<updated>|<digest>`.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!(
            "{ROW_V1}|{}|{}|{}|{}",
            self.status.token(),
            self.created_ms,
            self.updated_ms,
            self.digest
        )
        .into_bytes()
    }

    /// A row read back; `None` for bytes that are not one.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let [status, created, updated, digest] = fields(bytes, ROW_V1)?;
        Some(WorkRow {
            status: Status::of_token(status)?,
            created_ms: created.parse().ok()?,
            updated_ms: updated.parse().ok()?,
            digest: digest.to_string(),
        })
    }
}

/// THE DIGEST of the call a continuation runs (the published name, the arguments as admitted and the
/// caller's `_meta`): written in the handle's row by the creating unit, compared by the
/// continuation against the call its arrival carries, so the run is the call that was admitted.
#[must_use]
pub fn run_digest(params: &Value) -> String {
    busbar_contract::redacted::sha256_hex(&serde_json::to_vec(params).unwrap_or_default())
}

/// The key of chunk `n` of task `id`'s result: ordered, so a listing reads them back in order.
#[must_use]
pub fn chunk_key(id: &str, n: u32) -> Vec<u8> {
    format!("{id}/{n:04}").into_bytes()
}

/// The prefix every chunk of task `id`'s result is keyed under.
#[must_use]
pub fn chunk_prefix(id: &str) -> Vec<u8> {
    format!("{id}/").into_bytes()
}

/// THE RESULT, IN CHUNKS: the terminal value's bytes cut into plane records of at most
/// [`RESULT_CHUNK_BYTES`]; `Err` its length in bytes when it would take more than
/// [`MAX_RESULT_CHUNKS`].
///
/// # Errors
///
/// The value's length, when the host's records do not keep it.
pub fn result_chunks(id: &str, terminal: &Value) -> Result<Records, usize> {
    chunked(|n| chunk_key(id, n), terminal)
}

/// `value`'s bytes cut into plane records of at most [`RESULT_CHUNK_BYTES`], keyed `key(n)`; `Err`
/// its length in bytes when it would take more than [`MAX_RESULT_CHUNKS`].
fn chunked(key: impl Fn(u32) -> Vec<u8>, value: &Value) -> Result<Records, usize> {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let chunks: Vec<&[u8]> = bytes.chunks(RESULT_CHUNK_BYTES).collect();
    if chunks.len() > MAX_RESULT_CHUNKS {
        return Err(bytes.len());
    }
    Ok((0u32..)
        .zip(chunks)
        .map(|(n, c)| (key(n), c.to_vec()))
        .collect())
}

/// The key of chunk `n` of task `id`'s live state: ordered, apart from its result's.
#[must_use]
pub fn live_key(id: &str, n: u32) -> Vec<u8> {
    format!("{id}~/{n:04}").into_bytes()
}

/// The prefix every chunk of task `id`'s live state is keyed under.
#[must_use]
pub fn live_prefix(id: &str) -> Vec<u8> {
    format!("{id}~/").into_bytes()
}

/// THE LIVE STATE, IN CHUNKS ([`Task::live`]), as [`result_chunks`] cuts a result.
///
/// # Errors
///
/// The state's length, when the host's records do not keep it.
pub fn live_parts(id: &str, live: &Value) -> Result<Records, usize> {
    chunked(|n| live_key(id, n), live)
}

/// The live state read back from its chunks' bytes, in key order: the first document they hold (an
/// earlier, longer state's chunks past it are not read); `None` when they hold none.
#[must_use]
pub fn read_live(bytes: &[u8]) -> Option<Value> {
    serde_json::Deserializer::from_slice(bytes)
        .into_iter::<Value>()
        .next()?
        .ok()
}

/// The prefix `principal`'s index rows are keyed under: a digest of the principal, never the
/// principal itself.
#[must_use]
pub fn index_prefix(principal: &str) -> Vec<u8> {
    let owner = busbar_contract::redacted::sha256_hex(principal.as_bytes());
    format!("o/{}/", &owner[..32]).into_bytes()
}

/// The key of task `id`'s index row under `principal`.
#[must_use]
pub fn index_key(principal: &str, id: &str) -> Vec<u8> {
    let mut key = index_prefix(principal);
    key.extend_from_slice(id.as_bytes());
    key
}

/// A LIVE TASK'S INDEX ROW: until when a run holds it, and when it last moved. What a create reads
/// to find the tasks of its caller a process that is gone left behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskLease {
    /// Until when its run holds it (Unix ms); `0`: no run does (it is parked on its caller).
    pub until_ms: u64,
    /// When it last moved (Unix ms).
    pub updated_ms: u64,
}

/// The index row's version word.
const LEASE_V1: &str = "l1";

impl TaskLease {
    /// The row's bytes: `l1|<until>|<updated>`.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!("{LEASE_V1}|{}|{}", self.until_ms, self.updated_ms).into_bytes()
    }

    /// A row read back; `None` for bytes that are not one.
    #[must_use]
    pub fn read(bytes: &[u8]) -> Option<Self> {
        let [until, updated] = fields(bytes, LEASE_V1)?;
        Some(TaskLease {
            until_ms: until.parse().ok()?,
            updated_ms: updated.parse().ok()?,
        })
    }

    /// Whether the task it indexes is LEFT BEHIND at `now_ms`: its run's lease lapsed (the process
    /// running it is gone), or nothing moved it past [`ACTIVE_TASK_ABANDON_MS`].
    #[must_use]
    pub fn left_behind(&self, now_ms: u64) -> bool {
        (self.until_ms != 0 && now_ms > self.until_ms)
            || now_ms.saturating_sub(self.updated_ms) > ACTIVE_TASK_ABANDON_MS
    }
}

/// The `N` `|`-separated fields of a row whose version word is `version`; `None` for bytes that are
/// not one.
fn fields<'a, const N: usize>(bytes: &'a [u8], version: &str) -> Option<[&'a str; N]> {
    let mut parts = std::str::from_utf8(bytes).ok()?.split('|');
    if parts.next()? != version {
        return None;
    }
    parts.collect::<Vec<_>>().try_into().ok()
}

/// The terminal value read back from its chunks (in key order); `None` when they do not make one.
#[must_use]
pub fn read_chunks<'a>(chunks: impl Iterator<Item = &'a [u8]>) -> Option<Value> {
    let bytes: Vec<u8> = chunks.flatten().copied().collect();
    if bytes.is_empty() {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

/// The arguments a continuation calls with: the admitted arguments, with the caller's gathered ask
/// answers merged in under the operator's own keys, and NEVER over an argument the call was
/// admitted with (the hooks and the argument guard judged the admitted arguments; an answer may
/// never rewrite one). A clone, never a mutation.
#[must_use]
pub fn merge_answers(arguments: &Value, answers: &Map<String, Value>) -> Value {
    if answers.is_empty() {
        return arguments.clone();
    }
    let mut merged = arguments.as_object().cloned().unwrap_or_default();
    for (key, value) in answers {
        if !merged.contains_key(key) {
            merged.insert(key.clone(), value.clone());
        }
    }
    Value::Object(merged)
}

/// The task-scoped ask rounds for a tool, filtered to what this caller declared it can answer. A
/// round left EMPTY by the filter is dropped rather than parked on.
#[must_use]
pub fn task_ask_rounds(
    rounds: &[crate::tools_config::AskRoundCfg],
    capabilities: &Value,
) -> Vec<Vec<CallerAsk>> {
    rounds
        .iter()
        .map(|round| crate::ask::asks_for_round(round, capabilities))
        .filter(|round| !round.is_empty())
        .collect()
}

/// The `CreateTaskResult` envelope: the flat task shape with `resultType: task`, under the caller's
/// id.
#[must_use]
pub fn task_result(id: &Value, mut created: Value) -> Vec<u8> {
    // SEP-2663's discriminator, returned ONLY on a task busbar itself just created.
    if let Some(obj) = created.as_object_mut() {
        obj.insert("resultType".into(), "task".into());
    }
    busbar_contract::jsonrpc::result_bytes(&crate::codec::json(id), &crate::codec::json(&created))
}

/// Unix milliseconds as an ISO-8601 UTC instant, `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn iso8601_ms(ms: u64) -> String {
    let ms = i64::try_from(ms).unwrap_or(i64::MAX);
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = busbar_contract::civil::civil_from_days(days);
    let (h, mi, s) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
mod tests;
