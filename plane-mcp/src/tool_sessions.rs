// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SESSION STATE FOR THE SESSION REVISIONS: plane state, per process, bounded, and bound to its
//! owner. No statics, no clock (the caller passes `now_ms`), no randomness (the caller passes the
//! entropy).
//!
//! Every dimension has a ceiling in [`Bounds`], and ONE OWNER'S PRESSURE NEVER EVICTS ANOTHER
//! OWNER'S SESSION OR EVENTS: every eviction and trim lands on the owner whose open or write caused
//! it. An evicted, expired or foreign session answers exactly as an unknown one does (404, and the
//! client re-initialises), so a leaked id is not a probe. An all-zero entropy buffer is refused.

use std::collections::{BTreeMap, VecDeque};

use crate::revision::Revision;

/// The ceilings on the session table. See the module header for what each one evicts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// Most sessions held at once.
    pub max_sessions: usize,
    /// Most sessions one owner may hold at once.
    pub max_owner_sessions: usize,
    /// Most bytes one owner's sessions may hold together.
    pub max_owner_bytes: usize,
    /// Most bytes of buffered events one session may hold.
    pub max_session_bytes: usize,
    /// Most bytes the whole table may hold.
    pub max_total_bytes: usize,
    /// A session untouched for this many milliseconds is expired.
    pub idle_ms: u64,
    /// Most resumable event stream cursors one session may hold at once.
    pub stream_cap: usize,
}

impl Default for Bounds {
    fn default() -> Self {
        Self {
            max_sessions: 10_000,
            max_owner_sessions: 100,
            max_owner_bytes: 8 << 20,
            max_session_bytes: 1 << 20,
            max_total_bytes: 64 << 20,
            idle_ms: 30 * 60 * 1000,
            stream_cap: 16,
        }
    }
}

/// The fixed cost charged to a session for its own bookkeeping, so a table of empty sessions is
/// still bounded by `max_total_bytes`.
const SESSION_OVERHEAD: usize = 256;
/// The fixed cost charged per buffered event over its data.
const EVENT_OVERHEAD: usize = 32;

/// The principal and credential a session is bound to. A session belongs to the credential (the
/// virtual key) that opened it, never to a group of keys, so a sibling key cannot take it over.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Owner {
    /// The authenticated principal that opened the session.
    pub principal: String,
    /// The credential the principal presented: the virtual key's id, or one constant for the
    /// ungoverned open chain (which isolates nothing, matching that posture's wildcard grants).
    pub credential: String,
}

/// How a session's messages are carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carriage {
    /// The single endpoint: POST, the GET stream and DELETE.
    Endpoint,
    /// The `2024-11-05` event stream, with messages POSTed to the address it named.
    EventStream,
}

/// Why a session could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenRefused {
    /// The entropy was all zeroes: the entropy source failed, and an id minted from it would be
    /// guessable and would repeat.
    NoEntropy,
    /// The id already names a live session. The caller draws fresh entropy and tries again.
    Collision,
    /// The table is full and the opener holds no session that could give way. Another owner's
    /// session is never evicted to make room.
    Full,
}

/// What one owner holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Use {
    sessions: usize,
    bytes: usize,
}

/// One buffered server-sent event of a session stream, kept so a reconnecting `Last-Event-ID` can
/// resume from it.
#[derive(Debug)]
struct ReplayEvent {
    seq: u64,
    /// Session-wide write order, so the oldest event in any stream is found without a clock.
    order: u64,
    data: String,
}

#[derive(Debug)]
struct Stream {
    id: u32,
    next_seq: u64,
    /// The highest seq ever trimmed away, or 0 when nothing was trimmed.
    trimmed_through: u64,
    events: VecDeque<ReplayEvent>,
}

#[derive(Debug)]
struct Session {
    owner: Owner,
    revision: Revision,
    carriage: Carriage,
    initialized: bool,
    last_ms: u64,
    open: Vec<Stream>,
    next_stream: u32,
    next_order: u64,
    bytes: usize,
}

impl Session {
    fn base_bytes(owner: &Owner) -> usize {
        SESSION_OVERHEAD + owner.principal.len() + owner.credential.len()
    }

    /// Drops the oldest buffered event in the session. Returns the bytes freed (0 when empty).
    fn trim_oldest(&mut self) -> usize {
        let Some(stream) = self
            .open
            .iter_mut()
            .filter(|s| !s.events.is_empty())
            .min_by_key(|s| s.events.front().map_or(u64::MAX, |e| e.order))
        else {
            return 0;
        };
        let Some(event) = stream.events.pop_front() else {
            return 0;
        };
        stream.trimmed_through = stream.trimmed_through.max(event.seq);
        let freed = event.data.len() + EVENT_OVERHEAD;
        self.bytes -= freed;
        freed
    }
}

/// What a `Last-Event-ID` resumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// The stream the cursor named, which the resumed connection continues.
    pub stream: u32,
    /// `(event id, data)` for every buffered event after the cursor, in order.
    pub events: Vec<(String, String)>,
    /// `false` when events after the cursor were trimmed and cannot be replayed.
    pub complete: bool,
}

/// The session table for one plane instance.
#[derive(Debug)]
pub struct SessionTable {
    bounds: Bounds,
    sessions: BTreeMap<String, Session>,
    total_bytes: usize,
    owners: BTreeMap<Owner, Use>,
}

/// Formats an event id: `<stream>-<seq>`, unique within the session.
fn event_id(stream: u32, seq: u64) -> String {
    format!("{stream}-{seq}")
}

/// Reads an event id back. `None` for anything this table did not write.
fn parse_event_id(raw: &str) -> Option<(u32, u64)> {
    let (s, q) = raw.split_once('-')?;
    Some((s.parse().ok()?, q.parse().ok()?))
}

impl SessionTable {
    /// An empty table under `bounds`.
    #[must_use]
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            sessions: BTreeMap::new(),
            total_bytes: 0,
            owners: BTreeMap::new(),
        }
    }

    /// Sessions `owner` holds.
    #[must_use]
    pub fn owner_sessions(&self, owner: &Owner) -> usize {
        self.owners.get(owner).map_or(0, |u| u.sessions)
    }

    /// Bytes charged to `owner`.
    #[must_use]
    pub fn owner_bytes(&self, owner: &Owner) -> usize {
        self.owners.get(owner).map_or(0, |u| u.bytes)
    }

    fn hold_bytes(&mut self, owner: &Owner, bytes: usize) {
        self.total_bytes += bytes;
        self.owners.entry(owner.clone()).or_default().bytes += bytes;
    }

    fn release_bytes(&mut self, owner: &Owner, bytes: usize) {
        self.total_bytes -= bytes;
        if let Some(u) = self.owners.get_mut(owner) {
            u.bytes -= bytes;
        }
    }

    /// Whether `id` names a session the table still holds, whoever owns it (state kept beside a
    /// session is dropped once this is false).
    #[must_use]
    pub fn holds(&self, id: &str) -> bool {
        self.sessions.contains_key(id)
    }

    /// Opens a session for `owner`: its id, 32 lowercase hex digits from `entropy` (16 bytes from
    /// the caller's CSPRNG).
    ///
    /// # Errors
    /// [`OpenRefused::NoEntropy`] for an all-zero buffer, [`OpenRefused::Collision`] when the id is
    /// already live, [`OpenRefused::Full`] when only another owner's session could make room.
    pub fn open(
        &mut self,
        entropy: [u8; 16],
        owner: Owner,
        revision: Revision,
        carriage: Carriage,
        now_ms: u64,
    ) -> Result<String, OpenRefused> {
        if entropy.iter().all(|b| *b == 0) {
            return Err(OpenRefused::NoEntropy);
        }
        let mut id = String::with_capacity(32);
        for b in entropy {
            id.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
            id.push(char::from(b"0123456789abcdef"[usize::from(b & 0xf)]));
        }
        self.sweep(now_ms);
        if self.sessions.contains_key(&id) {
            return Err(OpenRefused::Collision);
        }
        while self.owner_sessions(&owner) >= self.bounds.max_owner_sessions.max(1) {
            if !self.evict_lru_of(&owner, None) {
                break;
            }
        }
        while self.sessions.len() >= self.bounds.max_sessions.max(1) {
            if !self.evict_lru_of(&owner, None) {
                return Err(OpenRefused::Full);
            }
        }
        let bytes = Session::base_bytes(&owner);
        self.hold_bytes(&owner, bytes);
        self.owners.entry(owner.clone()).or_default().sessions += 1;
        let key = owner.clone();
        self.sessions.insert(
            id.clone(),
            Session {
                owner,
                revision,
                carriage,
                initialized: false,
                last_ms: now_ms,
                open: Vec::new(),
                next_stream: 0,
                next_order: 0,
                bytes,
            },
        );
        if !self.enforce(&key, &id) {
            self.remove(&id);
            return Err(OpenRefused::Full);
        }
        Ok(id)
    }

    /// Finds `id` for `owner`, refreshing its idle clock. Unknown, expired and foreign sessions all
    /// read `None`.
    fn find(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<&mut Session> {
        let last_ms = self.sessions.get(id)?.last_ms;
        let expired = now_ms.saturating_sub(last_ms) >= self.bounds.idle_ms;
        if expired {
            self.remove(id);
            return None;
        }
        let s = self.sessions.get_mut(id)?;
        if s.owner != *owner {
            return None;
        }
        s.last_ms = now_ms;
        Some(s)
    }

    /// The revision `id` negotiated, when `owner` holds it.
    pub fn revision(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<Revision> {
        self.find(id, owner, now_ms).map(|s| s.revision)
    }

    /// How `id` is carried, when `owner` holds it.
    pub fn carriage(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<Carriage> {
        self.find(id, owner, now_ms).map(|s| s.carriage)
    }

    /// Records `notifications/initialized`. `false` when `owner` does not hold `id`.
    pub fn mark_initialized(&mut self, id: &str, owner: &Owner, now_ms: u64) -> bool {
        self.find(id, owner, now_ms)
            .map(|s| s.initialized = true)
            .is_some()
    }

    /// Ends `id` (DELETE). `false` when `owner` does not hold it.
    pub fn close(&mut self, id: &str, owner: &Owner, now_ms: u64) -> bool {
        if self.find(id, owner, now_ms).is_none() {
            return false;
        }
        self.remove(id);
        true
    }

    /// Opens a resumable stream in `id`. When the session is at `stream_cap`, the oldest stream
    /// and its buffered events are dropped first.
    pub fn open_stream(&mut self, id: &str, owner: &Owner, now_ms: u64) -> Option<u32> {
        let stream_cap = self.bounds.stream_cap.max(1);
        let s = self.find(id, owner, now_ms)?;
        let mut freed = 0;
        while s.open.len() >= stream_cap {
            let dropped = s.open.remove(0);
            freed += dropped
                .events
                .iter()
                .map(|e| e.data.len() + EVENT_OVERHEAD)
                .sum::<usize>();
        }
        s.bytes -= freed;
        let stream = s.next_stream;
        s.next_stream = s.next_stream.wrapping_add(1);
        s.open.push(Stream {
            id: stream,
            next_seq: 1,
            trimmed_through: 0,
            events: VecDeque::new(),
        });
        self.release_bytes(owner, freed);
        Some(stream)
    }

    /// Buffers `data` as the next event on `stream` and returns its event id. The buffer is then
    /// trimmed to the session and table bounds. `None` when `owner` does not hold `id` or the stream
    /// is not open.
    pub fn push(
        &mut self,
        id: &str,
        owner: &Owner,
        stream: u32,
        data: &str,
        now_ms: u64,
    ) -> Option<String> {
        let max_session = self.bounds.max_session_bytes;
        let s = self.find(id, owner, now_ms)?;
        let order = s.next_order;
        let st = s.open.iter_mut().find(|st| st.id == stream)?;
        let seq = st.next_seq;
        st.next_seq += 1;
        let cost = data.len() + EVENT_OVERHEAD;
        st.events.push_back(ReplayEvent {
            seq,
            order,
            data: data.to_string(),
        });
        s.next_order += 1;
        s.bytes += cost;
        let base = Session::base_bytes(&s.owner);
        let mut freed = 0;
        while s.bytes > base + max_session {
            let f = s.trim_oldest();
            if f == 0 {
                break;
            }
            freed += f;
        }
        // Trimming to fit can free more than this event cost (one older large event, or this
        // event itself past `max_session_bytes`): the owner is then charged less, never negative.
        if freed > cost {
            self.release_bytes(owner, freed - cost);
        } else {
            self.hold_bytes(owner, cost - freed);
        }
        self.enforce(owner, id);
        Some(event_id(stream, seq))
    }

    /// Resumes after `last_event_id`. `None` when `owner` does not hold `id`, or the cursor names a
    /// stream the session does not hold (a cursor from another stream is never replayed here: the
    /// spec forbids replaying one stream's messages on another).
    pub fn replay(
        &mut self,
        id: &str,
        owner: &Owner,
        last_event_id: &str,
        now_ms: u64,
    ) -> Option<Replay> {
        let (stream, cursor) = parse_event_id(last_event_id)?;
        let s = self.find(id, owner, now_ms)?;
        let st = s.open.iter().find(|st| st.id == stream)?;
        let events: Vec<(String, String)> = st
            .events
            .iter()
            .filter(|e| e.seq > cursor)
            .map(|e| (event_id(stream, e.seq), e.data.clone()))
            .collect();
        Some(Replay {
            stream,
            events,
            complete: st.trimmed_through <= cursor,
        })
    }

    /// Drops every expired session. Returns how many.
    pub fn sweep(&mut self, now_ms: u64) -> usize {
        let idle = self.bounds.idle_ms;
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, s)| now_ms.saturating_sub(s.last_ms) >= idle)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            self.remove(k);
        }
        expired.len()
    }

    fn remove(&mut self, id: &str) {
        if let Some(s) = self.sessions.remove(id) {
            self.release_bytes(&s.owner, s.bytes);
            let empty = self.owners.get_mut(&s.owner).is_some_and(|u| {
                u.sessions -= 1;
                u.sessions == 0
            });
            if empty {
                self.owners.remove(&s.owner);
            }
        }
    }

    /// Evicts `owner`'s least recently used session other than `keep`. `false` when there is none.
    /// Never another owner's.
    fn evict_lru_of(&mut self, owner: &Owner, keep: Option<&str>) -> bool {
        let victim = self
            .sessions
            .iter()
            .filter(|(k, s)| s.owner == *owner && Some(k.as_str()) != keep)
            .min_by_key(|(k, s)| (s.last_ms, (*k).clone()))
            .map(|(k, _)| k.clone());
        match victim {
            Some(v) => {
                self.remove(&v);
                true
            }
            None => false,
        }
    }

    /// Holds `owner` under its byte share and the table under its total, at `owner`'s cost only:
    /// its other sessions go first, then `keep`'s oldest events. `false` when that was not enough.
    fn enforce(&mut self, owner: &Owner, keep: &str) -> bool {
        loop {
            let over = self.owner_bytes(owner) > self.bounds.max_owner_bytes
                || self.total_bytes > self.bounds.max_total_bytes;
            if !over {
                return true;
            }
            if self.evict_lru_of(owner, Some(keep)) {
                continue;
            }
            let freed = self.sessions.get_mut(keep).map_or(0, Session::trim_oldest);
            if freed == 0 {
                return false;
            }
            self.release_bytes(owner, freed);
        }
    }
}

/// WHAT BUSBAR REMEMBERS ABOUT ONE UPSTREAM, as a client: the revision it negotiated and, on a
/// session revision, the upstream's session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remembered {
    /// The negotiated revision.
    pub revision: Revision,
    /// The upstream's session id, on a session revision.
    pub session: Option<String>,
}

impl Remembered {
    fn bytes(&self, key: &str) -> usize {
        SESSION_OVERHEAD + key.len() + self.session.as_ref().map_or(0, String::len)
    }
}

/// The key of one remembered upstream conversation: the member AND the caller binding it was
/// negotiated for (the caller reference the kernel lends; the ungoverned chain's is empty). Two
/// callers of one member never share a session (row 159 finding 3): a session revision's server
/// keeps per-session state, binds a session to the identity that opened it, and maps request ids
/// to answers within it.
#[must_use]
pub fn upstream_key(member: &str, binding: &str) -> String {
    format!("{member}\u{1f}{binding}")
}

/// The first JSON-RPC id a request lowered into a remembered session carries: above every id a
/// stateless round carries (`dispatch_request_id`, the round) and below `initialize`'s.
pub const SESSION_FIRST_ID: u64 = 1 << 32;

/// The client's per-upstream memory, bounded in count and bytes with least-recently-used eviction.
/// Forgetting an upstream costs one renegotiation and nothing else. Each remembered session also
/// numbers the requests busbar sends in it ([`UpstreamTable::next_id`]), so no id repeats within
/// one session (the session revisions forbid it).
#[derive(Debug)]
pub struct UpstreamTable {
    max_entries: usize,
    max_bytes: usize,
    entries: BTreeMap<String, (Remembered, u64)>,
    /// The next request id per remembered session, by key: kept while the session is.
    ids: BTreeMap<String, u64>,
    bytes: usize,
    tick: u64,
}

impl UpstreamTable {
    /// An empty table holding at most `max_entries` upstreams and `max_bytes`.
    #[must_use]
    pub fn new(max_entries: usize, max_bytes: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_bytes,
            entries: BTreeMap::new(),
            ids: BTreeMap::new(),
            bytes: 0,
            tick: 0,
        }
    }

    /// What is remembered about `upstream`, refreshing its recency.
    pub fn get(&mut self, upstream: &str) -> Option<Remembered> {
        self.tick += 1;
        let tick = self.tick;
        self.entries.get_mut(upstream).map(|(r, t)| {
            *t = tick;
            r.clone()
        })
    }

    /// THE NEXT REQUEST ID of `upstream`'s remembered session, taken: unique within that session
    /// for as long as it is remembered. `None` when nothing with a session is remembered for it.
    pub fn next_id(&mut self, upstream: &str) -> Option<u64> {
        self.entries
            .get(upstream)
            .filter(|(r, _)| r.session.is_some())?;
        let id = self
            .ids
            .entry(upstream.to_string())
            .or_insert(SESSION_FIRST_ID);
        let taken = *id;
        *id = id.saturating_add(1);
        Some(taken)
    }

    /// Remembers `value` for `upstream`, evicting least-recently-used upstreams to fit. The same
    /// session remembered again keeps its id numbering; another session starts its own.
    pub fn put(&mut self, upstream: &str, value: Remembered) {
        let same = self
            .entries
            .get(upstream)
            .is_some_and(|(r, _)| r.session.is_some() && r.session == value.session);
        let kept = if same {
            self.ids.get(upstream).copied()
        } else {
            None
        };
        self.forget(upstream);
        let cost = value.bytes(upstream);
        if cost > self.max_bytes {
            return;
        }
        while self.entries.len() >= self.max_entries || self.bytes + cost > self.max_bytes {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, t))| *t)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.forget(&victim);
        }
        self.tick += 1;
        self.bytes += cost;
        self.entries
            .insert(upstream.to_string(), (value, self.tick));
        if let Some(id) = kept {
            self.ids.insert(upstream.to_string(), id);
        }
    }

    /// Forgets `upstream` (its session ended, or it answered 404 for it).
    pub fn forget(&mut self, upstream: &str) {
        if let Some((r, _)) = self.entries.remove(upstream) {
            self.bytes -= r.bytes(upstream);
        }
        self.ids.remove(upstream);
    }
}

#[cfg(test)]
#[path = "tests/session_tests.rs"]
mod tests;
