// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP-owned delegated authorization state. This module never receives access or refresh tokens.
//! The transport performs token exchanges and the host retains credentials for governed dispatch.
//! The embedding driver must serialize a successful completion and its host credential binding
//! with revocation; a successful transition alone does not install or revoke host credentials.

use std::collections::{BTreeMap, BTreeSet};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use busbar_contract::abi::sdk::digest::sha256;
use serde::Serialize;
use zeroize::Zeroizing;

/// Public identity of a connection; none of these fields is a credential handle.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ConnectionKey {
    /// Authenticated local user, supplied by the host, never trusted from callback query parameters.
    pub user: String,
    /// Configured upstream member.
    pub upstream: String,
    /// Authenticated downstream credential binding receiving this user's consent.
    /// The runtime uses host caller_ref; it does not claim to distinguish clients sharing a key.
    pub downstream_client: String,
}

/// Exact strings approved during consent. Callback and token response processing must use the
/// same values, including trailing slashes; URL normalization does not establish equivalence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuthorizationBinding {
    /// Authorization server issuer, validated against its discovered metadata by the driver.
    pub issuer: String,
    /// Upstream resource indicator; not an arbitrary URL supplied by the callback.
    pub resource: String,
    /// Registered redirect URI.
    pub redirect_uri: String,
    /// Client identifier at the upstream authorization server.
    pub client_id: String,
}

/// Observable connection lifecycle, with no bearer material.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Consent exists but no successful authorization has completed.
    Consented,
    /// Waiting for a browser callback.
    Authorizing,
    /// The callback was consumed; one token exchange is in progress.
    Exchanging,
    /// Host credential binding may be used until its expiry.
    Active,
    /// Refresh is in progress; the previous binding remains usable until expiry.
    Refreshing,
    /// Consent was withdrawn and no completion can reactivate this revision.
    Revoked,
}

/// Safe connection metadata suitable for a public record; contains no tokens, state or verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicConnection {
    /// Public enrollment identity, unique within this driver instance; host custody additionally
    /// scopes it to its instance incarnation. Re-consent never reuses a revoked identity.
    pub id: String,
    /// User, member and downstream client identity.
    pub key: ConnectionKey,
    /// Host credential revision: zero before installation; installation, refresh and revocation increment it.
    pub revision: u64,
    /// Exact consent binding.
    pub binding: AuthorizationBinding,
    /// Scopes explicitly consented to by this user for this downstream client.
    pub scopes: BTreeSet<String>,
    /// Current lifecycle stage.
    pub status: Status,
    /// Access credential expiry in the driver's monotonically comparable millisecond clock.
    pub expires_at_ms: Option<u64>,
}

/// Discovery and upstream sessions are partitioned by all three principals AND authorization
/// revision. Cache hits must still call [`Connections::discovery_key`] to check current expiry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DiscoveryKey {
    /// Enrollment identity: re-consent cannot reuse a previous enrollment's cached results.
    pub connection_id: String,
    /// Public connection identity.
    pub connection: ConnectionKey,
    /// Authorization revision; refresh and revocation invalidate previous entries.
    pub revision: u64,
}

impl DiscoveryKey {
    /// Collision-free key for an upstream session store; JSON framing avoids delimiter ambiguity.
    #[must_use]
    pub fn session_key(&self) -> String {
        // Serialization of strings and u64 cannot fail.
        serde_json::to_string(self).expect("connection session key is serializable")
    }
}

/// Refusal reasons contain no OAuth secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Consent is absent, revoked, or belongs to another authenticated tuple.
    ConsentRequired,
    /// Invalid or changed issuer, resource, redirect, client, or scope binding.
    BindingMismatch,
    /// Unknown or already consumed authorization state.
    InvalidState,
    /// The authorization, exchange, or access binding expired.
    Expired,
    /// A completion belongs to an older revision or another lifecycle operation.
    StaleCompletion,
    /// A refresh is already outstanding or the connection has never become active.
    NotActive,
    /// The bounded table or revision counter cannot accept another operation.
    Capacity,
}

/// Browser authorization parameters. Debug deliberately omits the state.
pub struct AuthorizationRequest {
    /// One-use opaque authorization state. Send to the issuer and require it on callback.
    pub state: String,
    /// RFC 7636 S256 challenge. The driver must send `code_challenge_method=S256`.
    pub code_challenge: String,
    /// Binding to use when constructing the authorization request.
    pub binding: AuthorizationBinding,
    /// Explicitly consented scopes to request.
    pub scopes: BTreeSet<String>,
}

/// A consumed callback's exchange permit. Not clonable, serializable or debug printable. Its
/// private revision is checked again after network IO, including after concurrent revocation.
pub struct ExchangePermit {
    key: ConnectionKey,
    revision: u64,
    deadline_ms: u64,
    verifier: Zeroizing<String>,
    binding: AuthorizationBinding,
}

impl ExchangePermit {
    /// PKCE verifier for the sole token exchange; never persist this as an ordinary plane record.
    #[must_use]
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// Exact token exchange binding approved by the user.
    #[must_use]
    pub fn binding(&self) -> &AuthorizationBinding {
        &self.binding
    }
}

/// Revision fence for one refresh. Holds no token or host credential reference.
pub struct RefreshPermit {
    key: ConnectionKey,
    revision: u64,
    deadline_ms: u64,
}

struct Pending {
    state: Zeroizing<String>,
    verifier: Zeroizing<String>,
    deadline_ms: u64,
}

struct Connection {
    generation: u64,
    public: PublicConnection,
    pending: Option<Pending>,
}

/// Bounded in-memory protocol state. Restart fails closed: callers must obtain consent again.
/// The driver supplies authenticated identities, secure random bytes and a trustworthy clock.
pub struct Connections {
    entries: BTreeMap<ConnectionKey, Connection>,
    next_revision: u64,
    capacity: usize,
}

impl Connections {
    /// Construct an empty table with at most `capacity` connections, including revoked tombstones.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            next_revision: 1,
            capacity,
        }
    }

    fn revision(&mut self) -> Result<u64, Error> {
        let revision = self.next_revision;
        self.next_revision = revision.checked_add(1).ok_or(Error::Capacity)?;
        Ok(revision)
    }

    /// Record an explicit user consent decision. The driver must authenticate the tuple and
    /// present these exact issuer/resource/client/scopes before calling this method. Re-consent
    /// mints a new public enrollment identity and invalidates pending operations, discovery and
    /// sessions. The driver must revoke any previous host binding before replacing its consent.
    pub fn grant_consent(
        &mut self,
        key: ConnectionKey,
        binding: AuthorizationBinding,
        scopes: BTreeSet<String>,
    ) -> Result<PublicConnection, Error> {
        if key.user.is_empty()
            || key.upstream.is_empty()
            || key.downstream_client.is_empty()
            || !valid_binding(&binding)
            || scopes.iter().any(|scope| !valid_scope(scope))
        {
            return Err(Error::BindingMismatch);
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            return Err(Error::Capacity);
        }
        let generation = self.revision()?;
        let public = PublicConnection {
            id: format!("mcp-{generation}"),
            key: key.clone(),
            revision: 0,
            binding,
            scopes,
            status: Status::Consented,
            expires_at_ms: None,
        };
        self.entries.insert(
            key,
            Connection {
                generation,
                public: public.clone(),
                pending: None,
            },
        );
        Ok(public)
    }

    /// Begin authorization with independent, cryptographically random 32-byte state and verifier
    /// entropy. A new attempt invalidates every previous attempt for this tuple. Deadline is
    /// exclusive, and is also the deadline for completing the token exchange.
    pub fn begin_authorization(
        &mut self,
        key: &ConnectionKey,
        state_entropy: [u8; 32],
        verifier_entropy: [u8; 32],
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<AuthorizationRequest, Error> {
        self.consented(key)?;
        if deadline_ms <= now_ms {
            return Err(Error::Expired);
        }
        let revision = self.revision()?;
        // Revision binding prevents accidental reuse of a previously consumed state within this
        // instance, even if a driver mistakenly reuses entropy. Secure entropy is still required.
        let mut seed = Zeroizing::new(Vec::from(state_entropy));
        seed.extend_from_slice(&revision.to_be_bytes());
        let state = URL_SAFE_NO_PAD.encode(sha256(&seed));
        let verifier = Zeroizing::new(URL_SAFE_NO_PAD.encode(verifier_entropy));
        let challenge = URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()));
        let connection = self.entries.get_mut(key).ok_or(Error::ConsentRequired)?;
        connection.generation = revision;
        connection.public.status = Status::Authorizing;
        connection.public.expires_at_ms = None;
        connection.pending = Some(Pending {
            state: Zeroizing::new(state.clone()),
            verifier,
            deadline_ms,
        });
        Ok(AuthorizationRequest {
            state,
            code_challenge: challenge,
            binding: connection.public.binding.clone(),
            scopes: connection.public.scopes.clone(),
        })
    }

    /// Consume a callback exactly once after checking the authenticated tuple, issuer, resource,
    /// redirect and upstream client. The driver must obtain the issuer from the actual response,
    /// not fill it in from configuration; missing `iss` is refused by the driver when required.
    pub fn consume_callback(
        &mut self,
        key: &ConnectionKey,
        state: &str,
        binding: &AuthorizationBinding,
        now_ms: u64,
    ) -> Result<ExchangePermit, Error> {
        let connection = self.consented(key)?;
        if connection.public.binding != *binding {
            return Err(Error::BindingMismatch);
        }
        let pending = connection.pending.as_ref().ok_or(Error::InvalidState)?;
        if !same_state(&pending.state, state) {
            return Err(Error::InvalidState);
        }
        if pending.deadline_ms <= now_ms {
            let connection = self.entries.get_mut(key).ok_or(Error::ConsentRequired)?;
            connection.pending = None;
            connection.public.status = Status::Consented;
            return Err(Error::Expired);
        }
        let connection = self.entries.get_mut(key).ok_or(Error::ConsentRequired)?;
        let pending = connection.pending.take().ok_or(Error::InvalidState)?;
        connection.public.status = Status::Exchanging;
        Ok(ExchangePermit {
            key: key.clone(),
            revision: connection.generation,
            deadline_ms: pending.deadline_ms,
            verifier: pending.verifier,
            binding: binding.clone(),
        })
    }

    /// Accept a successful exchange only if consent and the exact outstanding revision survive.
    /// The driver first validates the token response's issuer/audience/scopes and retains its
    /// credentials in host custody. It must atomically bind them with this transition or discard
    /// them on refusal. No token is accepted or retained by this protocol model.
    pub fn complete_authorization(
        &mut self,
        permit: ExchangePermit,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<PublicConnection, Error> {
        self.complete(
            &permit.key,
            permit.revision,
            Status::Exchanging,
            permit.deadline_ms,
            now_ms,
            expires_at_ms,
        )
    }

    /// Reserve one refresh. Access expiry does not prevent refreshing a valid consent, but two
    /// refreshes cannot race to rotate the same credential. The driver owns refresh-token expiry.
    pub fn begin_refresh(
        &mut self,
        key: &ConnectionKey,
        now_ms: u64,
        deadline_ms: u64,
    ) -> Result<RefreshPermit, Error> {
        let connection = self.consented(key)?;
        if connection.public.status != Status::Active {
            return Err(Error::NotActive);
        }
        if deadline_ms <= now_ms {
            return Err(Error::Expired);
        }
        let connection = self.entries.get_mut(key).ok_or(Error::ConsentRequired)?;
        connection.public.status = Status::Refreshing;
        Ok(RefreshPermit {
            key: key.clone(),
            revision: connection.generation,
            deadline_ms,
        })
    }

    /// Complete refresh after host custody accepted the rotated credentials, fenced against
    /// revocation or re-consent. See [`Self::complete_authorization`] for the atomic driver duty.
    pub fn complete_refresh(
        &mut self,
        permit: RefreshPermit,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<PublicConnection, Error> {
        self.complete(
            &permit.key,
            permit.revision,
            Status::Refreshing,
            permit.deadline_ms,
            now_ms,
            expires_at_ms,
        )
    }

    /// Release a failed refresh without changing consent. A late failure cannot change a revoked
    /// or newer connection; an expired access binding remains unusable after this transition.
    pub fn fail_refresh(&mut self, permit: RefreshPermit) -> Result<(), Error> {
        let connection = self
            .entries
            .get_mut(&permit.key)
            .ok_or(Error::StaleCompletion)?;
        if connection.generation != permit.revision
            || connection.public.status != Status::Refreshing
        {
            return Err(Error::StaleCompletion);
        }
        connection.public.status = Status::Active;
        Ok(())
    }

    fn complete(
        &mut self,
        key: &ConnectionKey,
        revision: u64,
        status: Status,
        deadline_ms: u64,
        now_ms: u64,
        expires_at_ms: u64,
    ) -> Result<PublicConnection, Error> {
        let connection = self.entries.get(key).ok_or(Error::StaleCompletion)?;
        if connection.generation != revision || connection.public.status != status {
            return Err(Error::StaleCompletion);
        }
        if now_ms >= deadline_ms || expires_at_ms <= now_ms {
            let connection = self.entries.get_mut(key).ok_or(Error::StaleCompletion)?;
            connection.public.status = if status == Status::Refreshing {
                Status::Active
            } else {
                Status::Consented
            };
            return Err(Error::Expired);
        }
        let next = connection
            .public
            .revision
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        let connection = self.entries.get_mut(key).ok_or(Error::StaleCompletion)?;
        connection.public.revision = next;
        connection.public.status = Status::Active;
        connection.public.expires_at_ms = Some(expires_at_ms);
        Ok(connection.public.clone())
    }

    /// Withdraw consent and invalidate callbacks, exchanges, refreshes, discovery and sessions.
    /// The driver must also invalidate the host binding before acknowledging revocation.
    pub fn revoke(&mut self, key: &ConnectionKey) -> Result<PublicConnection, Error> {
        self.entries.get(key).ok_or(Error::ConsentRequired)?;
        let revision = self.revision()?;
        let connection = self.entries.get_mut(key).ok_or(Error::ConsentRequired)?;
        connection.public.revision = connection
            .public
            .revision
            .checked_add(1)
            .ok_or(Error::Capacity)?;
        connection.generation = revision;
        connection.public.status = Status::Revoked;
        connection.public.expires_at_ms = None;
        connection.pending = None;
        Ok(connection.public.clone())
    }

    /// Inspect only public connection metadata for an already authenticated tuple.
    #[must_use]
    pub fn get(&self, key: &ConnectionKey) -> Option<&PublicConnection> {
        self.entries.get(key).map(|connection| &connection.public)
    }

    /// Obtain the currently authorized partition for discovery or an upstream session. The same
    /// check must guard use of a cached result, so expiry/revocation cannot leave a usable cache.
    pub fn discovery_key(&self, key: &ConnectionKey, now_ms: u64) -> Result<DiscoveryKey, Error> {
        let connection = self.consented(key)?;
        if !matches!(
            connection.public.status,
            Status::Active | Status::Refreshing
        ) {
            return Err(Error::NotActive);
        }
        if connection
            .public
            .expires_at_ms
            .is_none_or(|expiry| expiry <= now_ms)
        {
            return Err(Error::Expired);
        }
        Ok(DiscoveryKey {
            connection_id: connection.public.id.clone(),
            connection: key.clone(),
            revision: connection.public.revision,
        })
    }

    fn consented(&self, key: &ConnectionKey) -> Result<&Connection, Error> {
        self.entries
            .get(key)
            .filter(|c| c.public.status != Status::Revoked)
            .ok_or(Error::ConsentRequired)
    }
}

fn same_state(expected: &str, actual: &str) -> bool {
    expected.len() == actual.len()
        && expected
            .bytes()
            .zip(actual.bytes())
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub(crate) fn valid_binding(binding: &AuthorizationBinding) -> bool {
    fn secure_url(value: &str, redirect: bool) -> bool {
        let Ok(url) = url::Url::parse(value) else {
            return false;
        };
        url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
            && (url.scheme() == "https"
                || (redirect
                    && url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"))))
    }
    !binding.client_id.is_empty()
        && secure_url(&binding.issuer, false)
        && url::Url::parse(&binding.issuer).is_ok_and(|url| url.query().is_none())
        && secure_url(&binding.resource, false)
        && secure_url(&binding.redirect_uri, true)
}

#[cfg(test)]
#[path = "tests/connection_tests.rs"]
mod tests;

/// RFC 6749 scope-token, with no whitespace, quote, backslash or non-ASCII byte.
pub(crate) fn valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}
