// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host launch receipts on the program need, never metadata supplied by an MCP peer. The public
//! identity is only the approved command path. Arguments, environment and working directory stay
//! bound to the host's private admission; this is no executable-byte or payload attestation.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeMap;

/// Why a stdio lease is refused when its head is not the host's first successful launch receipt.
pub(crate) const UNTRUSTED: &str =
    "the stdio MCP lease did not carry its first successful host launch receipt";
/// Why a stdio lease is refused when it carries a second launch head.
pub(crate) const REPEATED: &str = "the stdio MCP lease repeated its host launch head";

/// The host pair a launch head names: the member incarnation (`0` for a host that names none) and
/// the child's generation within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Observed {
    /// The host member incarnation ([`busbar_contract::conn::PROGRAM_INSTANCE_FIELD`]).
    pub instance: u64,
    /// The child's generation ([`busbar_contract::conn::PROGRAM_GENERATION_FIELD`]).
    pub generation: u64,
}

/// A checked internal name for each host pair. Existing call/ask/greeting ids remain u64, but
/// never alias a replacement Member's generation 1 or an earlier process's reply.
#[derive(Debug, Default)]
pub(crate) struct Versions {
    next: u64,
    latest: BTreeMap<String, (Observed, u64)>,
}

impl Versions {
    /// Resolve only the current exact checked stamp. Superseded replies cannot select a newer child.
    pub(crate) fn observed(&self, member: &str, stamp: u64) -> Option<Observed> {
        self.latest.get(member).and_then(|(observed, current)| {
            (*current == stamp && observed.instance != 0 && observed.generation != 0)
                .then_some(*observed)
        })
    }

    /// Only host narrowing fields, never forwarded as child JSON or treated as authentication.
    pub(crate) fn expected_fields(
        &self,
        member: &str,
        stamp: u64,
    ) -> Option<[(String, String); 2]> {
        let observed = self.observed(member, stamp)?;
        Some([
            (
                busbar_contract::conn::PROGRAM_EXPECT_INSTANCE_FIELD.to_string(),
                observed.instance.to_string(),
            ),
            (
                busbar_contract::conn::PROGRAM_EXPECT_GENERATION_FIELD.to_string(),
                observed.generation.to_string(),
            ),
        ])
    }

    /// [`Self::expected_fields`], only when `launch` is the very pair the stamp was checked under.
    pub(crate) fn expected_child_fields(
        &self,
        member: &str,
        stamp: u64,
        launch: Option<(u64, u64)>,
    ) -> Option<[(String, String); 2]> {
        let observed = self.observed(member, stamp)?;
        if launch != Some((observed.instance, observed.generation)) {
            return None;
        }
        self.expected_fields(member, stamp)
    }

    /// The checked internal stamp of `member`'s pair `observed`: the same stamp for the same pair, a
    /// fresh one for a newer pair, and a refusal for a pair older than the latest recorded.
    pub(crate) fn stamp(&mut self, member: &str, observed: Observed) -> Result<u64, String> {
        if let Some((before, stamp)) = self.latest.get(member) {
            if observed == *before {
                return Ok(*stamp);
            }
            if observed < *before {
                return Err("the stdio MCP host launch receipt is from a retired program".into());
            }
        }

        if observed
            == (Observed {
                instance: 0,
                generation: 0,
            })
        {
            return Ok(0);
        }
        let next = self
            .next
            .checked_add(1)
            .ok_or_else(|| "the stdio MCP launch identity space is exhausted".to_string())?;
        self.latest.insert(member.to_owned(), (observed, next));
        self.next = next;
        Ok(next)
    }
}

/// A receipt number in its one canonical spelling: decimal, non-zero, no sign, padding or space.
fn number(value: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(value).map_err(|_| UNTRUSTED.to_string())?;
    let n = text.parse::<u64>().map_err(|_| UNTRUSTED.to_string())?;
    if n == 0 || n.to_string().as_bytes() != value {
        return Err(UNTRUSTED.into());
    }
    Ok(n)
}

/// The host pair a launch head's `fields` (at `status`) name for the approved `command`. A
/// `rooted` (`local_program`) member requires the full single canonical receipt on a `2xx` head
/// or a numberless host program head (`0`, the connector ABI spelling for no status code);
/// any other member accepts a head that names only its generation, unless the head's status says
/// the launch failed.
pub(crate) fn observe<'a>(
    status: u32,
    fields: impl IntoIterator<Item = (&'a [u8], &'a [u8])>,
    command: &str,
    rooted: bool,
) -> Result<Observed, String> {
    let mut generation = None;
    let mut instance = None;
    let mut identity = None;
    for (name, value) in fields {
        let slot = if name
            .eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_GENERATION_FIELD.as_bytes())
        {
            &mut generation
        } else if name
            .eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_INSTANCE_FIELD.as_bytes())
        {
            &mut instance
        } else if name
            .eq_ignore_ascii_case(busbar_contract::conn::PROGRAM_IDENTITY_FIELD.as_bytes())
        {
            &mut identity
        } else {
            continue;
        };
        if slot.replace(value).is_some() {
            return Err(UNTRUSTED.into());
        }
    }
    if !rooted && instance.is_none() && identity.is_none() {
        if !(200..300).contains(&status) {
            return Err(UNTRUSTED.into());
        }
        let generation = generation.map(number).transpose()?.unwrap_or(0);
        return Ok(Observed {
            instance: 0,
            generation,
        });
    }
    // Program framing has no numeric status: the connector exports an absent code as 0.
    // Only a rooted local_program receipt may use that spelling; its complete canonical
    // host-owned identity below still proves the successful checked launch. Legacy heads
    // and every explicit unsuccessful status retain their existing refusal.
    if !(200..300).contains(&status) && !(rooted && status == 0) {
        return Err(UNTRUSTED.into());
    }
    let generation = number(generation.ok_or_else(|| UNTRUSTED.to_string())?)?;
    let instance = number(instance.ok_or_else(|| UNTRUSTED.to_string())?)?;

    if identity != Some(STANDARD.encode(command.as_bytes()).as_bytes()) {
        return Err(UNTRUSTED.into());
    }
    Ok(Observed {
        instance,
        generation,
    })
}

/// [`observe`] over a whole field block, refused unless the block is exactly its field lines.
pub(crate) fn block(
    status: u32,
    fields: &[u8],
    command: &str,
    rooted: bool,
) -> Result<Observed, String> {
    use busbar_contract::abi::transport::fields::{lines, LINE_END, SEPARATOR};
    let consumed: usize = lines(fields)
        .map(|(n, v)| n.len() + SEPARATOR.len() + v.len() + LINE_END.len())
        .sum();
    if consumed != fields.len() {
        return Err(UNTRUSTED.into());
    }
    observe(status, lines(fields), command, rooted)
}

#[cfg(test)]
#[path = "tests/program_trust_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/program_trust_audit.rs"]
mod program_trust_audit;
