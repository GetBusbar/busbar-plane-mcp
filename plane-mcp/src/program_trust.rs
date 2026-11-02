// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host launch receipts on the program need, never metadata supplied by an MCP peer. The public
//! identity is only the approved command path. Arguments, environment and working directory stay
//! bound to the host's private admission; this is no executable-byte or payload attestation.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::collections::BTreeMap;

pub(crate) const UNTRUSTED: &str =
    "the stdio MCP lease did not carry its first successful host launch receipt";
pub(crate) const REPEATED: &str = "the stdio MCP lease repeated its host launch head";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Observed {
    pub instance: u64,
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

    pub(crate) fn stamp(&mut self, member: &str, observed: Observed) -> Result<u64, String> {
        if let Some((before, stamp)) = self.latest.get(member) {
            if observed == *before {
                return Ok(*stamp);
            }
            if observed < *before {
                return Err("the stdio MCP host launch receipt is from a retired program".into());
            }
        }
        // Legacy non-rooted value-only fixtures may carry no generation. It authenticates nothing.
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

fn number(value: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(value).map_err(|_| UNTRUSTED.to_string())?;
    let n = text.parse::<u64>().map_err(|_| UNTRUSTED.to_string())?;
    if n == 0 || n.to_string().as_bytes() != value {
        return Err(UNTRUSTED.into());
    }
    Ok(n)
}

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
        let generation = generation
            .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
            .unwrap_or(0);
        return Ok(Observed {
            instance: 0,
            generation,
        });
    }
    if !(200..300).contains(&status) {
        return Err(UNTRUSTED.into());
    }
    let generation = number(generation.ok_or_else(|| UNTRUSTED.to_string())?)?;
    let instance = number(instance.ok_or_else(|| UNTRUSTED.to_string())?)?;
    // Comparing the canonical encoding of the approved UTF-8 bytes also rejects permissive
    // base64 aliases, invalid UTF-8 and whitespace, without allocating from untrusted input size.
    if identity != Some(STANDARD.encode(command.as_bytes()).as_bytes()) {
        return Err(UNTRUSTED.into());
    }
    Ok(Observed {
        instance,
        generation,
    })
}

pub(crate) fn block(
    status: u32,
    fields: &[u8],
    command: &str,
    rooted: bool,
) -> Result<Observed, String> {
    let consumed: usize = busbar_contract::abi::transport::fields::lines(fields)
        .map(|(n, v)| n.len() + 2 + v.len() + 2)
        .sum();
    if consumed != fields.len() {
        return Err(UNTRUSTED.into());
    }
    observe(
        status,
        busbar_contract::abi::transport::fields::lines(fields),
        command,
        rooted,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMAND: &str = "/approved/child\r\nnot-a-header";

    fn fields(instance: &str, generation: &str, command: &str) -> Vec<u8> {
        format!(
            "generation: {generation}\r\nprogram-instance: {instance}\r\nprogram-identity: {}\r\n",
            STANDARD.encode(command)
        )
        .into_bytes()
    }

    #[test]
    fn canonical_host_receipt_binds_exact_command_without_header_injection() {
        assert_eq!(
            block(200, &fields("37", "2", COMMAND), COMMAND, true).unwrap(),
            Observed {
                instance: 37,
                generation: 2
            }
        );
        assert!(block(200, &fields("37", "2", COMMAND), "/approved/other", true).is_err());
        for status in [0, 199, 300, 403, 500] {
            assert!(block(status, &fields("37", "2", COMMAND), COMMAND, true).is_err());
        }
    }

    #[test]
    fn rooted_receipt_requires_all_single_canonical_fields() {
        let good = fields("37", "2", COMMAND);
        assert!(block(200, &good, COMMAND, true).is_ok());
        for name in ["generation", "program-instance", "program-identity"] {
            let text = std::str::from_utf8(&good).unwrap();
            let absent = text
                .lines()
                .filter(|line| !line.starts_with(name))
                .map(|line| format!("{line}\r\n"))
                .collect::<String>();
            assert!(
                block(200, absent.as_bytes(), COMMAND, true).is_err(),
                "missing {name}"
            );
            for duplicate in [name.to_string(), name.to_uppercase()] {
                let mut duplicate_head = good.clone();
                duplicate_head.extend_from_slice(format!("{duplicate}: 1\r\n").as_bytes());
                assert!(
                    block(200, &duplicate_head, COMMAND, true).is_err(),
                    "duplicate {name}"
                );
            }
        }
        for bad in [
            "0",
            "00",
            "01",
            "+1",
            " 1",
            "1 ",
            "-1",
            "18446744073709551616",
        ] {
            assert!(
                block(200, &fields(bad, "2", COMMAND), COMMAND, true).is_err(),
                "instance {bad}"
            );
            assert!(
                block(200, &fields("37", bad, COMMAND), COMMAND, true).is_err(),
                "generation {bad}"
            );
        }
        for bad in ["", "L2FwcHJvdmVkL2NoaWxk", "////", "L2FwcHJvdmVkL2NoaWxk= "] {
            let head =
                format!("generation: 2\r\nprogram-instance: 37\r\nprogram-identity: {bad}\r\n");
            assert!(block(200, head.as_bytes(), COMMAND, true).is_err());
        }
        for tail in [b"broken".as_slice(), b"\r\n", b"x:y\r\n"] {
            let mut malformed = good.clone();
            malformed.extend_from_slice(tail);
            assert!(block(200, &malformed, COMMAND, true).is_err());
        }
    }

    #[test]
    fn legacy_generation_never_authenticates_rooted_stdio() {
        let fields = b"generation: 7\r\n";
        assert_eq!(
            block(200, fields, COMMAND, false).unwrap(),
            Observed {
                instance: 0,
                generation: 7
            }
        );
        assert!(block(200, fields, COMMAND, true).is_err());
        assert!(block(200, b"", COMMAND, true).is_err());
    }

    #[test]
    fn replacement_incarnation_and_respawn_never_reuse_a_cached_stamp() {
        let mut versions = Versions::default();
        let first = Observed {
            instance: 37,
            generation: 2,
        };
        let original = versions.stamp("server", first).unwrap();
        assert_eq!(versions.stamp("server", first).unwrap(), original);
        let respawn = versions
            .stamp(
                "server",
                Observed {
                    instance: 37,
                    generation: 3,
                },
            )
            .unwrap();
        assert_ne!(respawn, original);
        let replacement = versions
            .stamp(
                "server",
                Observed {
                    instance: 38,
                    generation: 1,
                },
            )
            .unwrap();
        assert_ne!(replacement, respawn);
        assert_ne!(replacement, original);
        assert_eq!(
            versions.observed("server", replacement),
            Some(Observed {
                instance: 38,
                generation: 1
            })
        );
        assert_eq!(versions.observed("server", original), None);
        assert_eq!(versions.observed("other", replacement), None);
        assert!(versions.stamp("server", first).is_err());
        assert!(versions
            .stamp(
                "server",
                Observed {
                    instance: 37,
                    generation: u64::MAX
                }
            )
            .is_err());
        assert_ne!(versions.stamp("other", first).unwrap(), original);
        assert_eq!(
            versions
                .stamp(
                    "server",
                    Observed {
                        instance: 38,
                        generation: 1
                    }
                )
                .unwrap(),
            replacement
        );
    }

    #[test]
    fn stamp_exhaustion_refuses_without_replacing_existing_identity() {
        let mut versions = Versions::default();
        let first = Observed {
            instance: 1,
            generation: 1,
        };
        let stamp = versions.stamp("server", first).unwrap();
        versions.next = u64::MAX;
        assert!(versions
            .stamp(
                "server",
                Observed {
                    instance: 2,
                    generation: 1
                }
            )
            .is_err());
        assert_eq!(versions.stamp("server", first).unwrap(), stamp);
        assert!(!versions.latest.contains_key("other"));
        assert!(versions.stamp("other", first).is_err());
        assert!(!versions.latest.contains_key("other"));
    }
    #[test]
    fn eager_body_guard_uses_only_the_current_checked_host_pair() {
        let observed = block(200, &fields("37", "2", COMMAND), COMMAND, true).unwrap();
        let mut versions = Versions::default();
        let checked = versions.stamp("server", observed).unwrap();
        assert_eq!(
            versions.expected_fields("server", checked).unwrap(),
            [
                ("program-expect-instance".to_string(), "37".to_string()),
                ("program-expect-generation".to_string(), "2".to_string()),
            ]
        );
        assert!(versions.expected_fields("other", checked).is_none());
        let new = versions
            .stamp(
                "server",
                Observed {
                    instance: 38,
                    generation: 1,
                },
            )
            .unwrap();
        assert!(versions.expected_fields("server", checked).is_none());
        assert_eq!(versions.expected_fields("server", new).unwrap()[0].1, "38");
        let legacy = versions
            .stamp(
                "legacy",
                Observed {
                    instance: 0,
                    generation: 7,
                },
            )
            .unwrap();
        assert!(versions.expected_fields("legacy", legacy).is_none());
    }
    #[test]
    fn persisted_child_stamp_cannot_alias_a_fresh_planes_stamp() {
        let mut old = Versions::default();
        let old_stamp = old
            .stamp(
                "server",
                Observed {
                    instance: 37,
                    generation: 1,
                },
            )
            .unwrap();
        let mut fresh = Versions::default();
        let new_stamp = fresh
            .stamp(
                "server",
                Observed {
                    instance: 38,
                    generation: 1,
                },
            )
            .unwrap();
        assert_eq!(
            old_stamp, new_stamp,
            "the adversarial fixture recreates the numeric stamp collision"
        );
        assert!(fresh
            .expected_child_fields("server", old_stamp, Some((37, 1)))
            .is_none());
        assert!(fresh
            .expected_child_fields("server", old_stamp, None)
            .is_none());
        assert!(fresh
            .expected_child_fields("server", new_stamp, Some((38, 1)))
            .is_some());
        let leg = crate::ask::ChildLeg {
            launch: Some((37, 1)),
            generation: old_stamp,
            wait: serde_json::json!(9),
            asks: vec![],
            work: None,
        };
        let decoded: crate::ask::ChildLeg =
            serde_json::from_slice(&serde_json::to_vec(&leg).unwrap()).unwrap();
        assert_eq!(decoded.launch, Some((37, 1)));
        assert!(fresh
            .expected_child_fields("server", decoded.generation, decoded.launch)
            .is_none());
    }
}
