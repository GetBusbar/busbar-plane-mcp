// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host launch receipts: the canonical receipt, its exact fields, and the checked stamps.

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
            let original = text
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}: ")))
                .unwrap();
            duplicate_head.extend_from_slice(format!("{duplicate}: {original}\r\n").as_bytes());
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
        let head = format!("generation: 2\r\nprogram-instance: 37\r\nprogram-identity: {bad}\r\n");
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

#[test]
fn persisted_child_generation_cannot_alias_the_same_instances_new_generation() {
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
    let stamp = fresh
        .stamp(
            "server",
            Observed {
                instance: 37,
                generation: 2,
            },
        )
        .unwrap();
    assert_eq!(old_stamp, stamp);
    assert!(fresh
        .expected_child_fields("server", old_stamp, Some((37, 1)))
        .is_none());
    assert!(fresh
        .expected_child_fields("server", stamp, Some((37, 2)))
        .is_some());
}
