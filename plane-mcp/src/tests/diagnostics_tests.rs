// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-plane diagnostics-catalog invariants for the MCP plane: code/slug uniqueness, the
//! class↔code thousands-digit contract, and the live-entry documentation floor. The committed
//! markdown/JSON snapshot tests render through the host's renderers, which this crate does not
//! link, so they run where those renderers are linked.

use super::*;

/// THE CATALOG IS NOT EMPTY, AND NOT ENTIRELY RETIRED.
///
/// Every other test in this file is a `for d in DIAGNOSTICS` loop whose assertions live INSIDE the
/// loop, and `every_live_entry_documents_meaning_and_action` additionally `continue`s past every
/// retired entry. A catalog that regressed to empty — a bad `cfg` gate, a botched merge — would
/// therefore make all four of them pass green while every documented diagnostic silently
/// disappeared. This is the floor that makes those loops mean something.
#[test]
fn the_catalog_is_not_empty() {
    assert!(
        !DIAGNOSTICS.is_empty(),
        "the diagnostics catalog is empty, which makes every loop test in this file vacuous"
    );
    assert!(
        DIAGNOSTICS.iter().any(|d| !d.retired),
        "the catalog holds nothing but retired entries, which makes \
         `every_live_entry_documents_meaning_and_action` vacuous"
    );
}

/// Codes are unique within this plane's catalog — a collision would make one un-resolvable.
#[test]
fn codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS {
        assert!(
            seen.insert(d.code),
            "duplicate code {} ({})",
            d.code,
            d.slug
        );
    }
}

/// The thousands digit of every code equals its class ordinal, and the x000 slot is reserved.
#[test]
fn code_thousands_digit_matches_class() {
    for d in DIAGNOSTICS {
        assert_eq!(
            d.code / 1000,
            d.class.ordinal(),
            "{} ({}) class/code mismatch",
            d.banner(),
            d.slug
        );
        assert!(
            d.code % 1000 != 0,
            "{} ({}) uses the reserved x000 slot",
            d.banner(),
            d.slug
        );
    }
}

/// Slugs are unique, non-empty, kebab-case — they are stable doc anchors and URL fragments.
#[test]
fn slugs_are_unique_and_kebab_case() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS {
        assert!(
            seen.insert(d.slug),
            "duplicate slug {:?} (code {})",
            d.slug,
            d.code
        );
        assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
        assert!(
            d.slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "slug {:?} (code {}) is not kebab-case",
            d.slug,
            d.code
        );
        assert!(
            !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
            "slug {:?} (code {}) has a leading/trailing/double hyphen",
            d.slug,
            d.code
        );
    }
}

/// Every non-retired entry documents its meaning and an action.
#[test]
fn every_live_entry_documents_meaning_and_action() {
    for d in DIAGNOSTICS {
        if d.retired {
            continue;
        }
        assert!(
            d.summary.len() > 20,
            "{} ({}) has no real summary",
            d.banner(),
            d.slug
        );
        assert!(
            d.action.len() > 3,
            "{} ({}) has no action",
            d.banner(),
            d.slug
        );
    }
}

/// THE PLANE'S `declares.json` IS ITS CATALOG: the static declared metadata the root reads for this
/// linked plugin (its `declares` section: every code this plane raises) states exactly the entries
/// [`DIAGNOSTICS`] holds, field for field, so the two cannot drift — and the plane's breaker fact.
#[test]
fn the_declares_file_states_the_catalog() {
    let declared: serde_json::Value =
        serde_json::from_str(crate::DECLARES).expect("declares.json is JSON");
    let want: Vec<serde_json::Value> = DIAGNOSTICS
        .iter()
        .map(|d| {
            serde_json::json!({
                "code": d.code,
                "slug": d.slug,
                "title": d.title,
                "severity": d.severity.as_str(),
                "summary": d.summary,
                "action": d.action,
                "since": d.since,
            })
        })
        .collect();
    // Beside the catalog, the plane's one breaker fact (ARCHITECT Q4): a transient failure below
    // the trip threshold never benches a member (the posture ruled for this plane); and the
    // carriers it needs, which the one document states for the dropped-in manifest too.
    let whole = serde_json::json!({
        "breaker": { "bench_below_trip_threshold": false },
        "diagnostics": want,
        "needs": ["http", "stdio"],
    });
    assert_eq!(
        declared,
        whole,
        "declares.json drifted from the catalog; expected:\n{}",
        serde_json::to_string_pretty(&whole).unwrap()
    );
}

/// THE DECLARED CODES ARE THE RAISED CODES: every diagnostic the door can raise is one of its
/// Statement's diagnostic ids (`out.diag` indexes them), each spelled `BUSBAR-NNNN` so the host's
/// log resolves its catalog entry, and the set of those codes equals the set `declares.json`
/// states. A declared code nothing raises, or a raised one nothing declares, fails here; so does a
/// retired entry.
#[test]
fn the_declared_codes_are_exactly_the_raised_codes() {
    let names = crate::tool_door::DIAG_NAMES;
    assert_eq!(
        crate::tool_door::DIAG_IDS_LEN,
        names.len(),
        "every diagnostic id the Statement states is a named one"
    );
    let raised: std::collections::BTreeSet<u16> = names
        .iter()
        .map(|name| {
            name.strip_prefix("BUSBAR-")
                .and_then(|n| n.parse::<u16>().ok())
                .unwrap_or_else(|| panic!("the raised diagnostic `{name}` names no catalog code"))
        })
        .collect();
    let declared: serde_json::Value =
        serde_json::from_str(crate::DECLARES).expect("declares.json is JSON");
    let declared: std::collections::BTreeSet<u16> = declared["diagnostics"]
        .as_array()
        .expect("declares.json states its diagnostics")
        .iter()
        .map(|d| {
            u16::try_from(d["code"].as_u64().expect("a declared code is a number"))
                .expect("a declared code fits a u16")
        })
        .collect();
    assert_eq!(
        raised, declared,
        "declares.json states other codes than the door raises"
    );
    assert!(
        DIAGNOSTICS.iter().all(|d| !d.retired),
        "a retired code is declared"
    );
}

/// NO DECLARED CODE IS ONE THE CORE'S CATALOGUE HOLDS: the core at `.busbar-ref`
/// (`BUSBAR_CHECKOUT`, `crates/busbar-kernel/src/diagnostics/catalog.toml`) refuses a plane that
/// declares a code its catalogue already holds ("plugin 'busbar-plane-mcp' declares BUSBAR-NNNN:
/// the catalogue already holds that code"), linked or dropped in, so a collision is a busbar that
/// does not boot. An unset variable is a failure, never a skip.
#[test]
fn no_declared_code_is_one_the_core_catalogue_holds() {
    let busbar = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the core catalogue is busbar's at .busbar-ref (plugin-ci exports it)",
    );
    let path =
        std::path::PathBuf::from(busbar).join("crates/busbar-kernel/src/diagnostics/catalog.toml");
    let catalog = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the core catalogue at {}: {e}", path.display()));
    let held: std::collections::BTreeSet<u16> = catalog
        .lines()
        .filter_map(|l| l.trim().strip_prefix("code"))
        .filter_map(|rest| rest.trim().strip_prefix('='))
        .filter_map(|n| n.trim().parse().ok())
        .collect();
    assert!(
        !held.is_empty(),
        "no `code = N` row read from {}",
        path.display()
    );
    for d in DIAGNOSTICS {
        assert!(
            !held.contains(&d.code),
            "BUSBAR-{:04} ({}) is a code the core catalogue at {} already holds",
            d.code,
            d.slug,
            path.display()
        );
    }
}
