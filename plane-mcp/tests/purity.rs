//! The plane is pure, and this is what says so.

#[path = "support/source_scan.rs"]
mod source_scan;

use source_scan::{sibling_plane_crates, src_dir, walk_surface};

/// A line that is only a comment says nothing about what the code does.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// The plane keeps no state of its own between calls.
#[test]
fn the_plane_holds_no_interior_state() {
    let forbidden = [
        "Cell<",
        "RefCell",
        "UnsafeCell",
        "Mutex<",
        "RwLock",
        "AtomicUsize",
        "AtomicU64",
        "AtomicU32",
        "AtomicBool",
        "OnceLock",
        "OnceCell",
        "LazyLock",
        "lazy_static",
        "thread_local",
        "static mut",
    ];
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane holds interior state: {offenders:?}"
    );
}

/// The plane performs no input and no output.
#[test]
fn the_plane_performs_no_input_or_output() {
    let forbidden = [
        "std::fs",
        "std::net",
        "std::process",
        "std::thread",
        "std::io",
        "SystemTime",
        "Instant::now",
        "tokio",
        "reqwest",
        "async fn",
        "await",
        "env!",
        "std::env",
        "println!",
        "eprintln!",
    ];
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane reaches outside itself: {offenders:?}"
    );
}

/// The plane names no kernel-side crate.
#[test]
fn the_plane_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
        "busbar_kernel",
    ];

    let siblings: Vec<String> = sibling_plane_crates()
        .into_iter()
        .map(|name| name.replace('-', "_"))
        .collect();
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
            for sibling in &siblings {
                if line.contains(sibling.as_str()) {
                    offenders.push(format!("{}:{}: {sibling}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names kernel-side crates: {offenders:?}"
    );
}

/// The plane never hands back a decision, an amount or a credential.
#[test]
fn the_plane_names_no_money_and_no_decision() {
    let forbidden = [
        "nano_units",
        "nanounits",
        "unit_price",
        "price_micros",
        "charge(",
        "admit_decision",
        "allow(",
        "deny(",
        "credential_bytes",
        "secret_value",
        "bearer_token",
    ];
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }

            let t = line.trim_start();
            if t.starts_with("#[") || t.starts_with("#![") {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names money or decisions: {offenders:?}"
    );
}

/// The plane satisfies no upstream's ask (Law 11, BUSBAR-1.6.0 lines 2127-2132: busbar "answers
#[test]
fn the_plane_satisfies_no_upstream_ask() {
    let forbidden = ["may_satisfy", "InputRequiredLoop"];
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane carries a satisfier of an upstream's ask: {offenders:?}"
    );
}

/// No code in this crate routes a call to another plane, and none implements the unserved plane
#[test]
fn no_code_routes_a_call_to_another_plane_or_implements_the_unserved_plane_traits() {
    let forbidden = [
        "NestedPlane",
        "SAMPLING_OP",
        "impl Plane for",
        "impl SessionPlane for",
    ];
    let mut offenders = Vec::new();
    walk_surface(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the crate carries the struck cross-plane route or a plane impl nothing serves: {offenders:?}"
    );
}
