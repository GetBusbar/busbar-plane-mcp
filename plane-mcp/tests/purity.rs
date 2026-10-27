//! The plane is pure, and this is what says so.
//!
//! A plane is pure over its inputs and performs no input or output of its own. The source is walked
//! for the shapes that would make either claim false. A comment claiming purity is worth nothing; a
//! scan is worth something. (The repeat-the-call determinism tests drove the unserved `Plane` impl
//! and were retired with it, finding 12.)

#[path = "support/source_scan.rs"]
mod source_scan;

use source_scan::{sibling_plane_crates, src_dir, walk_surface};

/// A line that is only a comment says nothing about what the code does.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("*") || t.starts_with("/*")
}

/// The plane keeps no state of its own between calls.
///
/// The only place cross-frame codec state may live is the kernel-held per-connection state, which
/// the kernel hands in and takes back. A plane holding a cell, a lock, an atomic or a global is a
/// plane that could answer differently the second time for a reason no caller can see.
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
///
/// Not a socket, not a file, not a process, not a thread, not a system clock. The one clock a plane
/// may read is the one the context hands it, which is why the system clock is on this list.
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
///
/// The manifest allow-list is the real control; this is the same rule asserted from the inside, so a
/// reach for the kernel is a red here rather than a discovery at packaging time.
#[test]
fn the_plane_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_substrate",
        "busbar_kernel",
    ];
    // Each sibling's module path: its directory name, underscore-spelled.
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
///
/// This is a source scan for the words a plane must not be able to say. It is coarse on purpose: a
/// plane that has started reasoning about money will name money.
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
            // A lint attribute is an instruction to the compiler, not a decision about a
            // request. It is the one shape here whose words overlap with the forbidden ones.
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
/// nothing on the caller's behalf"; a code path that answers what a response asks for "is deleted,
/// never added").
///
/// An upstream's sampling, elicitation or roots ask is relayed to the caller, who answers it. The
/// satisfier vocabulary — a per-dispatch loop that decided whether BUSBAR may satisfy an ask and
/// counted the rounds it satisfied — is the shape of the other answer, and it does not come back,
/// in production code or in a test that keeps it alive.
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
/// traits (finding 12; BUSBAR-1.6.0.md Law 11 "routes no call to another plane on the content's
/// say-so", and "a capability that is never constructed does not ship").
///
/// The door is the only thing this crate serves. A destination that opens a child unit of ANOTHER
/// plane (`NestedPlane`), the operation class a sampling ask was answered as (`SAMPLING_OP`), and a
/// `Plane`/`SessionPlane` impl nothing constructs are the struck route and the dead machinery that
/// carried it. This is a source scan, the pure-deletion plant: it fails while any of them exists.
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
