// SPDX-License-Identifier: Apache-2.0
//! Malformed admissions made by changing only metadata on this real MCP product.
use super::plugin_path as cdylib;
use busbar_plugin_loader::dispatch::{Bind, ConnTable, Kind, NoSink, Plugin};
use std::sync::Arc;
#[derive(Clone, Copy)]
enum Door {
    Linked,
    Dropped,
}
fn bind(d: &Dispatcher) -> Bind {
    Bind {
        instance: Arc::from("mcp-admission"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Probe,
    }
}
fn load<K: Kind>(by: Door, d: &Dispatcher) -> Result<Plugin<K>, LoadError> {
    let row = LinkedRow::of(busbar_plane_mcp::door)?;
    match by {
        Door::Linked => load_linked(&row, bind(d)),
        Door::Dropped => load_dropped(&cdylib(), &row.statement, bind(d)),
    }
}
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{Door as AbiDoor, DoorParts, Statement};
use busbar_contract::abi::mechanism::KindCode;
use busbar_plugin_loader::dispatch::kinds::{
    auth::Auth, export::Export, hook::Hook, plane::Plane, secret::Secret, store::Store,
    transport::Transport,
};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of, DispatchConfig, Dispatcher, LinkedRow, LoadError,
};
use std::sync::atomic::{AtomicPtr, Ordering};

static METADATA: std::sync::Mutex<()> = std::sync::Mutex::new(());
static RESTATED: AtomicPtr<AbiDoor> = AtomicPtr::new(std::ptr::null_mut());
extern "C" fn malformed() -> *const AbiDoor {
    RESTATED.load(Ordering::SeqCst)
}
fn real() -> DoorParts {
    // SAFETY: the shipped macro door owns a complete immutable static descriptor.
    unsafe { AbiDoor::read_parts(busbar_plane_mcp::door()) }
}
fn restate(parts: DoorParts) {
    // SAFETY: all pointers remain those of the actual product or leaked immutable test metadata.
    let door = unsafe { AbiDoor::__from_parts(parts) };
    RESTATED.store(Box::into_raw(Box::new(door)), Ordering::SeqCst);
}

#[test]
fn incompatible_abi_layout_and_statement_metadata_are_refused() {
    let _lock = METADATA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let d = Dispatcher::new(DispatchConfig::default());
    let honest = rendering_of(busbar_plane_mcp::door).unwrap();
    for by in [Door::Linked, Door::Dropped] {
        load::<Plane>(by, &d).expect("honest MCP loads");
    }
    let host = KindCode::Plane.abi_version();
    assert_eq!(real().kind_abi, host);
    for abi in [host + 1, host.wrapping_sub(1)] {
        restate(DoorParts {
            kind_abi: abi,
            ..real()
        });
        let want = LoadError::KindAbi {
            kind: KindCode::Plane,
            door: abi,
            host,
        };
        let err = LinkedRow::of_raw(malformed).unwrap_err();
        assert_eq!(err, want);
        assert!(err.to_string().contains("rebuild"));
        let mut stated = honest.clone();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        stated[at..at + 4].copy_from_slice(&abi.to_le_bytes());
        assert_eq!(
            load_dropped::<Plane>(&cdylib(), &stated, bind(&d))
                .map(|_| ())
                .unwrap_err(),
            LoadError::ManifestKindAbi { stated: abi, host }
        );
    }
    let host = KindCode::Plane.layout_fingerprint();
    assert_eq!(real().layout, host);
    for layout in [host ^ 1, 0] {
        restate(DoorParts { layout, ..real() });
        let err = LinkedRow::of_raw(malformed).unwrap_err();
        let LoadError::KindLayout {
            kind,
            stated,
            host: read,
            ..
        } = &err
        else {
            panic!("{err:?}")
        };
        assert_eq!((*kind, *stated, *read), (KindCode::Plane, layout, host));
        assert!(err
            .to_string()
            .contains("rebuild against this busbar-contract"));
        let row = LinkedRow {
            statement: honest.clone(),
            door: malformed,
        };
        assert_eq!(
            load_linked::<Plane>(&row, bind(&d))
                .map(|_| ())
                .unwrap_err(),
            err
        );
    }
    let original = real();
    // SAFETY: read the real descriptor's static Statement without changing any backing data.
    let st = unsafe { original.statement.read_unaligned() };
    const VERSION: &str = "0.0.0-conformance-restated";
    let st = Box::leak(Box::new(Statement {
        version: AbiStr {
            ptr: VERSION.as_ptr(),
            len: VERSION.len(),
        },
        ..st
    }));
    restate(DoorParts {
        statement: st,
        ..original
    });
    let lying = LinkedRow::of_raw(malformed).unwrap().statement;
    busbar_contract::abi::mechanism::rendering::read(&lying).unwrap();
    assert_ne!(lying, honest);
    let mut row = LinkedRow::of(busbar_plane_mcp::door).unwrap();
    row.statement = lying.clone();
    assert_eq!(
        load_linked::<Plane>(&row, bind(&d))
            .map(|_| ())
            .unwrap_err(),
        LoadError::StatementMismatch
    );
    assert_eq!(
        load_dropped::<Plane>(&cdylib(), &lying, bind(&d))
            .map(|_| ())
            .unwrap_err(),
        LoadError::StatementMismatch
    );
    let row = LinkedRow {
        statement: honest,
        door: malformed,
    };
    assert_eq!(
        load_linked::<Plane>(&row, bind(&d))
            .map(|_| ())
            .unwrap_err(),
        LoadError::StatementMismatch
    );
}

fn wrong_kind<K: busbar_plugin_loader::dispatch::Kind>() {
    let d = Dispatcher::new(DispatchConfig::default());
    for by in [Door::Linked, Door::Dropped] {
        assert_eq!(
            load::<K>(by, &d).map(|_| ()).unwrap_err(),
            LoadError::ManifestKind {
                stated: KindCode::Plane,
                want: K::CODE
            }
        );
    }
}
#[test]
fn the_actual_mcp_plane_refuses_every_other_kind_through_both_doors() {
    wrong_kind::<Auth>();
    wrong_kind::<Secret>();
    wrong_kind::<Hook>();
    wrong_kind::<Export>();
    wrong_kind::<Store>();
    wrong_kind::<Transport>();
}

#[test]
fn the_actual_mcp_serving_door_requires_a_connection_table_through_both_origins() {
    let d = Dispatcher::new(DispatchConfig::default());
    let row = LinkedRow::of(busbar_plane_mcp::door).unwrap();
    let statement = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
    let needs = statement.needs.len();
    assert!(needs > 0, "actual MCP declares its network/process needs");
    for by in [Door::Linked, Door::Dropped] {
        let bound = Bind {
            conns: ConnTable::NoNeeds,
            ..bind(&d)
        };
        let err = match by {
            Door::Linked => load_linked::<Plane>(&row, bound),
            Door::Dropped => load_dropped::<Plane>(&cdylib(), &row.statement, bound),
        }
        .map(|_| ())
        .unwrap_err();
        assert_eq!(
            err,
            LoadError::NoConnectionTable {
                plugin: statement.name.clone(),
                needs
            }
        );
        assert!(err
            .to_string()
            .contains(&format!("plugin '{}'", statement.name)));
        load::<Plane>(by, &d).expect("actual MCP binds as a probe without a serving table");
    }
}
#[test]
fn a_mcp_plane_with_another_answer_layout_is_refused() {
    use busbar_contract::abi::mechanism::door::KindTailHead;
    use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
    let _lock = METADATA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let real = real();
    let st = unsafe { real.statement.read_unaligned() };
    let tail = unsafe { st.kind_tail.cast::<PlaneTail>().read_unaligned() };
    assert_eq!(tail.answer_layout, ANSWER_LAYOUT);
    let d = Dispatcher::new(DispatchConfig::default());
    for by in [Door::Linked, Door::Dropped] {
        load::<Plane>(by, &d).expect("honest MCP plane loads");
    }
    for layout in [ANSWER_LAYOUT - 1, ANSWER_LAYOUT ^ 1, 0] {
        let tail = Box::leak(Box::new(PlaneTail {
            answer_layout: layout,
            ..tail
        }));
        let st = Box::leak(Box::new(Statement {
            kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
            ..st
        }));
        restate(DoorParts {
            statement: st,
            ..real
        });
        let err = LinkedRow::of_raw(malformed).unwrap_err();
        let LoadError::PlaneLayout { stated, host, .. } = &err else {
            panic!("{err}")
        };
        assert_eq!((*stated, *host), (layout, ANSWER_LAYOUT));
        assert!(
            err.to_string()
                .contains("rebuild against this busbar-contract"),
            "{err}"
        );
        let linked = LinkedRow::of_raw(malformed)
            .and_then(|row| load_linked::<Plane>(&row, bind(&d)).map(|_| ()))
            .unwrap_err();
        assert_eq!(linked, err);
    }
}
static READY_CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
const READY_FAILURE: &str = "conformance: discovery refused";
extern "C" fn failing_ready(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, RawOutcome};
    READY_CALLS.fetch_add(1, Ordering::SeqCst);
    let failed = RawOutcome::of(Outcome::Failed);
    unsafe {
        let out = &mut *out.cast::<OutHead>();
        out.outcome = failed;
        out.error = AbiStr {
            ptr: READY_FAILURE.as_ptr(),
            len: READY_FAILURE.len(),
        };
    }
    failed
}
#[test]
fn failing_mcp_readiness_is_not_retried_and_preserves_its_exact_error() {
    use busbar_contract::abi::mechanism::call::{Blob, Outcome};
    use busbar_contract::abi::plane::{PlaneOpenIn, PlaneOpenOut};
    use busbar_plugin_loader::dispatch::{in_head, out_head, Frame};
    let _lock = METADATA
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    READY_CALLS.store(0, Ordering::SeqCst);
    restate(DoorParts {
        size: std::mem::size_of::<AbiDoor>() as u32,
        ready: Some(failing_ready),
        ..real()
    });
    let d = Dispatcher::new(DispatchConfig::default());
    let p = load_linked::<Plane>(&LinkedRow::of_raw(malformed).unwrap(), bind(&d)).unwrap();
    assert!(p.has_ready());
    let cfg: serde_json::Value = serde_json::from_str(super::inputs()).unwrap();
    let settings = serde_json::to_vec(&cfg["settings"]).unwrap();
    let mut i: PlaneOpenIn = unsafe { std::mem::zeroed() };
    i.open.head = in_head();
    i.open.generation = 1;
    // The settings allocation remains alive through this synchronous OPEN call.
    i.open.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
        flags: 0,
    };
    let mut o: PlaneOpenOut = unsafe { std::mem::zeroed() };
    o.open.head = out_head();
    assert_eq!(p.open(&mut Frame::new(i, o)).0.outcome, Outcome::Ready);
    let before = p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst);
    let error = p.ready(&d, std::time::Duration::from_secs(30)).unwrap_err();
    assert_eq!(
        error,
        format!("plugin '{}' ready failed: {READY_FAILURE}", p.name())
    );
    assert_eq!(READY_CALLS.load(Ordering::SeqCst), 1);
    assert_eq!(
        p.inner.crossings.load(Ordering::SeqCst) - p.inner.resumes.load(Ordering::SeqCst) - before,
        1
    );
    let mut close = Frame::new(in_head(), out_head());
    assert_eq!(
        p.call(
            busbar_contract::abi::mechanism::lifecycle::slot::CLOSE,
            &mut close
        )
        .outcome,
        Outcome::Ready
    );
}
