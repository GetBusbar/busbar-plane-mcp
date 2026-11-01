use super::*;
use std::sync::atomic::AtomicBool;

static LIVE: AtomicBool = AtomicBool::new(true);
pub(super) fn entitlement() -> u64 {
    if LIVE.load(Ordering::SeqCst) {
        ENTITLED
    } else {
        0
    }
}
struct Revoked;
impl Revoked {
    fn now() -> Self {
        LIVE.store(false, Ordering::SeqCst);
        Self
    }
}
impl Drop for Revoked {
    fn drop(&mut self) {
        LIVE.store(true, Ordering::SeqCst);
    }
}

#[test]
fn a_held_get_stream_ends_when_its_unit_can_no_longer_reconfirm_standing() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let session = initialize(&d, 600, ALICE)
        .field("mcp-session-id")
        .unwrap()
        .to_string();
    let fields = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        d.arrive(601, "GET", "/mcp", b"", &fields).outcome,
        Outcome::Ready
    );
    assert_eq!(d.piece(601, &Given::stream_open(ALICE, 601)).status, 200);
    d.turn();
    let live = d.piece(601, &Given::collect(ALICE, 601));
    assert_eq!(
        live.outcome,
        Some(Outcome::Ready),
        "the positive standing control is collectable"
    );
    assert!(!live.done, "the positive standing control remains open");
    let _revoked = Revoked::now();
    d.turn();
    let ended = d.piece(601, &Given::collect(ALICE, 601));
    assert_eq!(ended.outcome, Some(Outcome::Ready));
    assert!(
        ended.done,
        "revoked standing closes the held GET before another buffered event is sent"
    );
}
