use super::*;

#[test]
fn a_legacy_event_stream_accepts_case_insensitive_media_types() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams {
        legacy_media_type: Some("Text/Event-Stream; charset=utf-8".into()),
        ..Default::default()
    });
    let d = open_with(LEGACY_SECTION);
    assert_eq!(view_of(&d.connect(903, "lg")), (Value::Null, json!(1)));
}

#[test]
fn a_new_call_after_eof_does_not_erase_an_already_completed_legacy_answer() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams {
        hold_calls: true,
        ..Upstreams::default()
    });
    let d = open_with(LEGACY_SECTION);
    let (body, fields) = legacy_call(901, "completed.txt");
    relayed(&d, 901, ALICE, &body, &fields);
    let mut session = None;
    for _ in 0..32 {
        let waiting = d.piece(901, &walk_refused(ALICE));
        assert_eq!(waiting.outcome, Some(Outcome::Pending));
        d.turn();
        let ready = {
            let ups = upstreams();
            ups.as_ref().and_then(|u| {
                u.open
                    .values()
                    .filter_map(|w| w.sse.as_ref())
                    .find(|s| !s.held.is_empty())
                    .map(|s| s.session.clone())
            })
        };
        if ready.is_some() {
            session = ready;
            break;
        }
    }
    let session = session.expect("the actual tool call reached the held legacy stream");
    on_stream(&session, |s| {
        s.events.extend(s.held.drain(..));
        s.closed = true;
    });
    upstreams().as_mut().unwrap().hold_calls = false;
    d.turn();
    let (next, next_fields) = legacy_call(902, "next.txt");
    relayed(&d, 902, ALICE, &next, &next_fields);
    let entering = d.piece(902, &walk_refused(ALICE));
    assert_eq!(entering.outcome, Some(Outcome::Pending));
    let old = d.pump(901, &walk_refused(ALICE));
    assert_eq!(
        legacy_text(&old),
        (json!(901), "legacy completed.txt".into())
    );
    let next = d.pump(902, &walk_refused(ALICE));
    assert_eq!(legacy_text(&next), (json!(902), "legacy next.txt".into()));
}
