use super::*;

fn origin_arrival(d: &Door, unit: u64, origins: &[&[u8]]) -> Arrived {
    let mut fields = vec![
        Field {
            name: str_of("mcp-method"),
            value: str_of("tools/call"),
        },
        Field {
            name: str_of("mcp-name"),
            value: str_of("st_read_file"),
        },
        Field {
            name: str_of("mcp-protocol-version"),
            value: str_of("2026-07-28"),
        },
    ];
    for bytes in origins {
        // SAFETY: these owned fixture bytes remain live for the synchronous arrival.
        let value = unsafe { AbiStr::from_raw_parts(bytes.as_ptr(), bytes.len()) };
        fields.push(Field {
            name: str_of("Origin"),
            value,
        });
    }
    let mut input: ArriveIn = z();
    input.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
    input.unit = unit;
    input.claim = claim("POST");
    input.target = str_of("/mcp");
    input.method = str_of("POST");
    input.body = octets(ST_CALL);
    input.fields = fields.as_ptr();
    input.fields_len = fields.len();
    let mut units = [z::<UnitCount>(); 8];
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    let mut output: ArriveOut = z();
    output.head = out_head::<ArriveOut>();
    let result = ops().arrive.unwrap()(
        d.instance,
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut output).cast(),
    );
    Arrived {
        outcome: result.outcome(),
        refusal_status: output.refusal_status,
    }
}

#[test]
fn an_invalid_or_repeated_origin_is_not_an_absent_origin() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    for (unit, origins) in [
        (6000, vec![b"\xff".as_slice()]),
        (
            6001,
            vec![
                b"http://localhost".as_slice(),
                b"https://hostile.example".as_slice(),
            ],
        ),
        (
            6002,
            vec![
                b"http://localhost".as_slice(),
                b"http://localhost".as_slice(),
            ],
        ),
    ] {
        let result = origin_arrival(&d, unit, &origins);
        assert_eq!(
            (result.outcome, result.refusal_status),
            (Outcome::Refused, 403)
        );
    }
    assert_eq!(origin_arrival(&d, 6003, &[]).outcome, Outcome::Ready);
    assert_eq!(
        origin_arrival(&d, 6004, &[b"http://localhost"]).outcome,
        Outcome::Ready
    );
}
