use super::*;

struct PendingClose {
    calls: Mutex<Vec<u32>>,
}

impl ProgramConn for PendingClose {
    fn establish(
        &self,
        ticket: Ticket,
        seq: u32,
        need: u32,
        member: &str,
        timeout: u32,
    ) -> Poll<Result<u64, String>> {
        ChildConn.establish(ticket, seq, need, member, timeout)
    }
    fn read_reply(
        &self,
        ticket: Ticket,
        seq: u32,
        stream: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>> {
        ChildConn.read_reply(ticket, seq, stream, buf, slot)
    }
    fn write(
        &self,
        ticket: Ticket,
        seq: u32,
        stream: u64,
        bytes: &[u8],
    ) -> Poll<Result<usize, String>> {
        ChildConn.write(ticket, seq, stream, bytes)
    }
    fn close(&self, ticket: Ticket, seq: u32, stream: u64) -> Poll<()> {
        let mut calls = self.calls.lock().unwrap();
        calls.push(seq);
        if calls.len() <= 2 {
            Poll::Pending
        } else {
            ChildConn.close(ticket, seq, stream)
        }
    }
}

struct FailedService {
    failed_at: &'static str,
    seen: Mutex<Vec<(u32, &'static str)>>,
    headed: Mutex<bool>,
}

impl ProgramConn for FailedService {
    fn establish(&self, _: Ticket, seq: u32, _: u32, _: &str, _: u32) -> Poll<Result<u64, String>> {
        self.seen.lock().unwrap().push((seq, "establish"));
        Poll::Ready(Ok(1))
    }
    fn read_reply(
        &self,
        _: Ticket,
        seq: u32,
        _: u64,
        buf: &mut [u8],
        slot: &mut ReplyPiece,
    ) -> Poll<Result<Replied, String>> {
        let mut headed = self.headed.lock().unwrap();
        let op = if *headed { "read" } else { "head" };
        self.seen.lock().unwrap().push((seq, op));
        if op == self.failed_at {
            return Poll::Ready(Err(format!("failed {op}")));
        }
        *headed = true;
        let body = b"generation: 1\r\n";
        buf[..body.len()].copy_from_slice(body);
        *slot = ReplyPiece {
            kind: REPLY_HEAD,
            fields: FrameSpan {
                offset: 0,
                len: body.len() as u64,
            },
            ..ReplyPiece::default()
        };
        Poll::Ready(Ok(Replied {
            piece: *slot,
            len: body.len(),
        }))
    }
    fn write(&self, _: Ticket, seq: u32, _: u64, bytes: &[u8]) -> Poll<Result<usize, String>> {
        self.seen.lock().unwrap().push((seq, "write"));
        if self.failed_at == "write" {
            Poll::Ready(Err("failed write".into()))
        } else {
            Poll::Ready(Ok(bytes.len()))
        }
    }
    fn close(&self, _: Ticket, seq: u32, _: u64) -> Poll<()> {
        self.seen.lock().unwrap().push((seq, "close"));
        Poll::Ready(())
    }
}

#[test]
fn a_failed_service_and_its_close_have_distinct_handles() {
    for failed_at in ["head", "write", "read"] {
        let host = FailedService {
            failed_at,
            seen: Mutex::new(Vec::new()),
            headed: Mutex::new(false),
        };
        let mut exchange = ProgramExchange::new(
            "srv",
            0,
            vec![(
                br#"{"jsonrpc":"2.0","id":7,"method":"tools/list"}"#.to_vec(),
                Some(7),
            )],
            false,
        );
        let mut peer = Door::default();
        let answer = exchange.drive(
            &host,
            Ticket {
                slot: 2,
                generation: 3,
            },
            19,
            &|_| true,
            &mut peer,
        );
        assert!(
            matches!(answer, Poll::Ready(Err(ref why)) if why.contains(failed_at)),
            "{answer:?}"
        );
        let seen = host.seen.lock().unwrap();
        let failed = seen.iter().find(|(_, op)| *op == failed_at).unwrap().0;
        let closed = seen.iter().find(|(_, op)| *op == "close").unwrap().0;
        assert_ne!(failed, closed, "{failed_at}: {seen:?}");
    }
}

#[test]
fn an_exhausted_exchange_reserves_close_within_its_own_service_range() {
    let _one = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    reset(1, Vec::new());
    let host = PendingClose {
        calls: Mutex::new(Vec::new()),
    };
    let messages = (0..crate::tool_program::EXCHANGE_SERVICES)
        .map(|_| {
            (
                br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
                None,
            )
        })
        .collect();
    let mut exchange = ProgramExchange::new("srv", 0, messages, false);
    let mut peer = Door::default();
    let ticket = Ticket {
        slot: 3,
        generation: 5,
    };
    assert!(exchange
        .drive(&host, ticket, 23, &|_| true, &mut peer)
        .is_pending());
    assert!(exchange
        .drive(&host, ticket, 23, &|_| true, &mut peer)
        .is_pending());
    assert!(matches!(
        exchange.drive(&host, ticket, 23, &|_| true, &mut peer),
        Poll::Ready(Err(_))
    ));
    let calls = host.calls.lock().unwrap();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|seq| *seq == calls[0]));
    assert!(
        calls[0] < 23 + crate::tool_program::EXCHANGE_SERVICES,
        "CLOSE must not occupy the next exchange's ESTABLISH handle"
    );
}
