use std::collections::VecDeque;

use crate::local_renderer::Local;

/// Called only after the existing history quota admits this encoded length. Retained history
pub(super) fn buffered(mut local: Local) -> Result<String, ()> {
    let length = local.len();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(|_| ())?;
    local.write_with(|piece| {
        let accepted = piece.len().min(length - bytes.len());
        bytes.extend_from_slice(&piece[..accepted]);
        accepted
    });
    if !local.done() || bytes.len() != length {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

#[derive(Clone, Debug)]
enum Part {
    Bytes { bytes: Vec<u8>, sent: usize },
    Local(Local),
}

/// An answer's small framing pieces and its input-backed JSON cursor, written under the host's
/// existing output backpressure. No segment materializes a rendered local answer.
#[derive(Clone, Debug, Default)]
pub(super) struct Output {
    parts: VecDeque<Part>,
}

impl Output {
    pub(super) fn take_json(&mut self) -> Option<Local> {
        if self.parts.len() != 1 {
            return None;
        }
        match self.parts.pop_front()? {
            Part::Local(local) => Some(local),
            part => {
                self.parts.push_front(part);
                None
            }
        }
    }
    pub(super) fn json(local: Local) -> Self {
        let mut output = Self::default();
        output.parts.push_back(Part::Local(local));
        output
    }

    pub(super) fn bytes(&mut self, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            self.parts.push_back(Part::Bytes { bytes, sent: 0 });
        }
    }

    pub(super) fn event(&mut self, local: Local, id: Option<&str>) {
        let mut prefix = b"event: message\n".to_vec();
        if let Some(id) = id {
            prefix.extend_from_slice(b"id: ");
            prefix.extend_from_slice(id.as_bytes());
            prefix.push(b'\n');
        }
        prefix.extend_from_slice(b"data: ");
        self.bytes(prefix);
        self.parts.push_back(Part::Local(local));
        self.bytes(b"\n\n".to_vec());
    }

    pub(super) fn done(&self) -> bool {
        self.parts.is_empty()
    }

    pub(super) fn write_with(&mut self, mut emit: impl FnMut(&[u8]) -> usize) -> usize {
        let mut written = 0;
        while let Some(part) = self.parts.front_mut() {
            let (n, done) = match part {
                Part::Bytes { bytes, sent } => {
                    let n = emit(&bytes[*sent..]);
                    *sent += n;
                    (n, *sent == bytes.len())
                }
                Part::Local(local) => {
                    let n = local.write_with(&mut emit);
                    (n, local.done())
                }
            };
            written += n;
            if done {
                self.parts.pop_front();
            } else {
                break;
            }
        }
        written
    }
}
