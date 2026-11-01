// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use busbar_contract::abi::mechanism::call::{Blob, OutHead};
use busbar_contract::abi::mechanism::extensions;

pub const RESUME: u32 = busbar_contract::abi::mechanism::call::FLAG_RESUME;

pub fn input(epoch: u64, receipt: Option<&[u8]>) -> Vec<u8> {
    let mut capability = vec![1];
    capability.extend_from_slice(&epoch.to_le_bytes());
    let mut entries = vec![("host_inspection_v1", capability.as_slice())];
    if let Some(receipt) = receipt {
        entries.push(("host_inspection_reply_v1", receipt));
    }
    extensions::encode(&entries)
}

pub fn bytes(blob: Blob) -> Vec<u8> {
    if blob.ptr.is_null() || blob.len == 0 {
        return Vec::new();
    }
    // SAFETY: test callers copy a host/plugin blob while its crossing or output lease is live.
    unsafe { std::slice::from_raw_parts(blob.ptr, blob.len).to_vec() }
}

pub fn request(head: &OutHead) -> Option<Vec<u8>> {
    extensions::get(&bytes(head.extensions), "host_inspection_request_v1").map(<[u8]>::to_vec)
}

pub fn reference(request: &[u8]) -> Option<&[u8]> {
    if request.first() != Some(&1) || request.get(25) != Some(&1) {
        return None;
    }
    let n = u32::from_le_bytes(request.get(26..30)?.try_into().ok()?) as usize;
    let reference = request.get(30..30 + n)?;
    (request.len() == 30 + n).then_some(reference)
}

pub fn sessions(request: &[u8]) -> Option<Vec<u64>> {
    if request.first() != Some(&1) || request.get(25) != Some(&2) {
        return None;
    }
    let n = u32::from_le_bytes(request.get(26..30)?.try_into().ok()?) as usize;
    if request.len() != 30 + n * 8 {
        return None;
    }
    Some(
        request[30..]
            .chunks_exact(8)
            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
            .collect(),
    )
}

fn receipt(request: &[u8], status: u8) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&(request.len() as u32).to_le_bytes());
    out.extend_from_slice(request);
    out.push(status);
    out
}

pub fn failed(request: &[u8], status: u8) -> Vec<u8> {
    receipt(request, status)
}

pub fn work(
    request: &[u8],
    observed: u64,
    opened: u64,
    retain: u64,
    settled: Option<u64>,
) -> Vec<u8> {
    assert!(reference(request).is_some());
    let mut out = receipt(request, 0);
    for n in [observed, opened, retain] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.push(u8::from(settled.is_some()));
    if let Some(settled) = settled {
        out.extend_from_slice(&settled.to_le_bytes());
    }
    out
}

pub fn carriers(request: &[u8], live: impl Fn(u64) -> bool) -> Vec<u8> {
    let sessions = sessions(request).expect("a carrier query");
    let mut out = receipt(request, 0);
    out.extend_from_slice(&(sessions.len() as u32).to_le_bytes());
    for session in sessions {
        out.extend_from_slice(&session.to_le_bytes());
        out.push(u8::from(live(session)));
    }
    out
}

pub fn release(
    instance: *mut std::ffi::c_void,
    head: &OutHead,
    ops: &busbar_contract::abi::mechanism::lifecycle::OpsHead,
) {
    use busbar_contract::abi::mechanism::call::{InHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot, ReleaseIn};
    if head.lease == 0 {
        return;
    }
    // SAFETY: both ABI heads are plain C data with a valid all-zero empty declaration.
    let (mut input_head, mut out): (InHead, OutHead) = unsafe { std::mem::zeroed() };
    input_head.size = std::mem::size_of::<ReleaseIn>() as u32;
    input_head.op = slot::RELEASE;
    out.size = std::mem::size_of::<OutHead>() as u32;
    let input = ReleaseIn {
        head: input_head,
        lease: head.lease,
    };
    // SAFETY: the test's live door and the lifecycle's exact RELEASE input/output types.
    let ret = ops.release.unwrap()(
        instance,
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(ret.outcome(), Outcome::Ready);
}
