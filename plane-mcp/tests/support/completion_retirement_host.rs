use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpsHead, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::sdk::completion_retirement::{self as wire, Capability};

pub struct Host {
    capability: Capability,
}

impl Host {
    pub fn new(owner: HostCtx, ticket: Ticket) -> Self {
        Self {
            capability: Capability {
                owner,
                ticket,
                epoch: 1,
                nonce: 1,
                acknowledged: [0; 32],
            },
        }
    }

    pub fn input(&self) -> Vec<u8> {
        wire::append_capability(&[], self.capability).unwrap()
    }

    pub fn acknowledge(&mut self, head: &OutHead) -> Vec<u32> {
        let Some(ack) = wire::read_ack(&bytes(head.extensions)).unwrap() else {
            return Vec::new();
        };
        assert_eq!(
            ack.capability, self.capability,
            "the host accepts only its exact current token"
        );
        // Host services and connector operations share the driver's sequence namespace.
        self.capability.nonce = self.capability.nonce.checked_add(1).unwrap();
        self.capability.acknowledged = wire::ack_digest(&ack).unwrap();
        ack.handles.into_iter().map(|handle| handle.seq).collect()
    }
}

fn bytes(blob: Blob) -> Vec<u8> {
    if blob.len == 0 {
        return Vec::new();
    }
    // SAFETY: the fixture copies this output while the SDK's answer lease is live.
    unsafe { std::slice::from_raw_parts(blob.ptr, blob.len).to_vec() }
}

pub fn release(instance: *mut std::ffi::c_void, head: &OutHead, ops: &OpsHead) {
    if head.lease == 0 {
        return;
    }
    // SAFETY: these C heads have a valid all-zero empty declaration.
    let (mut input, mut output): (ReleaseIn, OutHead) = unsafe { std::mem::zeroed() };
    input.head = InHead {
        size: std::mem::size_of::<ReleaseIn>() as u32,
        op: slot::RELEASE,
        ..input.head
    };
    input.lease = head.lease;
    output.size = std::mem::size_of::<OutHead>() as u32;
    // SAFETY: The caller proves the live instance and outstanding lease; these RELEASE frames have the exact declared layouts and remain live.
    let answer = unsafe {
        ops.release.unwrap()(
            instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut output).cast(),
        )
    };
    assert_eq!(answer.outcome(), Outcome::Ready);
}
