// SPDX-License-Identifier: Apache-2.0
use super::{Instance, McpDoor};

#[cfg(test)]
pub(crate) const DIAG_NAMES: &[&str] = super::door_sessions::DIAG_NAMES;
#[cfg(test)]
pub(crate) const DIAG_IDS_LEN: usize = super::door_sessions::DIAG_IDS.len();

#[cfg(test)]
thread_local! {
    pub(super) static LEGACY_EXCHANGE_COUNTS: std::cell::RefCell<Vec<(usize, super::Ticket, usize)>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(super) fn record(instance: &Instance<'_, McpDoor, busbar_contract::plugin::markers::PlaneKind>) {
    #[cfg(test)]
    if let Some(plane) = instance.get() {
        LEGACY_EXCHANGE_COUNTS.with(|counts| {
            counts.borrow_mut().push((
                std::ptr::from_ref(plane) as usize,
                instance.ticket(),
                instance.parked_count(),
            ));
        });
    }
    #[cfg(not(test))]
    let _ = instance;
}
