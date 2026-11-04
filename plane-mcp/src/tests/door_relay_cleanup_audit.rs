// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_settle_refused_as_already_settled_releases_custody() {
    assert!(confirmed(Ok(())));
    assert!(
        confirmed(Err(ServiceError::Declined(Outcome::Refused))),
        "a handle settled first elsewhere can never be settled again: keeping it retries forever"
    );
}

#[test]
fn any_other_settle_failure_keeps_custody_for_a_retry() {
    for failed in [
        ServiceError::Unserved,
        ServiceError::Broken,
        ServiceError::Declined(Outcome::Failed),
        ServiceError::Short { bytes: 1, items: 1 },
    ] {
        assert!(
            !confirmed(Err(failed)),
            "{failed:?} is not proof of settlement"
        );
    }
}
