// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::Outcome;

#[test]
fn only_a_successful_settlement_releases_custody() {
    assert!(confirmed(Ok(())));
    assert!(
        !confirmed(Err(ServiceError::Declined(Outcome::Refused))),
        "refusal can describe live work or a settlement that may still roll back"
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
