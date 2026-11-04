// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// A unit whose host inspection of `reference` answered `error`.
fn answered(plane: &McpDoor, key: u64, ticket: Ticket, reference: &str, error: InspectionError) {
    plane.inspection_units.insert(
        key,
        Unit {
            ticket,
            caller: "alice".to_string(),
            id: 1,
            query: InspectionQuery::Work {
                reference: reference.as_bytes().to_vec(),
            },
            state: Inspection::default(),
            result: Some(Err(error)),
        },
    );
}

#[test]
fn an_inspection_refusal_is_said_in_words_not_as_a_debug_variant() {
    let plane = McpDoor::default();
    let ticket = Ticket {
        slot: 2,
        generation: 5,
    };
    answered(&plane, 7, ticket, "task", InspectionError::Refused);
    let Poll::Ready(Err(words)) = work(&plane, 7, ticket, "alice", "task") else {
        panic!("a refused inspection is answered, not pending");
    };
    assert!(
        words.contains(&InspectionError::Refused.to_string()),
        "{words}"
    );
    assert!(
        !words.contains("Refused"),
        "the error enum's Debug name is not a caller's words: {words}"
    );
}
