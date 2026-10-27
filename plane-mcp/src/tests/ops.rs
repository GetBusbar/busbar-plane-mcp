//! Tests for `ops.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::{method_row_for, Sender, METHODS, OP_CLASSES};

/// Every method maps to a class the plane declares.
#[test]
fn every_method_names_a_declared_class() {
    for row in METHODS {
        assert!(
            OP_CLASSES.contains(&row.op),
            "method {} names an undeclared class {}",
            row.method,
            row.op
        );
    }
}

/// No method name is listed twice, so a lookup has one answer.
#[test]
fn no_method_name_is_repeated() {
    for (i, row) in METHODS.iter().enumerate() {
        assert!(
            !METHODS[..i].iter().any(|r| r.method == row.method),
            "method {} is listed twice",
            row.method
        );
    }
}

/// No class is produced by two different methods.
///
/// One class per method here, deliberately: this protocol spells each operation exactly one way,
/// so two methods sharing a class would mean one of them was mis-filed.
#[test]
fn no_class_is_produced_twice() {
    for (i, row) in METHODS.iter().enumerate() {
        assert!(
            !METHODS[..i].iter().any(|r| r.op == row.op),
            "class {} is produced by two methods",
            row.op
        );
    }
}

/// The lookup is total over the table and answers nothing else.
#[test]
fn the_lookup_answers_the_table_and_nothing_else() {
    for row in METHODS {
        assert_eq!(method_row_for(row.method), Some(row));
    }
    assert_eq!(method_row_for("this/method/does/not/exist"), None);
    assert_eq!(method_row_for(""), None);
}

/// Every method the codec's own dispatch table names is one this plane carries.
///
/// The table itself, iterated. This SCRAPED it out of the server half's source once — an
/// `include_str!` over `../../busbar-mcp/src/…` followed by a hand-rolled parse for quoted
/// pieces containing a slash — which coupled this crate to a sibling its manifest does not name
/// and could only ever see what the parse happened to catch. The table is the codec's now, so
/// the assertion is over the values themselves. A method the codec dispatches and this plane
/// does not carry would arrive here as an unsupported operation.
#[test]
fn every_dispatched_method_is_carried() {
    let mut seen = 0usize;
    for method in crate::codec::IMPLEMENTED_METHODS {
        if method.contains('/') {
            assert!(
                method_row_for(method).is_some(),
                "the codec dispatches {method} and this plane does not carry it"
            );
            seen += 1;
        }
    }
    assert!(
        seen >= 12,
        "only {seen} methods were read out of the codec's table"
    );
}

/// The three an upstream sends back are the three the plane calls provider-initiated.
#[test]
fn the_provider_methods_are_the_three() {
    let provider: Vec<&str> = METHODS
        .iter()
        .filter(|r| r.sender == Sender::Provider)
        .map(|r| r.method)
        .collect();
    assert_eq!(
        provider,
        vec!["sampling/createMessage", "roots/list", "elicitation/create"]
    );
}
