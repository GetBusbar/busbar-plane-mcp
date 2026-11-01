// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::super::pattern_matches;
use super::ArgWhy;
use serde_json::json;
use std::collections::BTreeMap;

#[test]
fn a_real_pattern_engine_error_is_refused_while_an_ordinary_nonmatch_is_not() {
    // The dependency's own backtrack-error fixture, with its limit only in this test matcher.
    let pattern = r"(?<=ab)c";
    let validator = jsonschema::options()
        .with_pattern_options(jsonschema::PatternOptions::fancy_regex().backtrack_limit(1))
        .build(&json!({"pattern": pattern}))
        .expect("a valid ECMA lookbehind pattern");
    let key = json!("abc");
    let error = validator
        .validate(&key)
        .expect_err("the configured test matcher encounters a real engine error");
    assert!(matches!(
        error.kind(),
        jsonschema::error::ValidationErrorKind::BacktrackLimitExceeded { .. }
    ));
    let mut patterns = BTreeMap::from([(pattern.to_string(), validator)]);
    assert_eq!(
        pattern_matches(pattern, "abc", &mut patterns),
        Err(ArgWhy::SchemaPattern)
    );
    assert_eq!(pattern_matches("z", "abc", &mut patterns), Ok(false));
    assert_eq!(pattern_matches("abc", "abc", &mut patterns), Ok(true));
}
