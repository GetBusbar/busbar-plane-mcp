// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact JSON values at MCP wire boundaries, before envelope validation and correlation.

use busbar_contract::spans::{exceeds_max_depth, MAX_JSON_DEPTH};
use serde::{Deserialize, Deserializer};
use serde_json::{value::RawValue, Value};

/// Parse one bounded document without confusing literal object keys with serde number transport.
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, serde_json::Error> {
    if exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        return serde_json::from_slice::<ExactValue>(b"").map(|value| value.0);
    }
    serde_json::from_slice::<ExactValue>(bytes).map(|value| value.0)
}

/// Parse one event's text with the same type and number guarantees as [`parse`].
pub(crate) fn parse_str(text: &str) -> Result<Value, serde_json::Error> {
    parse(text.as_bytes())
}

struct ExactValue(Value);

impl<'de> Deserialize<'de> for ExactValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // RawValue identifies the actual JSON token before any arbitrary-precision transport
        // maps are synthesized. Container members recurse through this same distinction; only
        // scalar tokens reach Value's deserializer. Escaped object keys remain ordinary keys.
        let raw = <&RawValue>::deserialize(deserializer)?.get();
        let value = match raw.as_bytes().first() {
            Some(b'{') => {
                let mut de = serde_json::Deserializer::from_str(raw);
                de.deserialize_map(ObjectVisitor)
            }
            Some(b'[') => serde_json::from_str::<Vec<ExactValue>>(raw)
                .map(|items| Value::Array(items.into_iter().map(|item| item.0).collect())),
            _ => serde_json::from_str::<Value>(raw),
        };
        value.map(ExactValue).map_err(serde::de::Error::custom)
    }
}

struct ObjectVisitor;

impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = serde_json::Map::new();
        while let Some((key, value)) = map.next_entry::<String, ExactValue>()? {
            object.insert(key, value.0);
        }
        Ok(Value::Object(object))
    }
}
