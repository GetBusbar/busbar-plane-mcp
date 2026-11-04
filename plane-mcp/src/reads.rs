// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO READS ANSWERED FROM THE SECTION: `prompts/get` and `resources/read`. No upstream is
//! contacted; the content is the operator's own, with the caller's text substituted into it and the
//! whole passed through the markup strip after substitution, never before.
//!
//! Pure: the request's params, the generation's [`Catalogue`] and the caller's `admit` predicate
//! in; the answer's bytes or its refusal out. A prompt that asks its caller for input first
//! ([`PromptEntry::ask_caller`]) reaches [`prompts_get`] only once that exchange let it through.
//!
//! The answers and the refusals are the served engine's: a missing member is `400` + `-32602`;
//! resources not found and not granted are one `404` + `-32602`; a uri two reachable approvals answer is
//! `409` + `-32000` naming them.

use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::call::error;
use crate::catalogue::{
    complete, Catalogue, Lookup, PromptEntry, ResourceEntry, ResourceTemplateEntry,
};
use crate::codec::{CODE_INVALID_PARAMS, CODE_REFUSED};
use crate::sanitize::normalise;
use crate::tool_arrival::Refusal;
use crate::tools_config::PromptContentCfg;

/// The status of a read that names nothing the caller may see.
const STATUS_NOT_FOUND: u32 = 404;
const MAX_RENDER_BYTES: usize = 8 * 1024 * 1024;
const MAX_READ_SELECTOR_BYTES: usize = 8192;

fn render_refusal(id: &Value) -> Refusal {
    error(
        crate::checks::STATUS,
        id,
        CODE_INVALID_PARAMS,
        "The requested content exceeds the rendering byte limit.".into(),
        None,
    )
}
pub(crate) fn check_selector(id: &Value, selector: &str) -> Result<(), Refusal> {
    if selector.len() > MAX_READ_SELECTOR_BYTES {
        Err(error(
            crate::checks::STATUS,
            id,
            CODE_INVALID_PARAMS,
            "The requested name or URI exceeds the byte limit.".into(),
            None,
        ))
    } else {
        Ok(())
    }
}

fn string_param<'a>(params: Option<&'a Value>, key: &str) -> Option<&'a str> {
    params.and_then(|p| p.get(key)).and_then(Value::as_str)
}

/// Substitute `{arg}` placeholders from `params.arguments`, in ONE pass over the template: an
/// argument's value is never read for placeholders, and an unknown placeholder is left as written.
/// Only string arguments substitute.
fn substitute_arguments(template: &str, params: Option<&Value>) -> Result<String, ()> {
    let Some(args) = params
        .and_then(|p| p.get("arguments"))
        .and_then(Value::as_object)
    else {
        return (template.len() <= MAX_RENDER_BYTES)
            .then(|| template.to_string())
            .ok_or(());
    };
    substitute_with(template, |name| args.get(name).and_then(Value::as_str))
}

/// The `messages` a prompt renders, in whichever form the operator declared: substituted first,
/// normalised second.
fn render_messages(prompt: &PromptEntry, params: Option<&Value>) -> Result<Vec<Value>, ()> {
    let mut remaining = MAX_RENDER_BYTES;
    let mut render = |s: &str| {
        let text = substitute_arguments(s, params)?;
        remaining = remaining.checked_sub(text.len()).ok_or(())?;
        Ok::<_, ()>(normalise(&text))
    };
    if prompt.messages.is_empty() {
        return Ok(vec![json!({
            "role": "user",
            "content": {
                "type": "text",
                "text": render(prompt.template.as_deref().unwrap_or(""))?,
            },
        })]);
    }
    prompt
        .messages
        .iter()
        .map(|m| {
            let content = match &m.content {
                PromptContentCfg::Text { text } => json!({ "type": "text", "text": render(text)? }),
                PromptContentCfg::Image { data, mime_type } => {
                    json!({ "type": "image", "data": data, "mimeType": mime_type })
                }
                PromptContentCfg::Audio { data, mime_type } => {
                    json!({ "type": "audio", "data": data, "mimeType": mime_type })
                }
                PromptContentCfg::Resource { resource } => {
                    let mut r = Map::new();
                    r.insert("uri".into(), render(&resource.uri)?.into());
                    if let Some(m) = &resource.mime_type {
                        r.insert("mimeType".into(), m.clone().into());
                    }
                    if let Some(t) = &resource.text {
                        r.insert("text".into(), render(t)?.into());
                    }
                    if let Some(b) = &resource.blob {
                        r.insert("blob".into(), b.clone().into());
                    }
                    json!({ "type": "resource", "resource": r })
                }
            };
            Ok(json!({ "role": m.role, "content": content }))
        })
        .collect()
}

/// The prompt `params.name` names, under the caller's grants.
///
/// # Errors
///
/// `400` + `-32602` without a string `params.name`; `404` + `-32000` for a prompt that does not
/// exist or is not the caller's, in one sentence.
pub fn prompt_named<'c>(
    catalogue: &'c Catalogue,
    id: &Value,
    params: Option<&Value>,
    admit: &impl Fn(&str, &str) -> bool,
) -> Result<&'c PromptEntry, Refusal> {
    let Some(name) = string_param(params, "name") else {
        return Err(error(
            crate::checks::STATUS,
            id,
            CODE_INVALID_PARAMS,
            "`params.name` is required and must be a string.".to_string(),
            None,
        ));
    };
    check_selector(id, name)?;
    catalogue.prompt_for(admit, name).ok_or_else(|| {
        error(
            STATUS_NOT_FOUND,
            id,
            CODE_INVALID_PARAMS,
            format!("`{name}` is not a prompt this server exposes."),
            None,
        )
    })
}

/// `prompts/get`'s answer for a prompt [`prompt_named`] found.
pub fn prompts_get(
    prompt: &PromptEntry,
    id: &Value,
    params: Option<&Value>,
) -> Result<Vec<u8>, Refusal> {
    let mut result =
        json!({"messages": render_messages(prompt, params).map_err(|()| render_refusal(id))?});
    if let Some(description) = prompt.description.as_deref() {
        result["description"] = normalise(description).into();
    }
    Ok(complete(id, result))
}

/// One `contents` entry: the uri, its media type, and the blob or else the text (normalised).
fn content(uri: &str, mime_type: Option<&String>, blob: Option<&String>, text: &str) -> Value {
    let mut content = Map::new();
    content.insert("uri".into(), uri.into());
    if let Some(m) = mime_type {
        content.insert("mimeType".into(), m.clone().into());
    }
    match blob {
        Some(blob) => content.insert("blob".into(), blob.clone().into()),
        None => content.insert("text".into(), normalise(text).into()),
    };
    Value::Object(content)
}

/// `template` with each `{name}` that `bindings` holds replaced by its value, in ONE pass over the
/// template: a bound value is copied as it is, so a value that itself spells `{other}` is never
/// substituted again.
fn substitute(template: &str, bindings: &BTreeMap<String, String>) -> Result<String, ()> {
    substitute_with(template, |name| bindings.get(name).map(String::as_str))
}

fn substitute_with<'a>(
    template: &str,
    binding: impl Fn(&str) -> Option<&'a str>,
) -> Result<String, ()> {
    if template.len() > MAX_RENDER_BYTES {
        return Err(());
    }
    let mut out = String::with_capacity(template.len());
    let mut opening = None;
    let mut copied = 0;
    for (at, ch) in template.char_indices() {
        match ch {
            '{' => opening = Some(at),
            '}' => {
                if let Some(start) = opening.take() {
                    if let Some(value) = binding(&template[start + 1..at]) {
                        if out
                            .len()
                            .saturating_add(start - copied)
                            .saturating_add(value.len())
                            > MAX_RENDER_BYTES
                        {
                            return Err(());
                        }
                        out.push_str(&template[copied..start]);
                        out.push_str(value);
                        copied = at + 1;
                    }
                }
            }
            _ => {}
        }
    }
    if out.len().saturating_add(template.len() - copied) > MAX_RENDER_BYTES {
        return Err(());
    }
    out.push_str(&template[copied..]);
    Ok(out)
}

fn concrete_content(res: &ResourceEntry) -> Value {
    let text = res.text.as_deref().unwrap_or("");
    content(&res.uri, res.mime_type.as_ref(), res.blob.as_ref(), text)
}

fn templated_content(
    requested: &str,
    template: &ResourceTemplateEntry,
    bindings: &BTreeMap<String, String>,
) -> Result<Value, ()> {
    let text = substitute(template.text.as_deref().unwrap_or_default(), bindings)?;
    Ok(content(requested, template.mime_type.as_ref(), None, &text))
}

fn ambiguous(id: &Value, uri: &str, candidates: &[String]) -> Refusal {
    error(
        409,
        id,
        CODE_REFUSED,
        format!(
            "`{uri}` is answered by more than one approval you are granted ({}). \
             Narrow the grant so exactly one of them applies.",
            candidates.join(", ")
        ),
        Some(json!({ "reason": "resource_ambiguous", "candidates": candidates })),
    )
}

/// `resources/read`: a concrete approval first, a template second, never a guess between two.
///
/// # Errors
///
/// `400` + `-32602` without a string `params.uri`; `409` + `-32000` for an ambiguity; `404` +
/// `-32602` for a uri nothing the caller may see answers. This dispatch serves `2026-07-28`,
/// which retires `-32002`; legacy session adaptation preserves the standard Invalid params code.
pub fn resources_read(
    catalogue: &Catalogue,
    id: &Value,
    params: Option<&Value>,
    admit: &impl Fn(&str, &str) -> bool,
) -> Result<Vec<u8>, Refusal> {
    let Some(uri) = string_param(params, "uri") else {
        return Err(error(
            crate::checks::STATUS,
            id,
            CODE_INVALID_PARAMS,
            "`params.uri` is required and must be a string.".to_string(),
            None,
        ));
    };
    check_selector(id, uri)?;
    let content = match catalogue.resource_by_uri(admit, uri) {
        Lookup::One(res) => concrete_content(res),
        Lookup::Ambiguous(candidates) => return Err(ambiguous(id, uri, &candidates)),
        Lookup::NotFound => match catalogue.resource_template_for(admit, uri) {
            Lookup::One((template, bindings)) => {
                templated_content(uri, template, &bindings).map_err(|()| render_refusal(id))?
            }
            Lookup::Ambiguous(candidates) => return Err(ambiguous(id, uri, &candidates)),
            Lookup::NotFound => {
                return Err(error(
                    STATUS_NOT_FOUND,
                    id,
                    CODE_INVALID_PARAMS,
                    format!("`{uri}` is not a resource this server exposes."),
                    Some(json!({"uri": uri})),
                ))
            }
        },
    };
    let result = crate::catalogue::cache_hints(json!({ "contents": [content] }));
    Ok(complete(id, result))
}

#[cfg(test)]
#[path = "tests/reads.rs"]
mod tests;
