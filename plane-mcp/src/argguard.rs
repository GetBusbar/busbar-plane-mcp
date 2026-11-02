// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARGUMENT HALF OF THE DISPATCH SSRF GUARD: a value-driven walk of `tools/call` arguments

use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED,
};
use busbar_contract::net::{extract_normalized_host, url_host_to_ascii};
use serde_json::Value;
use std::collections::BTreeMap;

/// THE HOST'S JUDGE, as the walk asks it: one host an argument names (an IPv6 literal bracketed,
pub type Judge<'a> = dyn FnMut(&str) -> Option<u64> + 'a;

/// How deep into the ARGUMENT value the walk goes before refusing. Arguments arrive as already
const MAX_VALUE_DEPTH: usize = 64;

/// How far the SCHEMA-side expansion follows `allOf`/`anyOf`/`oneOf` nesting. Bounded separately
const MAX_COMBINATOR_DEPTH: usize = 8;

/// What a URL-ish format says the value IS, which decides how it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Urlish {
    /// An absolute URL. A non-`http(s)` scheme is refused; `file:`, `gopher:` and friends are
    /// refused by absence rather than by a list somebody has to maintain.
    AbsoluteUrl,
    /// A URI reference, which may legitimately be relative. A relative reference names no host and
    /// is admissible; a scheme-relative `//host/path` names one and is judged.
    Reference,
    /// A bare host: `hostname`, `idn-hostname`, `ipv4`, `ipv6`.
    Host,
}

/// Why one argument value was refused. Each arm names the offending value, because a refusal an
/// operator cannot diagnose is a refusal an operator disables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArgWhy {
    /// An absolute-URL field carrying something that is not `http(s)`.
    Scheme(String),
    /// The value has no host component to judge.
    NoHost(String),
    /// `dest.judge` answered `DEST_METADATA`: a cloud-metadata endpoint, by name, address or the
    /// deployment's own list. Refused unconditionally, `allow_private` or not.
    CloudMetadata(String),
    /// `dest.judge` answered `DEST_OBFUSCATED`: an alternate IPv4 encoding (`2130706433`,
    /// `0x7f000001`, `127.1`) that a resolver expands but a canonical IP-literal check misses.
    ObfuscatedHost(String),
    /// `dest.judge` answered `DEST_INTERNAL`: an internal host the egress rules do not admit here.
    InternalHost(String),
    /// `dest.judge` refused the host with another `DEST_*` verdict.
    Refused(String, u64),
    /// The host gave no verdict (it serves no `dest.judge`, or the judgement failed).
    Unjudged(String),
    /// The argument nested deeper than the walk will follow.
    DepthExceeded,
    /// A schema property pattern could not be compiled or reliably evaluated.
    SchemaPattern,
    /// A schema combinator nested beyond the inspection budget.
    SchemaDepth,
}

impl std::fmt::Display for ArgWhy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgWhy::Scheme(v) => write!(
                f,
                "`{v}` is not an http(s) URL, and no other scheme is passed through in a tool \
                 argument"
            ),
            ArgWhy::NoHost(v) => write!(f, "`{v}` has no host to check"),
            ArgWhy::CloudMetadata(h) => write!(
                f,
                "`{h}` is a cloud-metadata endpoint; that is refused unconditionally, because an \
                 operator opting a server into private addressing has said nothing about the \
                 service whose whole value to an attacker is that it hands out credentials"
            ),
            ArgWhy::ObfuscatedHost(h) => write!(
                f,
                "`{h}` is an alternate IPv4 encoding a resolver expands; write the address in \
                 dotted-quad form so it can be checked"
            ),
            ArgWhy::InternalHost(h) => write!(
                f,
                "`{h}` is an internal address; set this server's `allow_private` if reaching \
                 internal hosts through its tools is deliberate (the deployment's destination \
                 rules still apply)"
            ),
            ArgWhy::Refused(h, verdict) => write!(
                f,
                "`{h}` is refused by the deployment's destination rules (verdict {verdict})"
            ),
            ArgWhy::Unjudged(h) => write!(
                f,
                "`{h}` could not be checked against the deployment's destination rules, so it is \
                 refused"
            ),
            ArgWhy::DepthExceeded => write!(
                f,
                "the tool arguments nest deeper than {MAX_VALUE_DEPTH} levels, which is refused \
                 rather than walked partially"
            ),
            ArgWhy::SchemaPattern => write!(
                f,
                "a schema `patternProperties` expression could not be checked, so the argument is refused"
            ),
            ArgWhy::SchemaDepth => write!(
                f,
                "the input schema nests combinators beyond {MAX_COMBINATOR_DEPTH} levels, so the argument is refused rather than inspected partially"
            ),
        }
    }
}

/// ONE REFUSED ARGUMENT, located precisely. The pointer is an RFC 6901 JSON Pointer into the
/// arguments, so an operator reading the refusal is told WHICH field of a nested document was the
/// problem rather than being handed the document back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArgRefusal {
    /// RFC 6901 pointer, e.g. `/delivery/callbacks/1`.
    pub pointer: String,
    /// The schema-declared format that put this field in scope, or `None` when the field was
    /// caught by the undeclared `http(s)://` detector.
    pub declared_format: Option<String>,
    /// Why the value was refused.
    pub why: ArgWhy,
}

impl std::fmt::Display for ArgRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let at = if self.pointer.is_empty() {
            "the argument"
        } else {
            self.pointer.as_str()
        };
        match &self.declared_format {
            Some(fmt) => write!(
                f,
                "tool argument {at} (schema format `{fmt}`) was refused: {}",
                self.why
            ),
            None if matches!(self.why, ArgWhy::SchemaPattern | ArgWhy::SchemaDepth) => {
                write!(f, "tool argument {at} was refused: {}", self.why)
            }
            None => write!(
                f,
                "tool argument {at} carries a URL the schema does not declare, and it was refused: \
                 {}",
                self.why
            ),
        }
    }
}

/// WHAT THE WALK ACTUALLY VISITED. Returned on success so a caller can assert a non-zero floor: a
/// walker that finds nothing refuses nothing and passes every test, which is the false-green shape
/// this check exists to avoid being.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArgScan {
    /// String values judged because the pinned schema declared a URL-ish format for them.
    pub declared_judged: usize,
    /// String values judged because the value itself is a URL naming a host (it began `http://`
    /// or `https://`, or a WHATWG reader reads it as one) while the schema declared no URL-ish
    /// format there.
    pub undeclared_judged: usize,
    /// Every string leaf the walk reached, judged or not. The denominator that makes the two
    /// numerators above readable.
    pub strings_seen: usize,
}

/// THE ENTRY POINT: walk `arguments` against the PINNED `schema` and refuse on the first
pub fn guard(
    schema: &Value,
    arguments: &Value,
    mut judge: impl FnMut(&str) -> Option<u64>,
) -> Result<ArgScan, ArgRefusal> {
    let mut scan = ArgScan::default();
    let mut pointer = String::new();
    let mut patterns = BTreeMap::new();
    walk(
        &[schema],
        arguments,
        &mut pointer,
        0,
        &mut judge,
        &mut scan,
        &mut patterns,
    )?;
    Ok(scan)
}

/// The value-driven walk. The VALUE drives and the schema rides alongside, which is what lets the
fn walk(
    schemas: &[&Value],
    value: &Value,
    pointer: &mut String,
    depth: usize,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
    patterns: &mut BTreeMap<String, jsonschema::Validator>,
) -> Result<(), ArgRefusal> {
    if depth > MAX_VALUE_DEPTH {
        return Err(ArgRefusal {
            pointer: pointer.clone(),
            declared_format: None,
            why: ArgWhy::DepthExceeded,
        });
    }

    expanded(schemas).map_err(|why| ArgRefusal {
        pointer: pointer.clone(),
        declared_format: None,
        why,
    })?;
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&escape_token(k));
                let children = child_for_key(schemas, k, patterns).map_err(|why| ArgRefusal {
                    pointer: pointer.clone(),
                    declared_format: None,
                    why,
                })?;
                walk(&children, v, pointer, depth + 1, judge, scan, patterns)?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&i.to_string());
                walk(
                    &child_for_index(schemas, i).map_err(|why| ArgRefusal {
                        pointer: pointer.clone(),
                        declared_format: None,
                        why,
                    })?,
                    v,
                    pointer,
                    depth + 1,
                    judge,
                    scan,
                    patterns,
                )?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::String(s) => judge_string(schemas, s, pointer, judge, scan),
        _ => Ok(()),
    }
}

/// One string leaf: declared first, then the undeclared `http(s)://` detector.
fn judge_string(
    schemas: &[&Value],
    s: &str,
    pointer: &str,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
) -> Result<(), ArgRefusal> {
    scan.strings_seen += 1;
    let trimmed = s.trim();
    let refused = |declared_format: Option<String>| {
        move |why| ArgRefusal {
            pointer: pointer.to_string(),
            declared_format,
            why,
        }
    };
    let declared = urlish_formats(schemas).map_err(refused(None))?;
    if !declared.is_empty() {
        scan.declared_judged += 1;
        for (format, kind) in declared {
            judge_argument(kind, trimmed, judge).map_err(refused(Some(format)))?;
        }
        return Ok(());
    }
    if starts_with_http(trimmed) {
        scan.undeclared_judged += 1;
        return judge_argument(Urlish::AbsoluteUrl, trimmed, judge).map_err(refused(None));
    }
    if let Some(found) = whatwg_host(s) {
        scan.undeclared_judged += 1;
        return match found {
            Some(host) => judge_host(&host, judge)
                .and_then(|()| judge_rfc_authority(&whatwg_cleaned(s), judge)),
            None => Err(ArgWhy::NoHost(s.to_string())),
        }
        .map_err(refused(None));
    }
    Ok(())
}

/// THE WHATWG SPECIAL SCHEMES: the six a WHATWG URL reader reads by the web rules (a backslash is a
const SPECIAL_SCHEMES: [&str; 6] = ["http", "https", "ws", "wss", "ftp", "file"];

/// THE HOST A WHATWG URL READER FINDS IN `value`, read as a fetching client reads it, by the
fn whatwg_host(value: &str) -> Option<Option<String>> {
    let cleaned = whatwg_cleaned(value);
    let special = special_scheme(&cleaned);
    let read = match special {
        Some((scheme, after)) if scheme.eq_ignore_ascii_case("file") => match file_host(after) {
            FileHost::Path => return None,
            FileHost::Named(host) => Some(host),
            FileHost::Unread => None,
        },
        Some((scheme, after)) if scheme.eq_ignore_ascii_case("ftp") => {
            busbar_contract::net::parse_url(&format!("http:{after}"))
                .ok()
                .map(|p| p.host)
        }
        _ => busbar_contract::net::parse_url(value).ok().map(|p| p.host),
    };
    match read {
        Some(host) => Some(Some(host.to_ascii_lowercase())),
        None => {
            let raw_url = !cleaned
                .chars()
                .any(|c| c.is_ascii_whitespace() || c.is_ascii_control());
            ((special.is_some() && raw_url) || opens_with_authority(&cleaned)).then_some(None)
        }
    }
}

/// The scheme of `cleaned` and what follows its `:`, when the scheme is a WHATWG special one (in any
fn special_scheme(cleaned: &str) -> Option<(&str, &str)> {
    let (scheme, after) = cleaned.split_once(':')?;
    SPECIAL_SCHEMES
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
        .then_some((scheme, after))
}

/// Whether `cleaned` opens with an RFC 3986 scheme and `://`: a URL with an authority by its
fn opens_with_authority(cleaned: &str) -> bool {
    cleaned.split_once("://").is_some_and(|(scheme, _)| {
        scheme.starts_with(|c: char| c.is_ascii_alphabetic())
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
    })
}

/// What a WHATWG reader finds after `file:`.
enum FileHost {
    /// No host: the value is a path (`file:/etc/x`, `file:///etc/x`).
    Path,
    /// The host the reader dials.
    Named(String),
    /// A host is spelled but no reader accepts it.
    Unread,
}

/// THE HOST OF A `file` URL, by the WHATWG file rule: a host follows only two slashes (either of
fn file_host(after: &str) -> FileHost {
    let mut chars = after.chars();
    let two_slashes = matches!(
        (chars.next(), chars.next()),
        (Some('/' | '\\'), Some('/' | '\\'))
    );
    if !two_slashes {
        return FileHost::Path;
    }
    let rest = chars.as_str();
    let end = rest.find(['/', '\\', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.is_empty() {
        return FileHost::Path;
    }
    match busbar_contract::net::parse_url(&format!("http://{authority}/")) {
        Ok(parts) => FileHost::Named(parts.host),
        Err(_) => FileHost::Unread,
    }
}

/// THE HOST A `uri-reference` NAMES, under the WHATWG reading: an absolute one's own, or a relative
fn reference_host(value: &str) -> Option<Option<String>> {
    if let Some(found) = whatwg_host(value) {
        return Some(found);
    }
    let cleaned = whatwg_cleaned(value);
    let mut opening = cleaned.chars();
    let network_path = matches!(
        (opening.next(), opening.next()),
        (Some('/' | '\\'), Some('/' | '\\'))
    );
    if network_path {
        return whatwg_host(&format!("https:{cleaned}"));
    }
    None
}

/// Whether the WHOLE value is an `http(s)` URL. Deliberately a prefix test on the whole trimmed
fn starts_with_http(v: &str) -> bool {
    let lower = v.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

/// The WHATWG URL parser's first step, as a connecting stack applies it: leading and trailing C0
fn whatwg_cleaned(v: &str) -> String {
    v.trim_matches(|c: char| c <= '\u{1f}' || c == ' ')
        .chars()
        .filter(|c| !matches!(*c, '\t' | '\n' | '\r'))
        .collect()
}

/// Whether `cleaned` names the `http` or `https` scheme, in any case.
fn http_scheme(cleaned: &str) -> bool {
    cleaned
        .split_once(':')
        .is_some_and(|(s, _)| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
}

fn judge_argument(kind: Urlish, value: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    match kind {
        Urlish::AbsoluteUrl => judge_absolute(value, judge),
        Urlish::Reference => {
            let cleaned = whatwg_cleaned(value);
            if opens_with_authority(&cleaned) || http_scheme(&cleaned) {
                return judge_absolute(value, judge);
            }

            match reference_host(value) {
                Some(Some(host)) => judge_host(&host, judge),
                Some(None) => Err(ArgWhy::NoHost(value.to_string())),
                None => Ok(()),
            }?;
            judge_rfc_authority(&cleaned, judge)
        }
        Urlish::Host => {
            if value.contains("://") || http_scheme(&whatwg_cleaned(value)) {
                return judge_absolute(value, judge);
            }
            judge_host(value, judge)?;
            judge_rfc_authority(&format!("//{}", whatwg_cleaned(value)), judge)
        }
    }
}

/// An absolute URL, read as a WHATWG parser reads it ([`whatwg_cleaned`]): the scheme allowlist,
fn judge_absolute(url: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let cleaned = whatwg_cleaned(url);
    if !http_scheme(&cleaned) {
        return Err(ArgWhy::Scheme(url.to_string()));
    }

    let host = if cleaned.contains("://") {
        extract_normalized_host(&cleaned)
    } else {
        busbar_contract::net::parse_url(&cleaned)
            .ok()
            .map(|p| p.host)
    }
    .ok_or_else(|| ArgWhy::NoHost(url.to_string()))?;
    judge_host(&host, judge)?;
    judge_rfc_authority(&cleaned, judge)
}

fn judge_rfc_authority(cleaned: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let rest = cleaned.strip_prefix("//").or_else(|| {
        cleaned
            .split_once(':')
            .and_then(|(_, after)| after.strip_prefix("//"))
    });
    if let Some(rest) = rest {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        if authority.contains('\\') {
            let host = authority.rsplit('@').next().unwrap_or(authority);
            judge_host(strip_port(host), judge)?;
        }
    }
    Ok(())
}

/// The host, asked of the host's one judge (`dest.judge`):
fn judge_host(raw: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let host = dial_host(raw).ok_or_else(|| ArgWhy::NoHost(raw.to_string()))?;
    let dest = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    ask(&host, &dest, judge)?;
    let dialled = url::Host::parse(&dest)
        .map(|h| h.to_string())
        .map_err(|_| ArgWhy::NoHost(host.clone()))?;
    if dialled != dest {
        let bare = dialled
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&dialled)
            .to_string();
        ask(&bare, &dialled, judge)?;
    }
    Ok(())
}

/// One host asked of the judge, its verdict rendered as the refusal.
fn ask(host: &str, dest: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let host = host.to_string();
    match judge(dest) {
        Some(DEST_ALLOWED) => Ok(()),
        Some(DEST_METADATA) => Err(ArgWhy::CloudMetadata(host)),
        Some(DEST_OBFUSCATED) => Err(ArgWhy::ObfuscatedHost(host)),
        Some(DEST_INTERNAL) => Err(ArgWhy::InternalHost(host)),
        Some(DEST_NO_HOST) => Err(ArgWhy::NoHost(host)),
        Some(verdict) => Err(ArgWhy::Refused(host, verdict)),
        None => Err(ArgWhy::Unjudged(host)),
    }
}

/// THE NAME A CONNECTING CLIENT DIALS for the host `raw`: read as a URL's host is read
fn dial_host(raw: &str) -> Option<String> {
    let read = normalize_host(raw)?;
    if read.is_ascii() {
        return Some(read);
    }
    let mapped = url_host_to_ascii(&read).ok()?;
    let host = mapped.strip_suffix('.').unwrap_or(mapped.as_ref());
    (!host.is_empty() && host.is_ascii()).then(|| host.to_string())
}

/// Normalize a bare host the same way a URL's host component is normalized, by routing it through
fn normalize_host(raw: &str) -> Option<String> {
    extract_normalized_host(
        &if busbar_contract::net::host_ip(raw).is_some_and(|ip| ip.is_ipv6()) {
            format!("https://[{raw}]/")
        } else {
            format!("https://{raw}/")
        },
    )
}

/// Drop a `:port` suffix from an authority, leaving a bracketed IPv6 literal intact for
fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority;
    }
    match authority.rsplit_once(':') {
        Some((left, _)) if !left.contains(':') => left,
        _ => authority,
    }
}

/// RFC 6901 token escaping: `~` becomes `~0` and `/` becomes `~1`, in that order, so a key
fn escape_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Every URL-ish `format` declared for this position, in declaration order. Overlapping property
fn urlish_formats(schemas: &[&Value]) -> Result<Vec<(String, Urlish)>, ArgWhy> {
    let mut out = Vec::new();
    for node in expanded(schemas)? {
        let Some(format) = node.get("format").and_then(Value::as_str) else {
            continue;
        };

        let kind = match format.to_ascii_lowercase().as_str() {
            "uri-reference" => Urlish::Reference,
            "hostname" | "idn-hostname" | "ipv4" | "ipv6" => Urlish::Host,
            "uri" | "iri" | "url" => Urlish::AbsoluteUrl,
            _ => continue,
        };
        out.push((format.to_string(), kind));
    }
    Ok(out)
}

/// A schema node plus every `allOf`/`anyOf`/`oneOf` branch reachable from it, so a URL-ish format
fn expanded<'a>(schemas: &[&'a Value]) -> Result<Vec<&'a Value>, ArgWhy> {
    let mut out = Vec::new();
    expand_into(schemas, &mut out, MAX_COMBINATOR_DEPTH)?;
    Ok(out)
}

fn expand_into<'a>(
    schemas: &[&'a Value],
    out: &mut Vec<&'a Value>,
    budget: usize,
) -> Result<(), ArgWhy> {
    if budget == 0 {
        return if schemas.is_empty() {
            Ok(())
        } else {
            Err(ArgWhy::SchemaDepth)
        };
    }
    for node in schemas {
        if !node.is_object() {
            continue;
        }
        out.push(node);
        for key in ["allOf", "anyOf", "oneOf"] {
            if let Some(branches) = node.get(key).and_then(Value::as_array) {
                let refs: Vec<&Value> = branches.iter().collect();
                expand_into(&refs, out, budget - 1)?;
            }
        }
    }
    Ok(())
}

/// Named properties and every matching property pattern apply together. `additionalProperties`
fn child_for_key<'a>(
    schemas: &[&'a Value],
    key: &str,
    patterns: &mut BTreeMap<String, jsonschema::Validator>,
) -> Result<Vec<&'a Value>, ArgWhy> {
    let mut out = Vec::new();
    for node in expanded(schemas)? {
        let mut covered = false;
        if let Some(named) = node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|m| m.get(key))
        {
            out.push(named);
            covered = true;
        }
        if let Some(entries) = node.get("patternProperties").and_then(Value::as_object) {
            for (pattern, child) in entries {
                if pattern_matches(pattern, key, patterns)? {
                    out.push(child);
                    covered = true;
                }
            }
        }
        if !covered {
            if let Some(extra) = node
                .get("additionalProperties")
                .filter(|extra| extra.is_object())
            {
                out.push(extra);
            }
        }
    }
    Ok(out)
}

/// Use the fleet's JSON Schema engine's ECMA-262 translation, not Rust regex syntax. Compile each
fn pattern_matches(
    pattern: &str,
    key: &str,
    patterns: &mut BTreeMap<String, jsonschema::Validator>,
) -> Result<bool, ArgWhy> {
    let matcher = match patterns.entry(pattern.to_string()) {
        std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        std::collections::btree_map::Entry::Vacant(entry) => {
            let schema = serde_json::json!({"pattern": pattern});
            let matcher = jsonschema::validator_for(&schema).map_err(|_| ArgWhy::SchemaPattern)?;
            entry.insert(matcher)
        }
    };
    let key = Value::String(key.to_string());
    let matched = matcher.validate(&key);
    match matched {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                jsonschema::error::ValidationErrorKind::Pattern { .. }
            ) =>
        {
            Ok(false)
        }
        Err(_) => Err(ArgWhy::SchemaPattern),
    }
}

/// The schema(s) governing array element `index`: the tuple position where the schema gives one
fn child_for_index<'a>(schemas: &[&'a Value], index: usize) -> Result<Vec<&'a Value>, ArgWhy> {
    let mut out = Vec::new();
    for node in expanded(schemas)? {
        if let Some(tuple) = node.get("prefixItems").and_then(Value::as_array) {
            if let Some(at) = tuple.get(index) {
                out.push(at);
                continue;
            }
        }
        match node.get("items") {
            Some(Value::Array(tuple)) => {
                if let Some(at) = tuple.get(index) {
                    out.push(at);
                } else if let Some(extra) = node
                    .get("additionalItems")
                    .filter(|extra| extra.is_object())
                {
                    out.push(extra);
                }
            }
            Some(single) if single.is_object() => out.push(single),
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "tests/argguard_tests.rs"]
mod tests;
