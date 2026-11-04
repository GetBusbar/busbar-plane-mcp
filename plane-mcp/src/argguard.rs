// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ARGUMENT HALF OF THE DISPATCH SSRF GUARD: a value-driven walk of `tools/call` arguments
//! against the pinned input schema, asking the host's one destination judge (`dest.judge`)
//! about every host they carry.

use busbar_contract::abi::host::service::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_METADATA, DEST_NO_HOST, DEST_OBFUSCATED,
};
use busbar_contract::net::{extract_normalized_host, url_host_to_ascii};
use serde_json::Value;
use std::collections::BTreeMap;

/// THE HOST'S JUDGE, as the walk asks it: one host an argument names (an IPv6 literal bracketed,
/// as `dest.judge` reads a `host[:port]`), answered with the host's `DEST_*` verdict, or `None`
/// when the host gave none (the value is then refused: fail closed).
pub type Judge<'a> = dyn FnMut(&str) -> Option<u64> + 'a;

/// How deep into the ARGUMENT value the walk goes before refusing. Arguments arrive as already
/// parsed JSON, so this is a floor under stack safety rather than the primary bound; exceeding it
/// is a refusal instead of a truncation, because a walk that silently stops is a walk that reports
/// "nothing found" on the one document built to make it stop.
const MAX_VALUE_DEPTH: usize = 64;

/// How far the SCHEMA-side expansion follows `allOf`/`anyOf`/`oneOf` nesting. Bounded separately
/// from the value depth because a pinned schema can nest combinators independently of how deep the
/// arguments go.
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
    /// The combined schema and argument inspection exceeds the per-call work bound.
    WorkExceeded,
    /// A schema combinator nested beyond the inspection budget.
    SchemaDepth,
    /// A schema reference (`$ref`, `$dynamicRef`, `$recursiveRef`) that does not resolve inside the
    /// pinned schema, so what it declares cannot be inspected.
    SchemaRef(String),
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
            ArgWhy::WorkExceeded => write!(f, "the schema and arguments exceed the inspection work budget"),
            ArgWhy::SchemaPattern => write!(
                f,
                "a schema `patternProperties` expression could not be checked, so the argument is refused"
            ),
            ArgWhy::SchemaDepth => write!(
                f,
                "the input schema nests combinators beyond {MAX_COMBINATOR_DEPTH} levels, so the argument is refused rather than inspected partially"
            ),
            ArgWhy::SchemaRef(reference) => write!(
                f,
                "the input schema reference `{reference}` does not resolve inside the schema, so the \
                 argument is refused rather than inspected partially"
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
            None if matches!(
                self.why,
                ArgWhy::SchemaPattern
                    | ArgWhy::SchemaDepth
                    | ArgWhy::SchemaRef(_)
                    | ArgWhy::WorkExceeded
            ) =>
            {
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
/// inadmissible value.
///
/// Fails on the first refusal rather than collecting all of them, because the call is refused
/// either way and the operator's question is "why was this refused", which one named field answers.
/// Every host found is asked of `judge` ([`Judge`]).
pub fn guard(
    schema: &Value,
    arguments: &Value,
    mut judge: impl FnMut(&str) -> Option<u64>,
) -> Result<ArgScan, ArgRefusal> {
    inspection_budget(schema, arguments).map_err(|why| ArgRefusal {
        pointer: String::new(),
        declared_format: None,
        why,
    })?;
    let mut verdicts = BTreeMap::new();
    let mut cached_judge = |host: &str| {
        *verdicts
            .entry(host.to_string())
            .or_insert_with(|| judge(host))
    };
    let mut scan = ArgScan::default();
    let mut pointer = String::new();
    let mut inspect = Inspect {
        references: SchemaReferences::new(schema).map_err(|why| ArgRefusal {
            pointer: String::new(),
            declared_format: None,
            why,
        })?,
        patterns: BTreeMap::new(),
    };
    walk(
        &[schema],
        arguments,
        &mut pointer,
        0,
        &mut cached_judge,
        &mut scan,
        &mut inspect,
    )?;
    Ok(scan)
}

/// Bound the cross product before schema expansion, regex evaluation or reference searches.
/// References may search the entire schema, so their cost is included in the schema weight.
const MAX_INSPECTION_WORK: usize = 1_000_000;
fn inspection_budget(schema: &Value, arguments: &Value) -> Result<(), ArgWhy> {
    fn weight(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        refs: &mut usize,
        patterns: &mut usize,
    ) -> Result<(), ArgWhy> {
        if depth > MAX_VALUE_DEPTH {
            return Err(ArgWhy::DepthExceeded);
        }
        *nodes = nodes.saturating_add(1 + value.as_str().map_or(0, str::len));
        if *nodes > MAX_INSPECTION_WORK {
            return Err(ArgWhy::WorkExceeded);
        }
        match value {
            Value::Object(map) => {
                *refs += REFERENCES
                    .iter()
                    .filter(|key| map.contains_key(**key))
                    .count();
                if let Some(Value::Object(p)) = map.get("patternProperties") {
                    *patterns = patterns.saturating_add(p.keys().map(String::len).sum::<usize>());
                }
                for (key, child) in map {
                    *nodes = nodes.saturating_add(key.len());
                    if *nodes > MAX_INSPECTION_WORK {
                        return Err(ArgWhy::WorkExceeded);
                    }
                    weight(child, depth + 1, nodes, refs, patterns)?;
                }
            }
            Value::Array(items) => {
                for child in items {
                    weight(child, depth + 1, nodes, refs, patterns)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let (mut schemas, mut refs, mut patterns) = (0, 0, 0);
    weight(schema, 0, &mut schemas, &mut refs, &mut patterns)?;
    let (mut values, mut unused_refs, mut unused_patterns) = (0, 0, 0);
    weight(
        arguments,
        0,
        &mut values,
        &mut unused_refs,
        &mut unused_patterns,
    )?;
    let work = schemas
        .saturating_mul(refs + 1)
        .saturating_add(patterns)
        .saturating_mul(values);
    if work > MAX_INSPECTION_WORK {
        Err(ArgWhy::WorkExceeded)
    } else {
        Ok(())
    }
}

/// A bounded diagnostic excerpt; do not copy hostile argument strings into errors wholesale.
fn excerpt(value: &str) -> String {
    const LIMIT: usize = 256;
    let mut end = value.len().min(LIMIT);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = value[..end].to_string();
    if end < value.len() {
        out.push('…');
    }
    out
}

/// Resource scopes and property patterns compiled once for this walk.
struct Inspect<'a> {
    /// The pinned schema resource index.
    references: SchemaReferences<'a>,
    /// Each distinct `patternProperties` expression, compiled once for this walk.
    patterns: BTreeMap<String, jsonschema::Validator>,
}

/// The value-driven walk. The VALUE drives and the schema rides alongside, which is what lets the
/// undeclared detector see fields the schema never mentioned — a schema-driven walk cannot, by
/// construction, visit a field the schema omits.
fn walk<'a>(
    schemas: &[&'a Value],
    value: &Value,
    pointer: &mut String,
    depth: usize,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
    inspect: &mut Inspect<'a>,
) -> Result<(), ArgRefusal> {
    if depth > MAX_VALUE_DEPTH {
        return Err(ArgRefusal {
            pointer: excerpt(pointer),
            declared_format: None,
            why: ArgWhy::DepthExceeded,
        });
    }

    let nodes = expanded(&inspect.references, schemas).map_err(|why| ArgRefusal {
        pointer: excerpt(pointer),
        declared_format: None,
        why,
    })?;
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&escape_token(k));
                let children =
                    child_for_key(&nodes, k, &mut inspect.patterns).map_err(|why| ArgRefusal {
                        pointer: excerpt(pointer),
                        declared_format: None,
                        why,
                    })?;
                walk(&children, v, pointer, depth + 1, judge, scan, inspect)?;
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
                    &child_for_index(&nodes, i),
                    v,
                    pointer,
                    depth + 1,
                    judge,
                    scan,
                    inspect,
                )?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::String(s) => judge_string(&nodes, s, pointer, judge, scan),
        _ => Ok(()),
    }
}

/// One string leaf: declared first, then the undeclared `http(s)://` detector. `nodes` is the
/// position's schema set already [`expanded`].
fn judge_string(
    nodes: &[&Value],
    s: &str,
    pointer: &str,
    judge: &mut Judge<'_>,
    scan: &mut ArgScan,
) -> Result<(), ArgRefusal> {
    scan.strings_seen += 1;
    let trimmed = s.trim();
    let refused = |declared_format: Option<String>| {
        move |why| ArgRefusal {
            pointer: excerpt(pointer),
            declared_format,
            why,
        }
    };
    let declared = urlish_formats(nodes);
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
            None => Err(ArgWhy::NoHost(excerpt(s))),
        }
        .map_err(refused(None));
    }
    Ok(())
}

/// THE WHATWG SPECIAL SCHEMES: the six a WHATWG URL reader reads by the web rules (a backslash is a
/// slash, any run of slashes after the scheme is skipped, the authority ends at `/`, `\`, `?` or
/// `#`).
const SPECIAL_SCHEMES: [&str; 6] = ["http", "https", "ws", "wss", "ftp", "file"];

/// THE HOST A WHATWG URL READER FINDS IN `value`, read as a fetching client reads it, by the
/// contract's one URL reader (`busbar_contract::net::parse_url`, the reader the host's own
/// destination guard reads with): leading and trailing C0 controls and spaces stripped, every tab
/// and newline removed, a backslash read as a slash under a special scheme and any run of slashes
/// after it skipped, the authority ended at `/`, `?`, `#` or `\`, the host percent-decoded.
/// All six WHATWG special schemes are read so: the contract reads `http`, `https`, `ws` and `wss`
/// itself, `ftp` is read as `http` is, and `file` by [`file_host`].
/// A host outside ASCII is judged as the punycode name a fetching client dials, as the client dials
/// it: `judge_host` maps every host it is handed through UTS-46 ([`dial_host`]).
/// `Some(Some(host))`: the value is a URL naming `host`, lower-cased. `Some(None)`: a URL no reader
/// accepts, refused rather than passed: it opens with any `scheme://`, or with a special scheme
/// and `:` and holds no ASCII whitespace or control character (a raw URL holds none, so prose such
/// as `http: the protocol` is not one), and no host could be read from it. `None`: it names no
/// host.
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
/// case).
fn special_scheme(cleaned: &str) -> Option<(&str, &str)> {
    let (scheme, after) = cleaned.split_once(':')?;
    SPECIAL_SCHEMES
        .iter()
        .any(|s| scheme.eq_ignore_ascii_case(s))
        .then_some((scheme, after))
}

/// Whether `cleaned` opens with an RFC 3986 scheme and `://`: a URL with an authority by its
/// spelling, whether or not a reader accepts the rest.
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
/// `/` and `\`), and runs to the next `/`, `\`, `?` or `#`; an empty one names no host.
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
/// one resolved against a web base.
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
/// string rather than a search, so a URL merely mentioned inside free text does not make the whole
/// value one.
fn starts_with_http(v: &str) -> bool {
    v.get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || v.get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

/// The WHATWG URL parser's first step, as a connecting stack applies it: leading and trailing C0
/// controls and spaces trimmed, then every tab, LF and CR removed (`ht\ttp://` is `http://`).
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
                Some(None) => Err(ArgWhy::NoHost(excerpt(value))),
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
/// then the host.
fn judge_absolute(url: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let cleaned = whatwg_cleaned(url);
    if !http_scheme(&cleaned) {
        return Err(ArgWhy::Scheme(excerpt(url)));
    }

    let host = if cleaned.contains("://") {
        extract_normalized_host(&cleaned)
    } else {
        busbar_contract::net::parse_url(&cleaned)
            .ok()
            .map(|p| p.host)
    }
    .ok_or_else(|| ArgWhy::NoHost(excerpt(url)))?;
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
/// the plane reads the host and holds no rule about it.
fn judge_host(raw: &str, judge: &mut Judge<'_>) -> Result<(), ArgWhy> {
    let host = dial_host(raw).ok_or_else(|| ArgWhy::NoHost(excerpt(raw)))?;
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
    let verdict = judge(dest);
    if verdict == Some(DEST_ALLOWED) {
        return Ok(());
    }
    let host = excerpt(host);
    match verdict {
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
/// ([`normalize_host`]), then, outside ASCII, mapped through UTS-46 by the contract's
/// `url_host_to_ascii`, with the one trailing root dot the
/// mapping can make dropped.
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
/// the same reader: an IPv6 literal is bracketed so the reader sees an authority rather than a
/// host:port, and everything else is passed as written.
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
/// [`normalize_host`] to unwrap.
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
/// containing either cannot forge a different pointer than the one it is at.
fn escape_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

/// Every URL-ish `format` declared for this position, in declaration order. Overlapping property
/// patterns apply together, so a relative-reference declaration cannot mask a hostname declaration.
fn urlish_formats(nodes: &[&Value]) -> Vec<(String, Urlish)> {
    let mut out = Vec::new();
    for node in nodes {
        let Some(format) = node.get("format").and_then(Value::as_str) else {
            continue;
        };

        let kind = match format.to_ascii_lowercase().as_str() {
            "uri-reference" | "iri-reference" => Urlish::Reference,
            "hostname" | "idn-hostname" | "ipv4" | "ipv6" => Urlish::Host,
            "uri" | "iri" | "url" => Urlish::AbsoluteUrl,
            _ => continue,
        };
        out.push((format.to_string(), kind));
    }
    out
}

/// A schema node plus every subschema that applies at the SAME position, so a URL-ish format
/// hidden behind any of them is still found: the `allOf`/`anyOf`/`oneOf` branches, the
/// `if`/`then`/`else` arms, the `dependentSchemas` (and draft-7 `dependencies`) schemas, and the
/// target of every `$ref`/`$dynamicRef`/`$recursiveRef`, resolved inside the pinned resource index. Every arm counts,
/// whichever one a value would select, so a declaration cannot be hidden behind a condition. A node
/// is taken once, so a reference cycle ends instead of spending the budget; a reference that does
/// not resolve refuses ([`ArgWhy::SchemaRef`]) rather than leaving its declaration unread.
fn expanded<'a>(
    references: &SchemaReferences<'a>,
    schemas: &[&'a Value],
) -> Result<Vec<&'a Value>, ArgWhy> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    expand_into(
        references,
        schemas,
        &mut out,
        &mut seen,
        MAX_COMBINATOR_DEPTH,
    )?;
    Ok(out)
}

/// The keywords whose value is an array of subschemas applying at the same position.
const SAME_POSITION_LISTS: [&str; 3] = ["allOf", "anyOf", "oneOf"];

/// The keywords whose value is one subschema applying at the same position.
const SAME_POSITION_SINGLES: [&str; 3] = ["if", "then", "else"];

/// The keywords whose value maps a property name to a subschema applying at the same position.
const SAME_POSITION_MAPS: [&str; 2] = ["dependentSchemas", "dependencies"];

/// The keywords that name another schema to apply at the same position.
const REFERENCES: [&str; 3] = ["$ref", "$dynamicRef", "$recursiveRef"];

fn expand_into<'a>(
    references: &SchemaReferences<'a>,
    schemas: &[&'a Value],
    out: &mut Vec<&'a Value>,
    seen: &mut std::collections::BTreeSet<*const Value>,
    budget: usize,
) -> Result<(), ArgWhy> {
    if budget == 0 {
        return if schemas.is_empty() {
            Ok(())
        } else {
            Err(ArgWhy::SchemaDepth)
        };
    }
    for &node in schemas {
        if !node.is_object() || !seen.insert(node as *const Value) {
            continue;
        }
        out.push(node);
        let mut applied: Vec<&'a Value> = Vec::new();
        for key in SAME_POSITION_LISTS {
            if let Some(branches) = node.get(key).and_then(Value::as_array) {
                applied.extend(branches);
            }
        }
        for key in SAME_POSITION_SINGLES {
            if let Some(arm) = node.get(key) {
                applied.push(arm);
            }
        }
        for key in SAME_POSITION_MAPS {
            if let Some(dependents) = node.get(key).and_then(Value::as_object) {
                applied.extend(dependents.values());
            }
        }
        for key in REFERENCES {
            if let Some(reference) = node.get(key) {
                let target = reference
                    .as_str()
                    .and_then(|spelled| references.resolve(node, spelled))
                    .ok_or_else(|| {
                        ArgWhy::SchemaRef(
                            reference
                                .as_str()
                                .map_or_else(|| "non-string reference".to_string(), excerpt),
                        )
                    })?;
                applied.push(target);
                // Dynamic scope can select an outer anchor. Inspect every possible pinned
                // override as well as the static target; never silently treat it as $ref.
                if key == "$dynamicRef" {
                    if let Some(name) = target.get("$dynamicAnchor").and_then(Value::as_str) {
                        applied.extend(
                            references
                                .dynamic
                                .iter()
                                .filter_map(|(anchor, schema)| (anchor == name).then_some(*schema)),
                        );
                    }
                } else if key == "$recursiveRef"
                    && target.get("$recursiveAnchor").and_then(Value::as_bool) == Some(true)
                {
                    applied.extend(references.recursive.iter().copied());
                }
            }
        }
        applied.retain(|schema| schema.is_object());
        expand_into(references, &applied, out, seen, budget - 1)?;
    }
    Ok(())
}

/// Index only schema-bearing keywords: example/default/enum objects are data, not resources.
/// All identifiers are unique within their resource scope. Ambiguity refuses the call.
struct SchemaReferences<'a> {
    bases: BTreeMap<*const Value, std::sync::Arc<url::Url>>,
    resources: BTreeMap<String, &'a Value>,
    anchors: BTreeMap<String, &'a Value>,
    dynamic: Vec<(String, &'a Value)>,
    recursive: Vec<&'a Value>,
    identifier_bytes: usize,
}

impl<'a> SchemaReferences<'a> {
    fn new(root: &'a Value) -> Result<Self, ArgWhy> {
        let mut index = Self {
            bases: BTreeMap::new(),
            resources: BTreeMap::new(),
            anchors: BTreeMap::new(),
            dynamic: Vec::new(),
            recursive: Vec::new(),
            identifier_bytes: 0,
        };
        let base = url::Url::parse("https://schema.invalid/__pinned__/")
            .map_err(|_| ArgWhy::SchemaRef("schema base".into()))?;
        let base = std::sync::Arc::new(base);
        index.resources.insert(base.to_string(), root);
        index.visit(root, &base)?;
        Ok(index)
    }

    fn charge_identifier(&mut self, bytes: usize) -> Result<(), ArgWhy> {
        self.identifier_bytes = self.identifier_bytes.saturating_add(bytes);
        if self.identifier_bytes > MAX_INSPECTION_WORK {
            return Err(ArgWhy::WorkExceeded);
        }
        Ok(())
    }

    fn insert_unique(
        map: &mut BTreeMap<String, &'a Value>,
        key: String,
        node: &'a Value,
    ) -> Result<(), ArgWhy> {
        if map.get(&key).is_some_and(|old| !std::ptr::eq(*old, node)) {
            return Err(ArgWhy::SchemaRef(excerpt(&key)));
        }
        map.insert(key, node);
        Ok(())
    }

    fn visit(&mut self, node: &'a Value, parent: &std::sync::Arc<url::Url>) -> Result<(), ArgWhy> {
        if !node.is_object() && !node.is_boolean() {
            return Ok(());
        }
        let mut base = parent.clone();
        if node.get("$id").is_some()
            && node.get("id").is_some()
            && node.get("$id") != node.get("id")
        {
            return Err(ArgWhy::SchemaRef("conflicting id and $id".into()));
        }
        if let Some(id) = node.get("$id").or_else(|| node.get("id")) {
            let mut resolved = id
                .as_str()
                .and_then(|id| schema_uri(parent, id))
                .ok_or_else(|| ArgWhy::SchemaRef("invalid schema identifier".into()))?;
            if resolved
                .fragment()
                .is_some_and(|fragment| !fragment.is_empty())
            {
                self.charge_identifier(resolved.as_str().len())?;
                Self::insert_unique(&mut self.anchors, resolved.to_string(), node)?;
                // Legacy fragment identifiers name anchors, not separate resources.
                resolved.set_fragment(None);
                if resolved != **parent {
                    return Err(ArgWhy::SchemaRef(
                        "fragment identifier changes resource".into(),
                    ));
                }
            } else {
                resolved.set_fragment(None);
                base = std::sync::Arc::new(resolved);
                self.charge_identifier(base.as_str().len().saturating_mul(2))?;
                Self::insert_unique(&mut self.resources, base.to_string(), node)?;
            }
        }
        self.bases.insert(node as *const Value, base.clone());
        for key in ["$anchor", "$dynamicAnchor"] {
            if let Some(anchor) = node.get(key) {
                let name = anchor
                    .as_str()
                    .filter(|name| {
                        !name.is_empty()
                            && name
                                .bytes()
                                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c))
                    })
                    .ok_or_else(|| ArgWhy::SchemaRef("invalid anchor".into()))?;
                let mut address = (*base).clone();
                address.set_fragment(Some(name));
                self.charge_identifier(address.as_str().len())?;
                Self::insert_unique(&mut self.anchors, address.to_string(), node)?;
                if key == "$dynamicAnchor" {
                    self.dynamic.push((name.to_string(), node));
                }
            }
        }
        if node.get("$recursiveAnchor").and_then(Value::as_bool) == Some(true) {
            self.recursive.push(node);
        }
        for key in [
            "$defs",
            "definitions",
            "properties",
            "patternProperties",
            "dependentSchemas",
            "dependencies",
        ] {
            if let Some(map) = node.get(key).and_then(Value::as_object) {
                for child in map.values() {
                    self.visit(child, &base)?;
                }
            }
        }
        for key in ["allOf", "anyOf", "oneOf", "prefixItems"] {
            if let Some(array) = node.get(key).and_then(Value::as_array) {
                for child in array {
                    self.visit(child, &base)?;
                }
            }
        }
        for key in [
            "not",
            "if",
            "then",
            "else",
            "contains",
            "propertyNames",
            "additionalProperties",
            "unevaluatedProperties",
            "additionalItems",
            "unevaluatedItems",
            "items",
            "contentSchema",
        ] {
            if let Some(child) = node.get(key) {
                if let Some(array) = child.as_array() {
                    if key == "items" {
                        for child in array {
                            self.visit(child, &base)?;
                        }
                    }
                } else {
                    self.visit(child, &base)?;
                }
            }
        }
        Ok(())
    }

    fn resolve(&self, node: &Value, reference: &str) -> Option<&'a Value> {
        let base = self.bases.get(&(node as *const Value))?;
        let mut address = schema_uri(base, reference)?;
        let fragment = percent_decoded(address.fragment().unwrap_or(""))?;
        address.set_fragment(None);
        let resource = *self.resources.get(address.as_str())?;
        if fragment.is_empty() {
            return Some(resource);
        }
        if fragment.starts_with('/') {
            let target = resource.pointer(&fragment)?;
            return (target.is_object() || target.is_boolean()).then_some(target);
        }
        address.set_fragment(Some(&fragment));
        self.anchors.get(address.as_str()).copied()
    }
}

/// Restrict WHATWG normalization to unambiguous URI spellings. The schema contract uses URI
/// references, so browser-only cleanup (backslashes, whitespace, encoded dot segments) refuses.
fn schema_uri(base: &url::Url, reference: &str) -> Option<url::Url> {
    if reference
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return None;
    }
    percent_decoded(reference)?;
    let document = reference.split('#').next()?;
    if document.to_ascii_lowercase().contains("%2e") {
        return None;
    }
    if reference.starts_with('#') || reference.is_empty() {
        let mut address = base.clone();
        address.set_fragment(reference.strip_prefix('#'));
        return Some(address);
    }
    if let Ok(absolute) = url::Url::parse(reference) {
        // The artificial retrieval URI must never masquerade as a supplied resource.
        if absolute
            .as_str()
            .starts_with("https://schema.invalid/__pinned__/")
        {
            return None;
        }
        if matches!(absolute.scheme(), "http" | "https" | "ftp" | "ws" | "wss") {
            let authority = document
                .split_once("://")?
                .1
                .split('/')
                .next()?
                .split('?')
                .next()?;
            if !schema_authority(&absolute, authority) {
                return None;
            }
        } else if absolute.scheme() == "file" {
            return None;
        }
        return Some(absolute);
    }
    let joined = base.join(reference).ok()?;
    if let Some(network) = document.strip_prefix("//") {
        let authority = network.split('/').next()?.split('?').next()?;
        if !schema_authority(&joined, authority) {
            return None;
        }
    }
    Some(joined)
}

/// Reject browser host rewrites that are not URI host equivalence (numeric aliases, IDNA,
/// percent decoding). Schema identifiers are names, not destinations to dial.
fn schema_authority(address: &url::Url, authority: &str) -> bool {
    let host_port = authority.rsplit('@').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .find(']')
            .map(|end| &host_port[..=end])
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    address
        .host_str()
        .is_some_and(|parsed| parsed.eq_ignore_ascii_case(host))
}

/// A URI fragment with its `%XX` escapes decoded; `None` for a malformed escape or a decoding that
/// is not UTF-8.
fn percent_decoded(fragment: &str) -> Option<String> {
    let bytes = fragment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Named properties and every matching property pattern apply together. `additionalProperties`
/// applies only when neither names the member, as JSON Schema requires, and
/// `unevaluatedProperties` unless that schema itself evaluates the member. `nodes`
/// is the position's schema set already [`expanded`].
fn child_for_key<'a>(
    nodes: &[&'a Value],
    key: &str,
    patterns: &mut BTreeMap<String, jsonschema::Validator>,
) -> Result<Vec<&'a Value>, ArgWhy> {
    let mut out = Vec::new();
    for &node in nodes {
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
            if let Some(extra) = node.get("additionalProperties") {
                covered = true;
                if extra.is_object() {
                    out.push(extra);
                }
            }
        }
        // Only this schema's unconditional local evaluation suppresses its fallback.
        // A sibling branch may fail and therefore contribute no evaluated properties.
        if !covered {
            if let Some(extra) = node.get("unevaluatedProperties").filter(|s| s.is_object()) {
                out.push(extra);
            }
        }
    }
    Ok(out)
}

/// Use the fleet's JSON Schema engine's ECMA-262 translation, not Rust regex syntax. Compile each
/// distinct expression once for this walk; no tool arguments or matchers survive the call.
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
/// (`prefixItems`, or the legacy array form of `items`), otherwise the single `items` schema, and
/// `contains` conservatively applies to every item, and `unevaluatedItems` applies unless that
/// schema itself gives the element an unconditional item schema. `nodes` is
/// the position's schema set already [`expanded`].
fn child_for_index<'a>(nodes: &[&'a Value], index: usize) -> Vec<&'a Value> {
    let mut out = Vec::new();
    for &node in nodes {
        if let Some(contains) = node.get("contains").filter(|schema| schema.is_object()) {
            out.push(contains);
        }
        let tuple = node.get("prefixItems").and_then(Value::as_array);
        let item = if let Some(at) = tuple.and_then(|tuple| tuple.get(index)) {
            Some(at)
        } else {
            match node.get("items") {
                Some(Value::Array(tuple)) => {
                    tuple.get(index).or_else(|| node.get("additionalItems"))
                }
                single => single,
            }
        };
        if let Some(item) = item.filter(|s| s.is_object() || s.is_boolean()) {
            out.push(item);
        } else if let Some(extra) = node.get("unevaluatedItems").filter(|s| s.is_object()) {
            out.push(extra);
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/argguard_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/argguard_audit.rs"]
mod argguard_audit;
