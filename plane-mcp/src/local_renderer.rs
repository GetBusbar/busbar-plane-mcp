// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Local results over pinned original inputs: nonrecursive substitution, whole-string markup
//! normalisation and resumable compact JSON without materialising the amplified text/result.
//! Planning admits at most 64 MiB of virtual text and encoded output, and 65,536 normalization
//! operations, so caller substitutions cannot amplify synchronous work without bound.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;

use crate::revision::Revision;
use serde_json::Value;

/// A range of an immutable original string, never a range of a materialised expansion.
#[derive(Clone, Copy, Debug)]
struct Span {
    source: usize,
    start: usize,
    end: usize,
}

impl Span {
    fn len(self) -> usize {
        self.end - self.start
    }
    fn prefix(self, length: usize) -> Self {
        Self {
            end: self.start + length,
            ..self
        }
    }
}

#[derive(Clone, Default)]
struct Rope(Option<Arc<RopeNode>>);

struct RopeNode {
    len: usize,
    height: usize,
    kind: RopeKind,
}

enum RopeKind {
    Leaf(Span),
    Branch(Rope, Rope),
}

#[derive(Clone, Copy, Debug)]
struct LengthOverflow;

// Bound synchronous planning work before retained-history admission.
const MAX_NORMALISE_OPERATIONS: usize = 65_536;
const MAX_RENDERED_BYTES: usize = 64 * 1024 * 1024;

fn add_rendered(length: Option<usize>, bytes: usize) -> Option<usize> {
    length
        .and_then(|n| n.checked_add(bytes))
        .filter(|n| *n <= MAX_RENDERED_BYTES)
}

impl Rope {
    fn span(span: Span) -> Self {
        if span.len() == 0 {
            return Self::default();
        }
        Self(Some(Arc::new(RopeNode {
            len: span.len(),
            height: 1,
            kind: RopeKind::Leaf(span),
        })))
    }
    fn len(&self) -> usize {
        self.0.as_ref().map_or(0, |node| node.len)
    }
    fn height(&self) -> usize {
        self.0.as_ref().map_or(0, |node| node.height)
    }
    fn branch(left: Self, right: Self) -> Result<Self, LengthOverflow> {
        if left.len() == 0 {
            return Ok(right);
        }
        if right.len() == 0 {
            return Ok(left);
        }
        Ok(Self(Some(Arc::new(RopeNode {
            len: left.len().checked_add(right.len()).ok_or(LengthOverflow)?,
            height: 1 + left.height().max(right.height()),
            kind: RopeKind::Branch(left, right),
        }))))
    }
    fn children(&self) -> (&Self, &Self) {
        match &self.0.as_ref().expect("a non-leaf AVL node").kind {
            RopeKind::Branch(left, right) => (left, right),
            RopeKind::Leaf(_) => unreachable!("an imbalanced AVL side has children"),
        }
    }
    fn balance(left: Self, right: Self) -> Result<Self, LengthOverflow> {
        if left.height() > right.height() + 1 {
            let (ll, lr) = left.children();
            if ll.height() >= lr.height() {
                Self::branch(ll.clone(), Self::branch(lr.clone(), right)?)
            } else {
                let (lrl, lrr) = lr.children();
                Self::branch(
                    Self::branch(ll.clone(), lrl.clone())?,
                    Self::branch(lrr.clone(), right)?,
                )
            }
        } else if right.height() > left.height() + 1 {
            let (rl, rr) = right.children();
            if rr.height() >= rl.height() {
                Self::branch(Self::branch(left, rl.clone())?, rr.clone())
            } else {
                let (rll, rlr) = rl.children();
                Self::branch(
                    Self::branch(left, rll.clone())?,
                    Self::branch(rlr.clone(), rr.clone())?,
                )
            }
        } else {
            Self::branch(left, right)
        }
    }
    fn concat(left: Self, right: Self) -> Result<Self, LengthOverflow> {
        if left.len() == 0 {
            return Ok(right);
        }
        if right.len() == 0 {
            return Ok(left);
        }
        if left.height() > right.height() + 1 {
            let (ll, lr) = left.children();
            Self::balance(ll.clone(), Self::concat(lr.clone(), right)?)
        } else if right.height() > left.height() + 1 {
            let (rl, rr) = right.children();
            Self::balance(Self::concat(left, rl.clone())?, rr.clone())
        } else {
            Self::branch(left, right)
        }
    }
    fn prefix(&self, length: usize) -> Result<Self, LengthOverflow> {
        if length == 0 {
            return Ok(Self::default());
        }
        if length == self.len() {
            return Ok(self.clone());
        }
        match &self.0.as_ref().expect("nonempty prefix").kind {
            RopeKind::Leaf(span) => Ok(Self::span(span.prefix(length))),
            RopeKind::Branch(left, right) => {
                if length <= left.len() {
                    left.prefix(length)
                } else {
                    Self::concat(left.clone(), right.prefix(length - left.len())?)
                }
            }
        }
    }
}

/// The traversal path contains only shared rope nodes. It never holds emitted text.
#[derive(Clone, Default)]
struct RopeCursor {
    todo: Vec<Rope>,
    current: Option<Span>,
    reverse: bool,
}

impl RopeCursor {
    fn new(rope: Rope, reverse: bool) -> Self {
        Self {
            todo: vec![rope],
            current: None,
            reverse,
        }
    }
    fn load(&mut self) -> Option<Span> {
        if let Some(span) = self.current.filter(|span| span.len() != 0) {
            return Some(span);
        }
        while let Some(rope) = self.todo.pop() {
            let Some(node) = rope.0 else { continue };
            match &node.kind {
                RopeKind::Leaf(span) => {
                    self.current = Some(*span);
                    return Some(*span);
                }
                RopeKind::Branch(left, right) => {
                    if self.reverse {
                        self.todo.push(left.clone());
                        self.todo.push(right.clone());
                    } else {
                        self.todo.push(right.clone());
                        self.todo.push(left.clone());
                    }
                }
            }
        }
        self.current = None;
        None
    }
    fn advance(&mut self, bytes: usize) {
        let span = self.current.as_mut().expect("loaded source span");
        if self.reverse {
            span.end -= bytes;
        } else {
            span.start += bytes;
        }
    }
}

#[derive(Clone, Copy)]
enum DemandKind {
    Any,
    Bare,
}

impl DemandKind {
    fn accepts(self, closing: bool) -> bool {
        matches!(self, Self::Any) || !closing
    }
}

#[derive(Clone, Default)]
struct Fixed {
    output: Rope,
    pending: Rope,
}

struct Demand {
    kind: DemandKind,
    fallback: Fixed,
    next: Option<usize>,
}

#[derive(Clone)]
enum Tail {
    Keep(Rope),
    Reset(Fixed),
}

impl Default for Tail {
    fn default() -> Self {
        Self::Keep(Rope::default())
    }
}

/// A source-sized pushdown summary. Each fallback is independent of the incoming opener stack.
#[derive(Clone, Default)]
struct Summary {
    nodes: Arc<Vec<Demand>>,
    demands: Option<usize>,
    tail: Tail,
}

#[derive(Default)]
struct BuildingSummary {
    demands: Option<usize>,
    tail: Tail,
}

struct Operation {
    head: Option<DemandKind>,
    output: Span,
    pending: Span,
    extend_bare: Option<Span>,
}

/// A compiler-owned pending word has one physical suffix, or the synthetic `</` followed by
/// that suffix. Its two ASCII bytes can refer to the removed raw tag's `<` and leading `/`.
/// This fixed-sized cursor never creates a node for each expanded opener.
#[derive(Clone, Copy)]
struct KnownWord {
    spans: [Span; 3],
    count: usize,
}

impl KnownWord {
    fn single(span: Span) -> Self {
        Self {
            spans: [span; 3],
            count: usize::from(span.len() != 0),
        }
    }
    fn extended(opening: Span, slash: Span, pending: Span) -> Self {
        Self {
            spans: [opening, slash, pending],
            count: if pending.len() == 0 { 2 } else { 3 },
        }
    }
    fn is_empty(&self) -> bool {
        self.count == 0
    }
    fn pop<'a>(&mut self, kind: DemandKind, source: &impl Fn(usize) -> &'a str) -> bool {
        let span = self.spans[self.count - 1];
        let closing = source(span.source).as_bytes()[span.end - 1] == b'/';
        if !kind.accepts(closing) {
            return false;
        }
        let mut bytes = if closing { 2 } else { 1 };
        while bytes != 0 {
            let span = &mut self.spans[self.count - 1];
            let consumed = bytes.min(span.len());
            span.end -= consumed;
            bytes -= consumed;
            if span.len() == 0 {
                self.count -= 1;
            }
        }
        true
    }
    fn rope(&self) -> Result<Rope, LengthOverflow> {
        let mut rope = Rope::default();
        for &span in &self.spans[..self.count] {
            rope = Rope::concat(rope, Rope::span(span))?;
        }
        Ok(rope)
    }
}

fn names(byte: Option<&u8>) -> bool {
    crate::sanitize::names_tag(byte)
}

fn head_demand(bytes: &[u8]) -> Option<DemandKind> {
    if names(bytes.first()) {
        Some(DemandKind::Any)
    } else if bytes.first() == Some(&b'/') && names(bytes.get(1)) {
        Some(DemandKind::Bare)
    } else {
        None
    }
}

/// The suffix is a word of bare `<` and closing `</` openers; every other byte makes the
/// preceding prefix permanently inert. A slash can extend only a bare opener.
fn opener_suffix(bytes: &[u8]) -> usize {
    let mut start = 0;
    let mut bare = false;
    for (at, byte) in bytes.iter().copied().enumerate() {
        match byte {
            b'<' => bare = true,
            b'/' if bare => bare = false,
            _ => {
                start = at + 1;
                bare = false;
            }
        }
    }
    start
}

fn operation(source: usize, start: usize, end: usize, original: &str) -> Operation {
    let bytes = &original.as_bytes()[start..end];
    let tag = (0..bytes.len()).find(|&at| {
        if bytes[at] != b'<' {
            return false;
        }
        let name = at + 1 + usize::from(bytes.get(at + 1) == Some(&b'/'));
        names(bytes.get(name))
    });
    let (stable, pending_end) = match tag {
        Some(tag) => (opener_suffix(&bytes[..tag]), tag),
        None => (bytes.len(), bytes.len()),
    };
    Operation {
        head: head_demand(bytes),
        extend_bare: tag
            .filter(|_| stable == 1 && bytes[0] == b'/')
            .map(|tag| Span {
                source,
                start: start + tag,
                end: start + tag + 1,
            }),
        output: Span {
            source,
            start,
            end: start + stable,
        },
        pending: Span {
            source,
            start: start + stable,
            end: start + pending_end,
        },
    }
}

fn fixed_after<'a>(
    mut pending: KnownWord,
    summary: &BuildingSummary,
    nodes: &[Demand],
    source: &impl Fn(usize) -> &'a str,
) -> Result<Fixed, LengthOverflow> {
    let mut demand = summary.demands;
    while let Some(index) = demand {
        let current = &nodes[index];
        if pending.is_empty() {
            return Ok(current.fallback.clone());
        }
        if !pending.pop(current.kind, source) {
            return Ok(Fixed {
                output: Rope::concat(pending.rope()?, current.fallback.output.clone())?,
                pending: current.fallback.pending.clone(),
            });
        }
        demand = current.next;
    }
    match &summary.tail {
        Tail::Keep(push) => Ok(Fixed {
            output: Rope::default(),
            pending: Rope::concat(pending.rope()?, push.clone())?,
        }),
        Tail::Reset(fixed) => Ok(Fixed {
            output: Rope::concat(pending.rope()?, fixed.output.clone())?,
            pending: fixed.pending.clone(),
        }),
    }
}

fn push_before<'a>(
    mut pending: KnownWord,
    summary: &BuildingSummary,
    nodes: &[Demand],
    source: &impl Fn(usize) -> &'a str,
) -> Result<BuildingSummary, LengthOverflow> {
    let mut demand = summary.demands;
    while let Some(index) = demand {
        let current = &nodes[index];
        if pending.is_empty() {
            return Ok(BuildingSummary {
                demands: demand,
                tail: summary.tail.clone(),
            });
        }
        if !pending.pop(current.kind, source) {
            return Ok(BuildingSummary {
                demands: None,
                tail: Tail::Reset(Fixed {
                    output: Rope::concat(pending.rope()?, current.fallback.output.clone())?,
                    pending: current.fallback.pending.clone(),
                }),
            });
        }
        demand = current.next;
    }
    Ok(BuildingSummary {
        demands: None,
        tail: match &summary.tail {
            Tail::Keep(push) => Tail::Keep(Rope::concat(pending.rope()?, push.clone())?),
            Tail::Reset(fixed) => Tail::Reset(Fixed {
                output: Rope::concat(pending.rope()?, fixed.output.clone())?,
                pending: fixed.pending.clone(),
            }),
        },
    })
}

fn compile_summary<'a>(
    span: Span,
    source: &impl Fn(usize) -> &'a str,
) -> Result<Summary, LengthOverflow> {
    let text = source(span.source);
    let mut operations = Vec::new();
    let mut start = span.start;
    for (at, byte) in text.as_bytes()[span.start..span.end].iter().enumerate() {
        if *byte == b'>' {
            if operations.len() == MAX_NORMALISE_OPERATIONS {
                return Err(LengthOverflow);
            }
            let end = span.start + at + 1;
            operations.push(operation(span.source, start, end, text));
            start = end;
        }
    }
    let mut summary = BuildingSummary::default();
    let mut nodes = Vec::new();
    for operation in operations.into_iter().rev() {
        let pending = KnownWord::single(operation.pending);
        if let Some(opening) = operation.extend_bare {
            let fixed = fixed_after(pending, &summary, &nodes, source)?;
            let fallback = Fixed {
                output: Rope::concat(Rope::span(operation.output), fixed.output)?,
                pending: fixed.pending,
            };
            let success = push_before(
                KnownWord::extended(opening, operation.output, operation.pending),
                &summary,
                &nodes,
                source,
            )?;
            let index = nodes.len();
            nodes.push(Demand {
                kind: DemandKind::Bare,
                fallback,
                next: success.demands,
            });
            summary = BuildingSummary {
                demands: Some(index),
                tail: success.tail,
            };
        } else if let Some(kind) = operation.head {
            let fixed = fixed_after(pending, &summary, &nodes, source)?;
            let fallback = Fixed {
                output: Rope::concat(Rope::span(operation.output), fixed.output)?,
                pending: fixed.pending,
            };
            let index = nodes.len();
            nodes.push(Demand {
                kind,
                fallback,
                next: summary.demands,
            });
            summary.demands = Some(index);
        } else if operation.output.len() == 0 {
            summary = push_before(pending, &summary, &nodes, source)?;
        } else {
            let fixed = fixed_after(pending, &summary, &nodes, source)?;
            summary = BuildingSummary {
                demands: None,
                tail: Tail::Reset(Fixed {
                    output: Rope::concat(Rope::span(operation.output), fixed.output)?,
                    pending: fixed.pending,
                }),
            };
        }
    }
    Ok(Summary {
        nodes: Arc::new(nodes),
        demands: summary.demands,
        tail: summary.tail,
    })
}

struct PendingFrame {
    original: Rope,
    remaining: usize,
    reverse: RopeCursor,
}

#[derive(Default)]
struct Openers(Vec<PendingFrame>);

impl Openers {
    fn push(&mut self, rope: Rope) {
        if rope.len() != 0 {
            self.0.push(PendingFrame {
                remaining: rope.len(),
                reverse: RopeCursor::new(rope.clone(), true),
                original: rope,
            });
        }
    }
    fn pop<'a>(&mut self, kind: DemandKind, source: &impl Fn(usize) -> &'a str) -> bool {
        let Some(frame) = self.0.last_mut() else {
            return false;
        };
        let span = frame.reverse.load().expect("nonempty pending frame");
        let closing = source(span.source).as_bytes()[span.end - 1] == b'/';
        if !kind.accepts(closing) {
            return false;
        }
        let mut bytes = if closing { 2 } else { 1 };
        frame.remaining -= bytes;
        while bytes != 0 {
            let span = frame.reverse.load().expect("complete pending opener");
            let consumed = bytes.min(span.len());
            frame.reverse.advance(consumed);
            bytes -= consumed;
        }
        if frame.remaining == 0 {
            self.0.pop();
        }
        true
    }
    fn flush(&mut self, output: &mut Vec<Rope>) -> Result<(), LengthOverflow> {
        for frame in self.0.drain(..) {
            output.push(frame.original.prefix(frame.remaining)?);
        }
        Ok(())
    }
    fn apply<'a>(
        &mut self,
        summary: &Summary,
        output: &mut Vec<Rope>,
        source: &impl Fn(usize) -> &'a str,
    ) -> Result<(), LengthOverflow> {
        let mut demand = summary.demands;
        while let Some(index) = demand {
            let current = &summary.nodes[index];
            if !self.pop(current.kind, source) {
                self.flush(output)?;
                output.push(current.fallback.output.clone());
                self.push(current.fallback.pending.clone());
                return Ok(());
            }
            demand = current.next;
        }
        match &summary.tail {
            Tail::Keep(push) => self.push(push.clone()),
            Tail::Reset(fixed) => {
                self.flush(output)?;
                output.push(fixed.output.clone());
                self.push(fixed.pending.clone());
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SourceSummary {
    first: usize,
    last: usize,
    middle: Summary,
}

fn source_summary<'a>(
    span: Span,
    source: &impl Fn(usize) -> &'a str,
) -> Result<Option<SourceSummary>, LengthOverflow> {
    let bytes = &source(span.source).as_bytes()[span.start..span.end];
    let Some(first) = bytes.iter().position(|byte| *byte == b'>') else {
        return Ok(None);
    };
    let last = bytes
        .iter()
        .rposition(|byte| *byte == b'>')
        .expect("first closing bracket exists");
    let first = span.start + first;
    let last = span.start + last;
    let middle = compile_summary(
        Span {
            start: first + 1,
            end: last + 1,
            ..span
        },
        source,
    )?;
    Ok(Some(SourceSummary {
        first,
        last,
        middle,
    }))
}

/// Select a virtual range without copying its bytes. Boundary fragments are bounded by the
/// physical template's substitution sites, even when an argument's value is repeated.
fn range_rope(parts: &[Span], from: usize, to: usize) -> Result<Rope, LengthOverflow> {
    let mut at = 0usize;
    let mut result = Rope::default();
    for part in parts {
        let end = at.checked_add(part.len()).ok_or(LengthOverflow)?;
        let start = from.max(at);
        let stop = to.min(end);
        if start < stop {
            result = Rope::concat(
                result,
                Rope::span(Span {
                    source: part.source,
                    start: part.start + start - at,
                    end: part.start + stop - at,
                }),
            )?;
        }
        at = end;
        if at >= to {
            break;
        }
    }
    Ok(result)
}

fn boundary_segment<'a>(
    parts: &[Span],
    stack: &mut Openers,
    output: &mut Vec<Rope>,
    source: &impl Fn(usize) -> &'a str,
) -> Result<(), LengthOverflow> {
    let mut first = [0u8; 2];
    let mut first_len = 0;
    let mut at = 0usize;
    let mut suffix_start = 0usize;
    let mut bare = false;

    let mut candidate: Option<(usize, usize, bool)> = None;
    let mut tag = None;
    'parts: for part in parts {
        for byte in source(part.source).as_bytes()[part.start..part.end]
            .iter()
            .copied()
        {
            let next = at.checked_add(1).ok_or(LengthOverflow)?;
            if first_len < first.len() {
                first[first_len] = byte;
                first_len += 1;
            }
            if let Some((start, before, slash)) = candidate {
                if names(Some(&byte)) {
                    tag = Some((start, before));
                    break 'parts;
                }
                if byte == b'/' && !slash {
                    candidate = Some((start, before, true));
                } else {
                    candidate = None;
                }
            }
            if byte == b'<' {
                candidate = Some((at, suffix_start, false));
            }
            match byte {
                b'<' => bare = true,
                b'/' if bare => bare = false,
                _ => {
                    suffix_start = next;
                    bare = false;
                }
            }
            at = next;
        }
    }
    if let Some(kind) = head_demand(&first[..first_len]) {
        if stack.pop(kind, source) {
            return Ok(());
        }
    }
    if let Some((tag_start, stable_end)) = tag {
        if stable_end == 1 && first[0] == b'/' && stack.pop(DemandKind::Bare, source) {
            let closing = Rope::concat(
                range_rope(parts, tag_start, tag_start + 1)?,
                range_rope(parts, 0, 1)?,
            )?;
            stack.push(Rope::concat(
                closing,
                range_rope(parts, stable_end, tag_start)?,
            )?);
            return Ok(());
        }
        if stable_end != 0 {
            stack.flush(output)?;
            output.push(range_rope(parts, 0, stable_end)?);
        }
        stack.push(range_rope(parts, stable_end, tag_start)?);
    } else {
        stack.flush(output)?;
        output.push(range_rope(parts, 0, at)?);
    }
    Ok(())
}

/// Normalise the virtual concatenation, sharing each original source's interior summary across
/// repeated argument occurrences. The only non-source-sized state is one shared-rope frame per
/// physical substitution site; no expanded opener stack or expanded output string is allocated.
fn normalise_spans<'a>(
    pieces: &[Span],
    reusable: &[bool],
    cache: &mut HashMap<usize, Option<SourceSummary>>,
    source: &impl Fn(usize) -> &'a str,
) -> Result<Vec<Rope>, LengthOverflow> {
    let mut stack = Openers::default();
    let mut output = Vec::new();
    let mut boundary = Vec::new();
    for &piece in pieces {
        if piece.len() == 0 {
            continue;
        }
        let summary = if reusable[piece.source]
            && piece.start == 0
            && piece.end == source(piece.source).len()
        {
            if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(piece.source) {
                entry.insert(source_summary(piece, source)?);
            }
            cache
                .get(&piece.source)
                .expect("cached source summary")
                .clone()
        } else {
            source_summary(piece, source)?
        };
        let Some(summary) = summary else {
            boundary.push(piece);
            continue;
        };
        boundary.push(Span {
            end: summary.first + 1,
            ..piece
        });
        boundary_segment(&boundary, &mut stack, &mut output, source)?;
        boundary.clear();
        stack.apply(&summary.middle, &mut output, source)?;
        if summary.last + 1 < piece.end {
            boundary.push(Span {
                start: summary.last + 1,
                ..piece
            });
        }
    }
    stack.flush(&mut output)?;

    for piece in boundary {
        output.push(Rope::span(piece));
    }
    output.retain(|rope| rope.len() != 0);
    Ok(output)
}

#[derive(Clone, Copy)]
enum ConfigField {
    Description,
    Template,
    Role(usize),
    Text(usize),
    Data(usize),
    Mime(usize),
    EmbeddedUri(usize),
    EmbeddedMime(usize),
    EmbeddedText(usize),
    EmbeddedBlob(usize),
    ResourceText,
    ResourceBlob,
    ResourceMime,
}

#[derive(Clone, Copy)]
enum Selection {
    Prompt { server: usize, entry: usize },
    Resource { server: usize, entry: usize },
    ResourceTemplate { server: usize, entry: usize },
}

#[derive(Clone, Copy)]
enum Original {
    Config(ConfigField),
    Argument(usize),
    Binding(usize),
    Uri,
}

struct Input {
    held: Arc<crate::plane_door::Held>,
    selection: Selection,
    id: Value,

    params: Option<Value>,
    arguments: Vec<String>,
    bindings: Vec<String>,
    uri: String,
    originals: Vec<Original>,
    reusable: Vec<bool>,
}

impl Input {
    fn prompt(&self) -> &crate::tools_config::PromptAllowCfg {
        let Selection::Prompt { server, entry } = self.selection else {
            unreachable!("prompt field")
        };
        self.held
            .section
            .servers
            .get_index(server)
            .expect("pinned server")
            .1
            .prompts_allow
            .get_index(entry)
            .expect("pinned prompt")
            .1
    }
    fn message(&self, index: usize) -> &crate::tools_config::PromptMessageCfg {
        &self.prompt().messages[index]
    }
    fn embedded(&self, index: usize) -> &crate::tools_config::PromptResourceCfg {
        let crate::tools_config::PromptContentCfg::Resource { resource } =
            &self.message(index).content
        else {
            unreachable!("embedded resource field")
        };
        resource
    }
    fn config(&self, field: ConfigField) -> &str {
        use crate::tools_config::PromptContentCfg;
        match field {
            ConfigField::Description => self.prompt().description.as_deref().unwrap_or_default(),
            ConfigField::Template => self.prompt().template.as_deref().unwrap_or_default(),
            ConfigField::Role(index) => &self.message(index).role,
            ConfigField::Text(index) => match &self.message(index).content {
                PromptContentCfg::Text { text } => text,
                _ => unreachable!("text message field"),
            },
            ConfigField::Data(index) => match &self.message(index).content {
                PromptContentCfg::Image { data, .. } | PromptContentCfg::Audio { data, .. } => data,
                _ => unreachable!("opaque media data"),
            },
            ConfigField::Mime(index) => match &self.message(index).content {
                PromptContentCfg::Image { mime_type, .. }
                | PromptContentCfg::Audio { mime_type, .. } => mime_type,
                _ => unreachable!("opaque media mime"),
            },
            ConfigField::EmbeddedUri(index) => &self.embedded(index).uri,
            ConfigField::EmbeddedMime(index) => self
                .embedded(index)
                .mime_type
                .as_deref()
                .unwrap_or_default(),
            ConfigField::EmbeddedText(index) => {
                self.embedded(index).text.as_deref().unwrap_or_default()
            }
            ConfigField::EmbeddedBlob(index) => {
                self.embedded(index).blob.as_deref().unwrap_or_default()
            }
            ConfigField::ResourceText | ConfigField::ResourceBlob | ConfigField::ResourceMime => {
                match self.selection {
                    Selection::Resource { server, entry } => {
                        let resource = self
                            .held
                            .section
                            .servers
                            .get_index(server)
                            .expect("pinned server")
                            .1
                            .resources_allow
                            .get_index(entry)
                            .expect("pinned resource")
                            .1;
                        match field {
                            ConfigField::ResourceText => {
                                resource.text.as_deref().unwrap_or_default()
                            }
                            ConfigField::ResourceBlob => {
                                resource.blob.as_deref().unwrap_or_default()
                            }
                            ConfigField::ResourceMime => {
                                resource.mime_type.as_deref().unwrap_or_default()
                            }
                            _ => unreachable!(),
                        }
                    }
                    Selection::ResourceTemplate { server, entry } => {
                        let resource = self
                            .held
                            .section
                            .servers
                            .get_index(server)
                            .expect("pinned server")
                            .1
                            .resource_templates_allow
                            .get_index(entry)
                            .expect("pinned template")
                            .1;
                        match field {
                            ConfigField::ResourceText => {
                                resource.text.as_deref().unwrap_or_default()
                            }
                            ConfigField::ResourceMime => {
                                resource.mime_type.as_deref().unwrap_or_default()
                            }
                            _ => unreachable!("resource templates contain no blob"),
                        }
                    }
                    Selection::Prompt { .. } => unreachable!("resource field"),
                }
            }
        }
    }
    fn source(&self, index: usize) -> &str {
        match self.originals[index] {
            Original::Config(field) => self.config(field),
            Original::Argument(index) => &self.arguments[index],
            Original::Binding(index) => &self.bindings[index],
            Original::Uri => &self.uri,
        }
    }
    fn register(&mut self, original: Original, reusable: bool) -> usize {
        let index = self.originals.len();
        self.originals.push(original);
        self.reusable.push(reusable);
        index
    }
    fn take_arguments(&mut self) -> BTreeMap<String, usize> {
        let mut found = Vec::new();
        if let Some(arguments) = self
            .params
            .as_mut()
            .and_then(|params| params.get_mut("arguments"))
            .and_then(Value::as_object_mut)
        {
            for (name, value) in arguments {
                if let Value::String(value) = value {
                    found.push((name.clone(), std::mem::take(value)));
                }
            }
        }
        let mut names = BTreeMap::new();
        for (name, value) in found {
            let argument = self.arguments.len();
            self.arguments.push(value);
            let source = self.register(Original::Argument(argument), true);
            names.insert(name, source);
        }
        names
    }
}

enum Part {
    Raw(&'static [u8]),
    Id(Vec<u8>),
    String(Vec<Rope>),
}

struct Plan {
    parts: Vec<Part>,
    len: usize,
}

struct Builder {
    input: Input,
    substitutions: BTreeMap<String, usize>,
    summaries: HashMap<usize, Option<SourceSummary>>,
    work_bytes: usize,
    work_operations: usize,
    parts: Vec<Part>,
}

fn substitution_spans(
    input: &Input,
    original: usize,
    bindings: &BTreeMap<String, usize>,
) -> Vec<Span> {
    let template = input.source(original);
    let mut opening = None;
    let mut copied = 0;
    let mut pieces = Vec::new();
    for (at, byte) in template.as_bytes().iter().enumerate() {
        match *byte {
            b'{' => opening = Some(at),
            b'}' => {
                if let Some(start) = opening.take() {
                    if let Some(&bound) = bindings.get(&template[start + 1..at]) {
                        pieces.push(Span {
                            source: original,
                            start: copied,
                            end: start,
                        });
                        pieces.push(Span {
                            source: bound,
                            start: 0,
                            end: input.source(bound).len(),
                        });
                        copied = at + 1;
                    }
                }
            }
            _ => {}
        }
    }
    pieces.push(Span {
        source: original,
        start: copied,
        end: template.len(),
    });
    pieces
}

impl Builder {
    fn raw(&mut self, bytes: &'static [u8]) {
        self.parts.push(Part::Raw(bytes));
    }
    fn field(
        &mut self,
        field: ConfigField,
        substitute: bool,
        normalise: bool,
    ) -> Result<(), LengthOverflow> {
        let original = self.input.register(Original::Config(field), false);
        self.string(original, substitute, normalise)
    }
    fn string(
        &mut self,
        original: usize,
        substitute: bool,
        normalise: bool,
    ) -> Result<(), LengthOverflow> {
        let pieces = if substitute {
            substitution_spans(&self.input, original, &self.substitutions)
        } else {
            vec![Span {
                source: original,
                start: 0,
                end: self.input.source(original).len(),
            }]
        };
        // Charge virtual input before normalization, including text that stripping later removes.
        for piece in &pieces {
            self.work_bytes = self
                .work_bytes
                .checked_sub(piece.len())
                .ok_or(LengthOverflow)?;
            if normalise && !self.summaries.contains_key(&piece.source) {
                let operations = self.input.source(piece.source).as_bytes()[piece.start..piece.end]
                    .iter()
                    .filter(|byte| **byte == b'>')
                    .count();
                self.work_operations = self
                    .work_operations
                    .checked_sub(operations)
                    .ok_or(LengthOverflow)?;
            }
        }
        let ropes = if normalise {
            let input = &self.input;
            normalise_spans(&pieces, &input.reusable, &mut self.summaries, &|index| {
                input.source(index)
            })?
        } else {
            pieces.into_iter().map(Rope::span).collect()
        };
        self.parts.push(Part::String(ropes));
        Ok(())
    }
    fn finish(mut self) -> Result<Local, crate::tool_arrival::Refusal> {
        self.raw(b"}");

        self.input.params = None;
        let input = Arc::new(self.input);
        let mut length = Some(0usize);
        for part in &self.parts {
            match part {
                Part::Raw(bytes) => length = add_rendered(length, bytes.len()),
                Part::Id(bytes) => length = add_rendered(length, bytes.len()),
                Part::String(ropes) => {
                    let mut cursor = RopeString::default();
                    cursor.write_with(ropes, &|index| input.source(index), |bytes| {
                        length = add_rendered(length, bytes.len());
                        if length.is_some() {
                            bytes.len()
                        } else {
                            0
                        }
                    });
                }
            }
            if length.is_none() {
                return Err(unrepresentable(&input.id));
            }
        }
        Ok(Local {
            input,
            plan: Arc::new(Plan {
                parts: self.parts,
                len: length.expect("checked length"),
            }),
            cursor: Delivery::default(),
        })
    }
    fn envelope(&mut self) {
        self.raw(b"{\"id\":");
        self.parts
            .push(Part::Id(crate::codec::json(&self.input.id)));
        self.raw(b",\"jsonrpc\":\"2.0\",\"result\":{");
    }
    fn prompt_result(&mut self, legacy: bool) -> Result<(), LengthOverflow> {
        use crate::tools_config::PromptContentCfg;
        self.envelope();
        if self.input.prompt().description.is_some() {
            self.raw(b"\"description\":");
            self.field(ConfigField::Description, false, true)?;
            self.raw(b",");
        }
        self.raw(b"\"messages\":[");
        let messages = self.input.prompt().messages.len();
        if messages == 0 {
            self.raw(b"{\"content\":{\"text\":");
            self.field(ConfigField::Template, true, true)?;
            self.raw(b",\"type\":\"text\"},\"role\":\"user\"}");
        }
        for index in 0..messages {
            if index != 0 {
                self.raw(b",");
            }
            let shape = match &self.input.message(index).content {
                PromptContentCfg::Text { .. } => 0,
                PromptContentCfg::Image { .. } => 1,
                PromptContentCfg::Audio { .. } => 2,
                PromptContentCfg::Resource { .. } => 3,
            };
            self.raw(b"{\"content\":{");
            match shape {
                0 => {
                    self.raw(b"\"text\":");
                    self.field(ConfigField::Text(index), true, true)?;
                    self.raw(b",\"type\":\"text\"}");
                }
                1 | 2 => {
                    self.raw(b"\"data\":");
                    self.field(ConfigField::Data(index), false, false)?;
                    self.raw(b",\"mimeType\":");
                    self.field(ConfigField::Mime(index), false, false)?;
                    self.raw(if shape == 1 {
                        b",\"type\":\"image\"}"
                    } else {
                        b",\"type\":\"audio\"}"
                    });
                }
                _ => {
                    let resource = self.input.embedded(index);
                    let (blob, mime, text) = (
                        resource.blob.is_some(),
                        resource.mime_type.is_some(),
                        resource.text.is_some(),
                    );
                    self.raw(b"\"resource\":{");
                    let mut previous = false;
                    if blob {
                        self.raw(b"\"blob\":");
                        self.field(ConfigField::EmbeddedBlob(index), false, false)?;
                        previous = true;
                    }
                    if mime {
                        if previous {
                            self.raw(b",");
                        }
                        self.raw(b"\"mimeType\":");
                        self.field(ConfigField::EmbeddedMime(index), false, false)?;
                        previous = true;
                    }
                    if text {
                        if previous {
                            self.raw(b",");
                        }
                        self.raw(b"\"text\":");
                        self.field(ConfigField::EmbeddedText(index), true, true)?;
                        previous = true;
                    }
                    if previous {
                        self.raw(b",");
                    }
                    self.raw(b"\"uri\":");
                    self.field(ConfigField::EmbeddedUri(index), true, true)?;
                    self.raw(b"},\"type\":\"resource\"}");
                }
            }
            self.raw(b",\"role\":");
            self.field(ConfigField::Role(index), false, false)?;
            self.raw(b"}");
        }
        self.raw(b"]");
        if !legacy {
            self.raw(b",\"resultType\":\"complete\"");
        }
        self.raw(b"}");
        Ok(())
    }
    fn resource_result(&mut self, legacy: bool) -> Result<(), LengthOverflow> {
        let (blob, mime, substitute) = match self.input.selection {
            Selection::Resource { server, entry } => {
                let resource = self
                    .input
                    .held
                    .section
                    .servers
                    .get_index(server)
                    .expect("pinned server")
                    .1
                    .resources_allow
                    .get_index(entry)
                    .expect("pinned resource")
                    .1;
                (resource.blob.is_some(), resource.mime_type.is_some(), false)
            }
            Selection::ResourceTemplate { server, entry } => {
                let resource = self
                    .input
                    .held
                    .section
                    .servers
                    .get_index(server)
                    .expect("pinned server")
                    .1
                    .resource_templates_allow
                    .get_index(entry)
                    .expect("pinned template")
                    .1;
                (false, resource.mime_type.is_some(), true)
            }
            Selection::Prompt { .. } => unreachable!("resource result"),
        };
        self.envelope();
        if !legacy {
            self.raw(b"\"cacheScope\":\"private\",");
        }
        self.raw(b"\"contents\":[{");
        let mut previous = false;
        if blob {
            self.raw(b"\"blob\":");
            self.field(ConfigField::ResourceBlob, false, false)?;
            previous = true;
        }
        if mime {
            if previous {
                self.raw(b",");
            }
            self.raw(b"\"mimeType\":");
            self.field(ConfigField::ResourceMime, false, false)?;
            previous = true;
        }
        if !blob {
            if previous {
                self.raw(b",");
            }
            self.raw(b"\"text\":");
            self.field(ConfigField::ResourceText, substitute, true)?;
        }
        self.raw(b",\"uri\":");
        let uri = self.input.register(Original::Uri, false);
        self.string(uri, false, false)?;
        self.raw(b"}]");
        if !legacy {
            self.raw(b",\"resultType\":\"complete\",\"ttlMs\":0");
        }
        self.raw(b"}");
        Ok(())
    }
}

fn unrepresentable(id: &Value) -> crate::tool_arrival::Refusal {
    crate::call::error(
        500,
        id,
        crate::codec::CODE_REFUSED,
        "The local result exceeds the rendering work or encoded-length budget.".to_string(),
        None,
    )
}

fn resource_ambiguous(
    id: &Value,
    uri: &str,
    candidates: Vec<String>,
) -> crate::tool_arrival::Refusal {
    crate::call::error(
        409,
        id,
        crate::codec::CODE_REFUSED,
        format!(
            "`{uri}` is answered by more than one approval you are granted ({}). \
             Narrow the grant so exactly one of them applies.",
            candidates.join(", ")
        ),
        Some(serde_json::json!({"reason": "resource_ambiguous", "candidates": candidates})),
    )
}

/// A JSON string whose normalised bytes are shared source spans rather than a materialised String.
#[derive(Clone, Default)]
struct RopeString {
    root: usize,
    source: RopeCursor,
    active: bool,
    plain_end: usize,
    escape: [u8; 6],
    escape_len: usize,
    escape_at: usize,
    opened: bool,
    closing: bool,
    done: bool,
}

impl RopeString {
    fn queue(&mut self, bytes: &[u8]) {
        self.escape[..bytes.len()].copy_from_slice(bytes);
        self.escape_len = bytes.len();
        self.escape_at = 0;
    }
    fn write_with<'a>(
        &mut self,
        ropes: &[Rope],
        source: &impl Fn(usize) -> &'a str,
        mut write: impl FnMut(&[u8]) -> usize,
    ) -> usize {
        let mut written = 0;
        while !self.done {
            if self.escape_at < self.escape_len {
                let bytes = &self.escape[self.escape_at..self.escape_len];
                let accepted = write(bytes).min(bytes.len());
                if accepted == 0 {
                    break;
                }
                self.escape_at += accepted;
                written += accepted;
                continue;
            }
            if self.closing {
                self.done = true;
                continue;
            }
            if !self.opened {
                self.opened = true;
                self.queue(b"\"");
                continue;
            }
            if !self.active {
                let Some(rope) = ropes.get(self.root) else {
                    self.closing = true;
                    self.queue(b"\"");
                    continue;
                };
                self.root += 1;
                self.source = RopeCursor::new(rope.clone(), false);
                self.active = true;
                self.plain_end = 0;
            }
            let Some(span) = self.source.load() else {
                self.active = false;
                self.plain_end = 0;
                continue;
            };
            let bytes = &source(span.source).as_bytes()[span.start..span.end];
            if self.plain_end < span.start {
                self.plain_end = span.start;
            }
            if self.plain_end == span.start {
                self.plain_end = span.start
                    + bytes
                        .iter()
                        .position(|byte| *byte < 0x20 || matches!(*byte, b'"' | b'\\'))
                        .unwrap_or(bytes.len());
            }
            let plain = self.plain_end - span.start;
            if plain != 0 {
                let accepted = write(&bytes[..plain]).min(plain);
                if accepted == 0 {
                    break;
                }
                self.source.advance(accepted);
                written += accepted;
                if accepted == bytes.len() {
                    self.plain_end = 0;
                }
                continue;
            }
            let byte = bytes[0];
            self.source.advance(1);
            self.plain_end = span.start + 1;
            match byte {
                b'"' => self.queue(b"\\\""),
                b'\\' => self.queue(b"\\\\"),
                8 => self.queue(b"\\b"),
                9 => self.queue(b"\\t"),
                10 => self.queue(b"\\n"),
                12 => self.queue(b"\\f"),
                13 => self.queue(b"\\r"),
                control => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    self.queue(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(control >> 4) as usize],
                        HEX[(control & 15) as usize],
                    ]);
                }
            }

            if self.source.current.is_some_and(|span| span.len() == 0) {
                self.plain_end = 0;
            }
        }
        written
    }
}

#[derive(Clone, Default)]
struct Delivery {
    part: usize,
    raw_at: usize,
    string: RopeString,
}

/// One local result. Replay cursors share the pinned generation and original argument allocations;
/// cloning or restarting a delivery never clones expanded text or a result Value tree.
#[derive(Clone)]
pub(crate) struct Local {
    input: Arc<Input>,
    plan: Arc<Plan>,
    cursor: Delivery,
}

impl std::fmt::Debug for Local {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Local")
            .field("len", &self.len())
            .field("done", &self.done())
            .finish_non_exhaustive()
    }
}

impl Local {
    pub(crate) fn prompt(
        held: Arc<crate::plane_door::Held>,
        published: String,
        id: Value,
        params: Option<Value>,
        revision: Revision,
    ) -> Result<Self, crate::tool_arrival::Refusal> {
        let legacy = revision.has_sessions();
        if params
            .as_ref()
            .and_then(|p| p.get("arguments"))
            .is_some_and(|arguments| {
                !arguments
                    .as_object()
                    .is_some_and(|args| args.values().all(Value::is_string))
            })
        {
            return Err(crate::call::error(
                400,
                &id,
                crate::codec::CODE_INVALID_PARAMS,
                "`params.arguments` must be an object of strings.".to_string(),
                None,
            ));
        }
        let prompt = held
            .catalogue
            .prompt_for(&|_, _| true, &published)
            .ok_or_else(|| {
                crate::call::error(
                    404,
                    &id,
                    crate::codec::CODE_REFUSED,
                    format!("`{published}` is not a prompt this server exposes."),
                    None,
                )
            })?;
        if revision == Revision::R2024_11_05
            && prompt.messages.iter().any(|message| {
                matches!(
                    message.content,
                    crate::tools_config::PromptContentCfg::Audio { .. }
                )
            })
        {
            return Err(crate::call::error(
                400,
                &id,
                crate::codec::CODE_INVALID_PARAMS,
                "This prompt contains audio, which MCP 2024-11-05 cannot represent.".to_string(),
                None,
            ));
        }
        let server = held
            .section
            .servers
            .get_index_of(&prompt.server)
            .expect("catalogue server in held section");
        let entry = held
            .section
            .servers
            .get_index(server)
            .expect("pinned server")
            .1
            .prompts_allow
            .get_index_of(&prompt.name)
            .expect("catalogue prompt in held section");
        let mut input = Input {
            held,
            selection: Selection::Prompt { server, entry },
            id,
            params,
            arguments: Vec::new(),
            bindings: Vec::new(),
            uri: String::new(),
            originals: Vec::new(),
            reusable: Vec::new(),
        };
        let substitutions = input.take_arguments();
        let mut builder = Builder {
            input,
            substitutions,
            summaries: HashMap::new(),
            work_bytes: MAX_RENDERED_BYTES,
            work_operations: MAX_NORMALISE_OPERATIONS,
            parts: Vec::new(),
        };
        builder
            .prompt_result(legacy)
            .map_err(|_| unrepresentable(&builder.input.id))?;
        builder.finish()
    }
    pub(crate) fn resource(
        held: Arc<crate::plane_door::Held>,
        id: Value,
        mut params: Option<Value>,
        admit: &impl Fn(&str, &str) -> bool,
        revision: Revision,
    ) -> Result<Self, crate::tool_arrival::Refusal> {
        let legacy = revision.has_sessions();
        use crate::catalogue::Lookup;
        let Some(uri) = params
            .as_ref()
            .and_then(|params| params.get("uri"))
            .and_then(Value::as_str)
        else {
            return Err(crate::call::error(
                crate::checks::STATUS,
                &id,
                crate::codec::CODE_INVALID_PARAMS,
                "`params.uri` is required and must be a string.".to_string(),
                None,
            ));
        };
        crate::reads::check_selector(&id, uri)?;
        let selected = match held.catalogue.resource_by_uri(admit, uri) {
            Lookup::One(resource) => {
                let server = held
                    .section
                    .servers
                    .get_index_of(&resource.server)
                    .expect("catalogue server in held section");
                let entry = held
                    .section
                    .servers
                    .get_index(server)
                    .expect("pinned server")
                    .1
                    .resources_allow
                    .get_index_of(&resource.uri)
                    .expect("catalogue resource in held section");
                Ok((Selection::Resource { server, entry }, BTreeMap::new()))
            }
            Lookup::Ambiguous(candidates) => Err(resource_ambiguous(&id, uri, candidates)),
            Lookup::NotFound => match held.catalogue.resource_template_for(admit, uri) {
                Lookup::One((resource, bindings)) => {
                    let server = held
                        .section
                        .servers
                        .get_index_of(&resource.server)
                        .expect("catalogue server in held section");
                    let entry = held
                        .section
                        .servers
                        .get_index(server)
                        .expect("pinned server")
                        .1
                        .resource_templates_allow
                        .get_index_of(&resource.uri_template)
                        .expect("catalogue template in held section");
                    Ok((Selection::ResourceTemplate { server, entry }, bindings))
                }
                Lookup::Ambiguous(candidates) => Err(resource_ambiguous(&id, uri, candidates)),
                Lookup::NotFound => Err(crate::call::error(
                    404,
                    &id,
                    if legacy {
                        -32002
                    } else {
                        crate::codec::CODE_INVALID_PARAMS
                    },
                    format!("`{uri}` is not a resource this server exposes."),
                    Some(serde_json::json!({"uri": uri})),
                )),
            },
        };
        let (selection, bindings) = selected?;
        let uri = match params
            .as_mut()
            .and_then(|params| params.get_mut("uri"))
            .map(Value::take)
        {
            Some(Value::String(uri)) => uri,
            _ => unreachable!("resource lookup required a string URI"),
        };
        let mut input = Input {
            held,
            selection,
            id,
            params,
            arguments: Vec::new(),
            bindings: Vec::new(),
            uri,
            originals: Vec::new(),
            reusable: Vec::new(),
        };
        let mut substitutions = BTreeMap::new();
        for (name, value) in bindings {
            let binding = input.bindings.len();
            input.bindings.push(value);
            let source = input.register(Original::Binding(binding), true);
            substitutions.insert(name, source);
        }
        let mut builder = Builder {
            input,
            substitutions,
            summaries: HashMap::new(),
            work_bytes: MAX_RENDERED_BYTES,
            work_operations: MAX_NORMALISE_OPERATIONS,
            parts: Vec::new(),
        };
        builder
            .resource_result(legacy)
            .map_err(|_| unrepresentable(&builder.input.id))?;
        builder.finish()
    }
    pub(crate) fn len(&self) -> usize {
        self.plan.len
    }
    pub(crate) fn id(&self) -> &Value {
        &self.input.id
    }
    pub(crate) fn done(&self) -> bool {
        self.cursor.part == self.plan.parts.len()
    }
    pub(crate) fn write_with(&mut self, mut write: impl FnMut(&[u8]) -> usize) -> usize {
        let mut written = 0;
        while let Some(part) = self.plan.parts.get(self.cursor.part) {
            match part {
                Part::Raw(bytes) => {
                    let bytes = &bytes[self.cursor.raw_at..];
                    if !bytes.is_empty() {
                        let accepted = write(bytes).min(bytes.len());
                        if accepted == 0 {
                            break;
                        }
                        self.cursor.raw_at += accepted;
                        written += accepted;
                        if accepted < bytes.len() {
                            continue;
                        }
                    }
                }
                Part::Id(bytes) => {
                    let bytes = &bytes[self.cursor.raw_at..];
                    if !bytes.is_empty() {
                        let accepted = write(bytes).min(bytes.len());
                        if accepted == 0 {
                            break;
                        }
                        self.cursor.raw_at += accepted;
                        written += accepted;
                        if accepted < bytes.len() {
                            continue;
                        }
                    }
                }
                Part::String(ropes) => {
                    written += self.cursor.string.write_with(
                        ropes,
                        &|index| self.input.source(index),
                        &mut write,
                    );
                    if !self.cursor.string.done {
                        break;
                    }
                }
            }
            self.cursor.part += 1;
            self.cursor.raw_at = 0;
            self.cursor.string = RopeString::default();
        }
        written
    }
}

#[cfg(test)]
#[path = "tests/local_renderer.rs"]
mod tests;
