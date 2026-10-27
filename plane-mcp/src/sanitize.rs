// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MARKUP-NORMALISATION, and nothing more: strips HTML-like tags from the text busbar composes and
//! serves itself (catalogue names and descriptions, section-answered prompts and resources). An
//! upstream's result is its own (Law 11). This is the fixed floor, not a semantic-injection defence.

/// Strip instruction-injection markup from one string: anything that lexes as a tag (`<`, an
/// optional `/`, then an ASCII letter, `!` or `?`, up to `>`) is removed and its inner text kept;
/// an unterminated `<` is ordinary text. A deletion can join a tag across the seam, so the output's
/// tail is re-examined after each one: no tag survives in the OUTPUT. Linear in the input.
pub fn normalise(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    // The `>` that closes whatever tag opens at or after the cursor, remembered rather than
    // re-derived. The cursor only ever moves FORWARD, so this answer is refreshed only once the
    // cursor passes it, and each refresh resumes where the last one stopped — every byte of the
    // input is examined by this scan at most once across the whole call. Re-scanning `bytes[i..]`
    // for every `<` instead would answer identically and cost O(n^2) on input an untrusted upstream
    // chooses, which is the shape `<a<a<a…` has. `None` is terminal and must stay terminal: with no
    // `>` left after the cursor, no later `<` can close either, so there is nothing to look for.
    let mut next_tag_end = find_tag_end(bytes, 0);
    while i < bytes.len() {
        if bytes[i] == b'<' && starts_tag(bytes, i) {
            if next_tag_end.is_some_and(|end| end < i) {
                next_tag_end = find_tag_end(bytes, i);
            }
            if let Some(end) = next_tag_end {
                i = end + 1;
                // The deletion just made `out`'s tail adjacent to `bytes[i..]`. That is the one and
                // only way two non-adjacent pieces of input meet, so it is the one and only place a
                // tag can appear in the output that was not one in the input.
                collapse_reconstituted_tags(&mut out, bytes, &mut i, &mut next_tag_end);
                continue;
            }
            // Unterminated: no `>` closes this `<` anywhere before end of input, so it is not a tag.
            // Fall through and copy the `<` as ordinary text — never drop the tail. Every later
            // `<letter` in this string is likewise `>`-less and takes the same inert path, so the
            // remainder round-trips byte-for-byte.
        }
        // Copy one whole character, never one byte (`i` is always on a boundary: it only ever
        // moves by a character or past an ASCII `>`).
        let Some(c) = input[i..].chars().next() else {
            break;
        };
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// Remove the tag that the just-completed deletion may have reconstituted across the seam between
/// the emitted text and `bytes[i..]`, and keep removing while each removal makes another.
///
/// Only a `<` or `</` sitting at the very END of `out` can be the start of such a tag. Any earlier
/// `<` in `out` is already followed by a character that was emitted with it — and it was emitted
/// verbatim precisely because that character disqualified it as a tag opener — so it is inert for
/// good, and nothing but this function ever removes a character from `out`.
///
/// Each removal drops the pending opener and advances the cursor past the closing `>`, so the cursor
/// strictly increases and `out` strictly shrinks: the loop runs at most as many times as there are
/// bytes, and the whole scan stays linear.
fn collapse_reconstituted_tags(
    out: &mut String,
    bytes: &[u8],
    i: &mut usize,
    next_tag_end: &mut Option<usize>,
) {
    while let Some(opener) = pending_opener(out, bytes, *i) {
        if next_tag_end.is_some_and(|end| end < *i) {
            *next_tag_end = find_tag_end(bytes, *i);
        }
        // No `>` left anywhere ahead, so the seam cannot close into a tag and never will — deletions
        // only ever remove bytes, so a `>` cannot appear later than the input already has one.
        let Some(end) = *next_tag_end else { return };
        out.truncate(out.len() - opener);
        *i = end + 1;
    }
}

/// The length of the `<` or `</` left dangling at the end of `out` that `bytes[i..]` would complete
/// into a tag, or `None` when the seam is inert.
fn pending_opener(out: &str, bytes: &[u8], i: usize) -> Option<usize> {
    let head = names_tag(bytes.get(i));
    if out.ends_with("</") {
        // `</` needs only the name to follow.
        return head.then_some(2);
    }
    if out.ends_with('<') {
        // A bare `<` takes either form: the name may follow directly, or after a `/` that is still
        // in the input rather than in `out`.
        let closing = bytes.get(i) == Some(&b'/') && names_tag(bytes.get(i + 1));
        return (head || closing).then_some(1);
    }
    None
}

/// Does the `<` at `i` begin something that lexes as a tag? See [`normalise`] for why this is a
/// character-class test and not "anything up to the next `>`".
fn starts_tag(bytes: &[u8], i: usize) -> bool {
    let mut j = i + 1;
    if bytes.get(j) == Some(&b'/') {
        j += 1;
    }
    names_tag(bytes.get(j))
}

/// Whether `c` can open a tag's name: an ASCII letter, `!` or `?`.
fn names_tag(c: Option<&u8>) -> bool {
    matches!(c, Some(c) if c.is_ascii_alphabetic() || *c == b'!' || *c == b'?')
}

/// The index of the `>` closing the tag opened at `i`, or `None` when the input ends first.
fn find_tag_end(bytes: &[u8], i: usize) -> Option<usize> {
    bytes[i..].iter().position(|b| *b == b'>').map(|p| i + p)
}

#[cfg(test)]
#[path = "tests/sanitize_tests.rs"]
mod sanitize_tests;
