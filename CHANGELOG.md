# Changelog

All notable changes to busbar-plane-mcp are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The release notes customers read are
busbar's own `CHANGELOG.md`, which names each change again when busbar's pin takes it.

## Unreleased

### Changed

- **A `tools/call` that never left its queue is not charged.** A call waiting its turn on a stdio
  server's child, whose deadline passed before its turn came, was never sent. Its caller is still
  answered the same upstream-failure tool error (HTTP 200, `isError: true`), but the plane reports
  no `per_request` fee unit, so the admission's fee is given back. Its call-log line reads
  `refused` / `queue_deadline`, audited rejected; it used to read `dispatched` / `upstream_failed`
  and keep the fee. A call that went out keeps its fee whatever the server answered, and counts
  one `tool_calls` plus the answer's bytes whenever the server answered at all, an HTTP 5xx
  included. (ARCHITECT/coordinator ruling 2026-10-14, after BUSBAR-1.6.0.md #62 and Q35.)
