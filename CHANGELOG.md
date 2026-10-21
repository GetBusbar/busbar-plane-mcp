# Changelog

All notable changes to the `mcp` plane plugin (`busbar-plane-mcp`, `busbar-plane-mcp-plugin`).

## 1.6.0

### Informational

- `subscriptions/listen` relays the `notifications/resources/updated` its members announce to the
  listening callers, once each, as the listen's own notification (tagged with its subscription id).
  busbar never subscribes upstream: a caller's `resources/subscribe` (session
  revisions) or listen subscription is recorded by busbar and answered by busbar, and no
  `resources/subscribe` or `resources/unsubscribe` is sent to a member.
