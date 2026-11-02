// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
import { createServer as httpServer } from 'node:http';
import { createServer as httpsServer } from 'node:https';
import { readFileSync } from 'node:fs';

// The standalone battery's negative controls still use plaintext. Positive busbar boots
// supply both fields and pin this certificate; incomplete TLS setup must never downgrade.
export function createServer(handler) {
  const cert = process.env.MCP_FIXTURE_TLS_CERT;
  const key = process.env.MCP_FIXTURE_TLS_KEY;
  if (!cert && !key) return httpServer(handler);
  if (!cert || !key) throw new Error('both MCP fixture TLS certificate and key are required');
  return httpsServer({ cert: readFileSync(cert), key: readFileSync(key), minVersion: 'TLSv1.2' }, handler);
}
