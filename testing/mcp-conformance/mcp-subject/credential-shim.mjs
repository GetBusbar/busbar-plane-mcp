// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE CONFORMANCE SUITE'S CREDENTIAL, HELD WHERE A CLIENT WOULD HOLD IT.
//
// The official MCP conformance suite's `server` command takes ONE argument that matters here:
// `--url`. It has no `--header`, no `--token`, and reads no environment variable for either (its
// only `process.env` reference in the published build is `GITHUB_TOKEN`, for the unrelated
// `tier-check` subcommand). It is a TRANSPORT conformance suite: it assumes the endpoint it is
// pointed at will answer it.
//
// busbar will not, because busbar's MCP endpoint is an OAuth resource server and an unauthenticated
// POST gets `401` with an RFC 9728 challenge. A suite that receives `401` on all 37 required
// scenarios has proven nothing about busbar, which is the precise failure this leg exists to end.
//
// THIS IS THE CLIENT SIDE OF THE CONNECTION, NOT THE SERVER SIDE. The shim is the part of an MCP
// client that holds a credential and attaches it -- the thing every real MCP client does, and the
// thing this particular client cannot be told to do. It runs in the same job, on loopback, in front
// of a busbar whose auth is entirely untouched: the token it attaches is verified in full, and
// `mcp-conformance.sh` proves that in the same run by showing that the SAME busbar answers `401` to
// a token with no audience, to one bound to a different audience, and to one whose signature was
// altered. Nothing here is inside busbar's trust boundary and nothing here relaxes it.
//
// TRANSPARENCY IS THE WHOLE DESIGN, and it has exactly one deliberate exception.
//   * Method, path, query and body are forwarded byte-for-byte.
//   * Every request header is forwarded UNCHANGED -- including `Origin`, which the suite's
//     `dns-rebinding-protection` scenario varies on purpose and which busbar must judge itself, and
//     including `Mcp-Method` / `Mcp-Name` / `MCP-Protocol-Version`, which the suite deliberately
//     mangles to test the mirrored-header MUSTs.
//   * Every response header, status and body is forwarded back unchanged.
//   * `Host` is rewritten to the upstream authority, because a forwarded `Host` naming this shim
//     would describe a hop the origin server never had.
//   * `Authorization` is added ONLY when the request carries none. A suite scenario that sends its
//     own credential keeps it, so a future authorization scenario is not silently overwritten by
//     ours.
//
// Usage: node credential-shim.mjs <listen-port> <upstream-port> 3<<<"$bearer"

import http from 'node:http';
import { readFileSync, openSync, constants, closeSync, appendFileSync, writeFileSync, statSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { Socket } from 'node:net';
import { MUTATIONS, operatorMutation } from './operator-mutation.mjs';

const [listenPort, upstreamPort, credentialFifo, portFile, excludedPorts = ''] = process.argv.slice(2);
const deferred = credentialFifo !== undefined;
const excluded = new Set(excludedPorts.split(',').filter(Boolean).map(Number));
if (!listenPort || !upstreamPort || (deferred && !portFile)) {
  console.error('usage: credential-shim.mjs <listen-port> <upstream-port> [credential-fifo port-file]');
  process.exit(2);
}

let token;
let mutate;
function installCredentials(bearer, adminToken) {
  if (!bearer) throw new Error('missing bearer');
  // The admin credential never reaches the diagnostic peer or any HTTP response.
  if (process.env.MCP_OPERATOR_CONFIG) {
    if (!adminToken || !process.env.MCP_OPERATOR_ADMIN_PORT) throw new Error('missing operator configuration');
    mutate = operatorMutation({ config: process.env.MCP_OPERATOR_CONFIG,
      adminPort: process.env.MCP_OPERATOR_ADMIN_PORT, token: adminToken,
      receipt: process.env.MCP_OPERATOR_RECEIPT });
  }
  token = bearer;
}

if (deferred) {
  // Hold the actual listener while boot mints its audience-bound token. Only the
  // owning fixture can supply credentials, and neither credential enters argv.
  try {
    const info = statSync(credentialFifo);
    if (!info.isFIFO() || (info.mode & 0o777) !== 0o600 || info.uid !== process.getuid()) throw new Error();
  } catch {
    console.error('credential shim requires an owner-only credential FIFO');
    process.exit(2);
  }
  process.on('exit', () => {
    rmSync(credentialFifo, { force: true });
    rmSync(portFile, { force: true });
  });
  process.on('SIGTERM', () => process.exit(143));
  process.on('SIGINT', () => process.exit(130));
} else {
  try {
    const bearer = readFileSync(3, 'utf8').trim(); closeSync(3);
    let adminToken;
    if (process.env.MCP_OPERATOR_CONFIG) {
      adminToken = readFileSync(4, 'utf8').trim(); closeSync(4);
    }
    installCredentials(bearer, adminToken);
  } catch {
    console.error('provide the bearer on descriptor 3 and configured operator credential on descriptor 4');
    process.exit(2);
  }
}

const server = http.createServer(async (req, res) => {
  if (!token) { res.writeHead(503, { 'content-type': 'text/plain' }).end('credential shim is not ready'); return; }
  let buffered;
  // This is a test operator action, not an MCP implementation or an emitted
  // notification. Only named, configured hooks from the admitted fixture client
  // can cause it. All other bytes follow the ordinary transparent transport.
  if (mutate && req.method === 'POST' && MUTATIONS.has(req.headers['mcp-name'])
      && (!req.headers.authorization || req.headers.authorization === `Bearer ${token}`)) {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    buffered = Buffer.concat(chunks);
    let message;
    try { message = JSON.parse(buffered.toString('utf8')); } catch { /* forwarded as-is */ }
    if (message?.method === 'tools/call' && message.params?.name === req.headers['mcp-name']) {
      try { await mutate(message.params.name); }
      catch (error) { console.error(`fixture operator: ${error.message}`); res.writeHead(502, { 'content-type': 'text/plain' }).end(`fixture operator: ${error.message}`); return; }
    }
  }
  // Optional, hash-only witness for the credential seam. Observe the client's
  // supplied header before adding our fallback; never persist credential bytes
  // or request bodies, including on the negative forwarding case.
  const witness = process.env.MCP_SEAM_FRONT_TRANSCRIPT;
  if (witness && typeof req.headers.authorization === 'string') {
    const suppliedAuthorizationSha256 = createHash('sha256').update(req.headers.authorization).digest('hex');
    let chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => {
      let id;
      try { id = JSON.parse(Buffer.concat(chunks).toString('utf8')).id; }
      catch { /* malformed requests are still forwarded unchanged */ }
      chunks = [];
      if (id === undefined) return;
      try {
        appendFileSync(witness, `${JSON.stringify({
          method: req.headers['mcp-method'] === 'tools/call' ? 'tools/call' : null,
          requestIdSha256: createHash('sha256').update(JSON.stringify(id)).digest('hex'),
          suppliedAuthorizationSha256,
        })}\n`, { mode: 0o600 });
      } catch { upstream.destroy(); res.destroy(); }
    });
  }
  const headers = { ...req.headers, host: `127.0.0.1:${upstreamPort}` };
  // Case-insensitively, because a client may send `Authorization` in any case and Node lowercases
  // incoming header names but a future refactor of this object must not depend on that.
  const alreadyAuthenticated = Object.keys(headers).some((h) => h.toLowerCase() === 'authorization');
  if (!alreadyAuthenticated) headers.authorization = `Bearer ${token}`;

  const upstream = http.request(
    { host: '127.0.0.1', port: Number(upstreamPort), path: req.url, method: req.method, headers },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode, upstreamRes.headers);
      upstreamRes.on('error', (error) => res.destroy(error));
      upstreamRes.on('aborted', () => res.destroy());
      upstreamRes.pipe(res);
    },
  );
  // A dead upstream must look like a dead upstream, never like a conformance verdict: `502` with
  // the reason, so a scenario that fails because busbar exited says so instead of being read as a
  // protocol defect.
  upstream.on('error', (e) => {
    if (res.headersSent) { res.destroy(e); return; }
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end(`credential-shim: upstream busbar at 127.0.0.1:${upstreamPort} did not answer: ${e}`);
  });
  if (buffered) upstream.end(buffered);
  else req.pipe(upstream);
});

server.on('error', (error) => {
  console.error(`credential shim listener failed: ${error.code}`);
  process.exit(1);
});
let allocations = 0;
function listen(port) {
  server.listen(port, '127.0.0.1', onListening);
}
function onListening() {
  // Other fixture roles have selected ports but have not bound them yet. Never
  // publish a suite port that aliases one. Allocation is bounded and happens
  // before the canonical audience exists; no scenario or product is retried.
  if (excluded.has(server.address().port)) {
    if (++allocations >= 4) {
      console.error('credential shim could not allocate a distinct fixture port');
      process.exit(1);
    }
    server.close(() => listen(0));
    return;
  }
  if (!deferred) return;
  // A nonblocking pipe handle keeps shutdown responsive even if boot fails
  // before writing credentials. A blocking fs.readFile can strand a worker in
  // open/read and prevent Node from exiting when the fixture reaper signals it.
  let input;
  const fail = () => {
    console.error('credential shim could not load fixture credentials');
    process.exit(2);
  };
  try {
    input = new Socket({ fd: openSync(credentialFifo, constants.O_RDWR | constants.O_NONBLOCK), readable: true, writable: false });
  } catch { fail(); }
  let text = '';
  input.setEncoding('utf8');
  input.on('error', fail);
  input.on('data', (chunk) => {
    text += chunk;
    if (text.length > 65536) { fail(); return; }
    if (!text.endsWith('\n') || text.split('\n').length < 3) return;
    try {
      const [bearer, adminToken, extra] = text.slice(0, -1).split('\n');
      if (extra !== undefined) throw new Error();
      installCredentials(bearer, adminToken);
      text = '';
      input.destroy();
      rmSync(credentialFifo, { force: true });
    } catch { fail(); }
  });
  try { writeFileSync(portFile, `${server.address().port}\n`, { mode: 0o600, flag: 'wx' }); }
  catch { console.error('credential shim could not publish its port'); process.exit(1); }
}
listen(Number(listenPort));
