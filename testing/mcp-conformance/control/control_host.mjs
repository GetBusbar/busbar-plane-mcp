#!/usr/bin/env node
// Independent reference HOST fixture, not an official Python SDK implementation.
// The front door is authenticated loopback HTTP. The stdio driver below is its
// client, holding a credential just as any front-door MCP client would. The host
// creates new upstream RPCs/headers; it never forwards downstream envelopes.
import { createServer } from 'node:http';
import { createServer as reserveServer } from 'node:net';
import { spawn } from 'node:child_process';
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline';

const HERE = dirname(fileURLToPath(import.meta.url));
const VERSION = '2026-07-28';
const bearerFile = process.env.MCP_SEAM_BEARER_FILE;
const witness = process.env.MCP_SEAM_FRONT_TRANSCRIPT;
if (!bearerFile || !witness || !process.env.MCP_FAKE_TRANSCRIPT) {
  throw new Error('reference host needs credential file and front/upstream witnesses');
}
const bearer = readFileSync(bearerFile, 'utf8').trim();
if (!bearer) throw new Error('reference host credential is empty');
const expectedCommand = `${process.execPath} ${resolve(HERE, '../fakepeer/fake-server.mjs')}`;
if (process.env.MCP_SEAM_UPSTREAM_CMD !== expectedCommand) {
  throw new Error('reference host supports the configured battery fake peer only');
}
const scratch = mkdtempSync(join(tmpdir(), 'mcp-reference-host-'));
const children = [];
let front;
let closing = false;
const active = new Set();
const digest = (value) => createHash('sha256').update(value).digest('hex');
const complete = (value) => ({ resultType: 'complete', ...value });
const envelope = (method, params = {}) => ({ jsonrpc: '2.0', id: randomUUID(), method,
  params: { ...params, _meta: {
    'io.modelcontextprotocol/protocolVersion': VERSION,
    'io.modelcontextprotocol/clientCapabilities': {},
    'io.modelcontextprotocol/clientInfo': { name: 'independent-reference-host', version: '1.0.0' },
  } },
});

async function stop(code = 0) {
  if (closing) return;
  closing = true;
  for (const controller of active) controller.abort();
  front?.closeAllConnections();
  front?.close();
  await Promise.all(children.map((child) => new Promise((done) => {
    if (child.exitCode !== null || child.signalCode !== null) { done(); return; }
    const timer = setTimeout(() => { child.kill('SIGKILL'); done(); }, 1500);
    child.once('close', () => { clearTimeout(timer); done(); });
    child.kill('SIGTERM');
  })));
  rmSync(scratch, { recursive: true, force: true });
  process.exit(code);
}
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { void stop(); });

async function upstream(index) {
  // Reserve a loopback port, then detect binding failure in the spawned bridge.
  // It is never treated as a successful control run if another process wins it.
  const reservation = reserveServer();
  await new Promise((done, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', done);
  });
  const port = reservation.address().port;
  await new Promise((done) => reservation.close(done));
  const control = join(scratch, `upstream-${index}.json`);
  writeFileSync(control, JSON.stringify({
    mode: process.env.MCP_FAKE_MODE || 'honest',
    transcript: process.env.MCP_FAKE_TRANSCRIPT,
    // Always record the actual HTTP header/body witness, with hash-only tokens.
    // Noncredential scenarios also need raw hostile frames from the fake peer.
    ...(process.env.MCP_SEAM_CREDENTIAL_PROBE === '1' ? { credentialFile: bearerFile } : {}),
  }));
  const env = { ...process.env };
  // This reference uses isolated plaintext loopback, not the product TLS fixture.
  delete env.MCP_FIXTURE_TLS_CERT;
  delete env.MCP_FIXTURE_TLS_KEY;
  const child = spawn(process.execPath, [resolve(HERE, '../fakepeer/http-fake-server.mjs'), String(port), control],
    { env, stdio: ['ignore', 'ignore', 'pipe'] });
  children.push(child);
  await new Promise((done, reject) => {
    const timer = setTimeout(() => reject(new Error('upstream bridge did not become ready')), 5000);
    let logs = '';
    child.stderr.on('data', (chunk) => {
      process.stderr.write(chunk);
      logs += chunk.toString();
      if (logs.includes(`listening on 127.0.0.1:${port}`)) { clearTimeout(timer); done(); }
    });
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`upstream bridge exited ${code}`)); });
  });
  return `http://127.0.0.1:${port}/mcp`;
}

async function upstreamCall(url, method, params) {
  const message = envelope(method, params);
  const controller = new AbortController();
  active.add(controller);
  const timer = setTimeout(() => controller.abort(new Error('upstream RPC deadline exceeded')), 3000);
  try {
    const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream',
      'mcp-protocol-version': VERSION, 'mcp-method': method };
    if (typeof params?.name === 'string') headers['mcp-name'] = params.name;
    const response = await fetch(url, { method: 'POST', headers,
      body: JSON.stringify(message), signal: controller.signal });
    if (!response.ok) throw new Error(`upstream HTTP ${response.status}`);
    const text = await response.text();
    const frames = /text\/event-stream/i.test(response.headers.get('content-type') || '')
      ? text.split(/\r?\n\r?\n/).filter(Boolean).map((event) => {
        const data = event.split(/\r?\n/).filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).replace(/^ /, '')).join('\n');
        return JSON.parse(data);
      }) : [JSON.parse(text)];
    let answer;
    for (const frame of frames) {
      if (!frame || Array.isArray(frame) || frame.jsonrpc !== '2.0') throw new Error('invalid upstream envelope');
      // Modern role boundary: a server-initiated request is discarded, never
      // answered upstream and never emitted to this host's downstream clients.
      if (typeof frame.method === 'string') continue;
      if (frame.id !== message.id) throw new Error('upstream response id mismatch');
      if (answer) throw new Error('duplicate upstream response');
      if (Object.hasOwn(frame, 'result') === Object.hasOwn(frame, 'error')) throw new Error('invalid upstream response');
      answer = frame;
    }
    if (!answer) throw new Error('upstream did not answer the request');
    if (answer.error) throw new Error(`upstream RPC error ${answer.error.code}`);
    if (answer.result?.resultType !== 'complete') throw new Error('unsupported upstream result type');
    return answer.result;
  } finally {
    clearTimeout(timer);
    active.delete(controller);
  }
}

async function start() {
  const upstreams = [await upstream(0), await upstream(1)];
  async function dispatch(message) {
    if (message.method === 'server/discover') return complete({ supportedVersions: [VERSION],
      serverInfo: { name: 'independent-reference-host', version: '1.0.0' }, capabilities: { tools: {} } });
    if (message.method === 'tools/list') {
      const tools = [];
      for (const [index, url] of upstreams.entries()) {
        const listing = await upstreamCall(url, 'tools/list');
        for (const tool of listing.tools || []) tools.push({ name: index ? `seamright_${tool.name}` : tool.name,
          // A configured host owns its public descriptions. Untrusted upstream
          // prose is not republished as instructions; schemas remain data.
          description: 'Tool supplied by the configured reference upstream.',
          inputSchema: tool.inputSchema,
          ...(tool.outputSchema ? { outputSchema: tool.outputSchema } : {}) });
      }
      return complete({ tools });
    }
    if (message.method === 'tools/call') {
      const name = message.params?.name;
      if (typeof name !== 'string') throw new Error('tool name is required');
      const right = name.startsWith('seamright_');
      try {
        return await upstreamCall(upstreams[right ? 1 : 0], 'tools/call', {
          name: right ? name.slice('seamright_'.length) : name,
          arguments: message.params?.arguments || {},
        });
      } catch (error) {
        // A failed dependency is a tool execution failure; the host stays alive.
        return complete({ isError: true, content: [{ type: 'text', text: `Upstream call failed: ${error.message}` }] });
      }
    }
    throw new Error(`unsupported reference-host method ${message.method}`);
  }

  front = createServer(async (req, res) => {
    try {
      const supplied = req.headers.authorization || '';
      const expected = `Bearer ${bearer}`;
      const authorized = Buffer.byteLength(supplied) === Buffer.byteLength(expected)
        && timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
      if (!authorized) { res.writeHead(401).end(); return; }
      if (req.method !== 'POST') { res.writeHead(405).end(); return; }
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const message = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      // The witness observes an actually received and authenticated HTTP header.
      if (message.id !== undefined) appendFileSync(witness, JSON.stringify({
        method: message.method, requestIdSha256: digest(JSON.stringify(message.id)),
        suppliedAuthorizationSha256: digest(supplied),
      }) + '\n', { mode: 0o600 });
      if (message.id === undefined) { res.writeHead(202).end(); return; }
      let reply;
      try { reply = { jsonrpc: '2.0', id: message.id, result: await dispatch(message) }; }
      catch (error) { reply = { jsonrpc: '2.0', id: message.id, error: { code: -32603, message: error.message } }; }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(reply));
    } catch (error) {
      res.writeHead(400).end(String(error));
    }
  });
  await new Promise((done, reject) => { front.once('error', reject); front.listen(0, '127.0.0.1', done); });
  const frontUrl = `http://127.0.0.1:${front.address().port}/mcp`;
  process.stderr.write(`reference-host: ${frontUrl}\n`);
  const pending = new Set();
  const lines = createInterface({ input: process.stdin });
  lines.on('line', (line) => {
    if (!line.trim()) return;
    const work = (async () => {
      const response = await fetch(frontUrl, { method: 'POST',
        headers: { authorization: `Bearer ${bearer}`, 'content-type': 'application/json' }, body: line });
      if (!response.ok) throw new Error(`reference front door returned HTTP ${response.status}`);
      const text = await response.text();
      if (text) process.stdout.write(`${text}\n`);
    })().catch((error) => { console.error(error); void stop(1); }).finally(() => pending.delete(work));
    pending.add(work);
  });
  lines.on('close', () => { void Promise.all(pending).then(() => stop()); });
}
start().catch((error) => { console.error(error); void stop(1); });
