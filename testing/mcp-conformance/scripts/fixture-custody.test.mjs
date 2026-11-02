import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const mirror = fileURLToPath(new URL('../fakepeer/http-fake-server.mjs', import.meta.url));
const digest = fileURLToPath(new URL('../mcp-subject/tool-digest.mjs', import.meta.url));
const revision = '2026-07-28';
const request = (id) => ({ jsonrpc: '2.0', id, method: 'tools/list', params: { _meta: {
  'io.modelcontextprotocol/protocolVersion': revision,
  'io.modelcontextprotocol/clientCapabilities': {},
} } });

async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = once(child, 'close');
  child.kill('SIGTERM');
  await closed;
}

test('each half-answer gets a live child, and a later honest peer still answers', { timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-fixture-custody-'));
  const control = join(dir, 'control.json');
  const transcript = join(dir, 'transcript.jsonl');
  writeFileSync(control, JSON.stringify({ mode: 'half-answer', transcript }));
  // Reserve a free port without depending on a fixed host port.
  const reserve = createServer();
  reserve.listen(0, '127.0.0.1');
  await once(reserve, 'listening');
  const port = reserve.address().port;
  await new Promise((resolve) => reserve.close(resolve));
  const child = spawn(process.execPath, [mirror, String(port), control], { stdio: ['ignore', 'ignore', 'pipe'] });
  let log = '';
  try {
    await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('exit', (code) => reject(new Error(`mirror exited ${code}: ${log}`)));
      child.stderr.on('data', (chunk) => {
        log += chunk;
        if (log.includes('listening on')) resolve();
      });
    });
    for (const id of ['first', 'second']) {
      await assert.rejects(async () => {
        const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
          method: 'POST', body: JSON.stringify(request(id)), signal: AbortSignal.timeout(3000),
        });
        await response.text();
      });
    }
    const entries = readFileSync(transcript, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(entries.filter((e) => e.direction === 'client->server').map((e) => e.payload.id), ['first', 'second']);
    const partials = entries.filter((e) => e.direction === 'server->client-raw');
    assert.equal(partials.length, 2, 'both requests must receive the actual half-answer stimulus');
    for (const [i, id] of ['first', 'second'].entries()) assert.ok(partials[i].payload.includes(JSON.stringify(id)));
    writeFileSync(control, JSON.stringify({ mode: 'honest', transcript }));
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST', body: JSON.stringify(request('healthy')), signal: AbortSignal.timeout(3000),
    });
    assert.equal((await response.json()).id, 'healthy');
  } finally {
    await stop(child);
    rmSync(dir, { recursive: true, force: true });
  }
});

test('tool digest mirrors the offered protocol version in the HTTP header', { timeout: 10000 }, async () => {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const message = JSON.parse(body);
      const offered = message.params?._meta?.['io.modelcontextprotocol/protocolVersion'];
      if (req.headers['mcp-protocol-version'] !== offered || req.headers['mcp-method'] !== message.method) {
        res.writeHead(400).end(JSON.stringify({ error: 'protocol mirror missing' }));
        return;
      }
      res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: {
        tools: [{ name: 'fixture', inputSchema: { type: 'object' } }],
      } }));
    });
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const child = spawn(process.execPath, [digest, `http://127.0.0.1:${server.address().port}/mcp`]);
  let output = '', errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  try {
    const [code] = await once(child, 'close');
    assert.equal(code, 0, errors);
    assert.match(output, /^fixture sha256:[0-9a-f]{64}\n$/);
  } finally {
    await stop(child);
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
