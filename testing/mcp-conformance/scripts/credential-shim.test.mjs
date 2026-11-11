import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { mkdtempSync, readFileSync, existsSync, rmSync, chmodSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';

const shim = fileURLToPath(new URL('../mcp-subject/credential-shim.mjs', import.meta.url));
const bearer = 'fixture-bearer-never-log';
const admin = 'fixture-admin-never-log';

async function listen(server, port = 0) {
  server.listen(port, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}
async function close(server) {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
}
function start(upstreamPort, { port = 0, privateFifo = true, standalone = false, excludedPorts = [] } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-shim-'));
  const fifo = join(dir, 'credentials.fifo');
  const portFile = join(dir, 'port');
  execFileSync('mkfifo', ['-m', '600', fifo]);
  if (!privateFifo) chmodSync(fifo, 0o644);
  const args = [shim, String(port), String(upstreamPort)];
  if (!standalone) args.push(fifo, portFile, excludedPorts.join(','));
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^MCP_(OPERATOR|SEAM)_/.test(key)) delete env[key];
  const child = spawn(process.execPath, args, { env, stdio: ['ignore', 'pipe', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  const exited = once(child, 'close');
  if (standalone) child.stdio[3].end(bearer);
  return {
    fifo, portFile, child, exited,
    output: () => output,
    async port() {
      const deadline = Date.now() + 3000;
      while (!existsSync(portFile)) {
        assert.equal(child.exitCode, null, output);
        assert.ok(Date.now() < deadline, 'shim must publish its held port');
        await delay(10);
      }
      return Number(readFileSync(portFile, 'utf8'));
    },
    async stop() {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
      await exited;
      assert.ok(!output.includes(bearer) && !output.includes(admin), 'logs must not include credentials');
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const request = (port, authorization) => fetch(`http://127.0.0.1:${port}/mcp?exact=query`, {
  method: 'POST', headers: { origin: 'https://client.example', 'mcp-method': 'tools/list',
    ...(authorization ? { authorization } : {}) }, body: 'exact request bytes', signal: AbortSignal.timeout(2000),
});

test('held listener rejects competing bind, then forwards exact bytes and credential precedence', { timeout: 10000 }, async () => {
  const seen = [];
  const upstream = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    seen.push({ path: req.url, method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() });
    res.writeHead(207, { 'x-fixture': 'unchanged' }).end('exact response bytes');
  });
  const upstreamPort = await listen(upstream);
  const fixture = start(upstreamPort);
  try {
    const port = await fixture.port();
    const competing = createServer();
    await assert.rejects(listen(competing, port), { code: 'EADDRINUSE' });
    const pending = await request(port);
    assert.equal(pending.status, 503);
    await pending.text();
    assert.equal(seen.length, 0, 'uncredentialed readiness must never touch the upstream');
    await writeFile(fixture.fifo, `${bearer}\n${admin}\n`, { flag: 'r+' });
    // FIFO deletion acknowledges credential installation, without probing product behavior.
    while (existsSync(fixture.fifo)) await delay(10);
    for (const authorization of [undefined, 'Bearer explicit-client']) {
      const response = await request(port, authorization);
      assert.equal(response.status, 207);
      assert.equal(response.headers.get('x-fixture'), 'unchanged');
      assert.equal(await response.text(), 'exact response bytes');
    }
    assert.equal(seen.length, 2);
    for (const [index, entry] of seen.entries()) {
      assert.equal(entry.path, '/mcp?exact=query');
      assert.equal(entry.method, 'POST');
      assert.equal(entry.body, 'exact request bytes');
      assert.equal(entry.headers.origin, 'https://client.example');
      assert.equal(entry.headers['mcp-method'], 'tools/list');
      assert.equal(entry.headers.host, `127.0.0.1:${upstreamPort}`);
      assert.equal(entry.headers.authorization, index ? 'Bearer explicit-client' : `Bearer ${bearer}`);
    }
    fixture.child.kill('SIGTERM');
    await fixture.exited;
    assert.equal(existsSync(fixture.portFile), false);
    assert.equal(existsSync(fixture.fifo), false);
    const successor = createServer();
    await listen(successor, port);
    await close(successor);
  } finally { await fixture.stop(); await close(upstream); }
});

test('termination before credentials removes the private FIFO and held port', { timeout: 5000 }, async () => {
  const fixture = start(1);
  try {
    const port = await fixture.port();
    fixture.child.kill('SIGTERM');
    await fixture.exited;
    assert.equal(existsSync(fixture.fifo), false);
    assert.equal(existsSync(fixture.portFile), false);
    const successor = createServer();
    await listen(successor, port);
    await close(successor);
  } finally { await fixture.stop(); }
});

test('failed listener startup cleans the FIFO and publishes no port', { timeout: 5000 }, async () => {
  const occupied = createServer();
  const fixture = start(1, { port: await listen(occupied) });
  try {
    assert.equal((await fixture.exited)[0], 1);
    assert.match(fixture.output(), /EADDRINUSE/);
    assert.equal(existsSync(fixture.fifo), false);
    assert.equal(existsSync(fixture.portFile), false);
  } finally { await fixture.stop(); await close(occupied); }
});

test('invalid deferred credentials fail closed and clean the listener', { timeout: 5000 }, async () => {
  const fixture = start(1);
  try {
    await fixture.port();
    await writeFile(fixture.fifo, '\n\n', { flag: 'r+' });
    assert.equal((await fixture.exited)[0], 2);
    assert.match(fixture.output(), /could not load fixture credentials/);
    assert.equal(existsSync(fixture.fifo), false);
    assert.equal(existsSync(fixture.portFile), false);
  } finally { await fixture.stop(); }
});

test('deferred startup rejects a FIFO readable by other users', { timeout: 5000 }, async () => {
  const fixture = start(1, { privateFifo: false });
  try {
    assert.equal((await fixture.exited)[0], 2);
    assert.equal(existsSync(fixture.portFile), false);
    assert.match(fixture.output(), /owner-only credential FIFO/);
  } finally { await fixture.stop(); }
});

test('standalone descriptor-3 mode retains fallback authorization', { timeout: 5000 }, async () => {
  const upstream = createServer((req, res) => res.end(req.headers.authorization));
  const portReserve = createServer();
  const port = await listen(portReserve);
  await close(portReserve);
  const fixture = start(await listen(upstream), { standalone: true, port });
  try {
    let response;
    const deadline = Date.now() + 3000;
    while (!response) {
      try { response = await request(port); }
      catch (error) { if (Date.now() >= deadline) throw error; await delay(10); }
    }
    assert.equal(await response.text(), `Bearer ${bearer}`);
  } finally { await fixture.stop(); await close(upstream); }
});

// Force the first allocation onto a pending role's port. The suite must choose
// another before publishing its audience, leaving all pending roles bindable.
test('suite allocation cannot alias a pending data, admin, or upstream port', { timeout: 5000 }, async () => {
  const reservations = [createServer(), createServer(), createServer()];
  const ports = await Promise.all(reservations.map((server) => listen(server)));
  await Promise.all(reservations.map(close));
  const fixture = start(ports[0], { port: ports[1], excludedPorts: ports });
  const roles = [createServer(), createServer(), createServer()];
  try {
    const suitePort = await fixture.port();
    assert.ok(!ports.includes(suitePort), 'published canonical port must be distinct from all pending roles');
    await Promise.all(roles.map((server, index) => listen(server, ports[index])));
    const competing = createServer();
    await assert.rejects(listen(competing, suitePort), { code: 'EADDRINUSE' });
    const response = await request(suitePort);
    assert.equal(response.status, 503);
    await response.text();
  } finally {
    await fixture.stop();
    await Promise.all(roles.map(close));
  }
});
