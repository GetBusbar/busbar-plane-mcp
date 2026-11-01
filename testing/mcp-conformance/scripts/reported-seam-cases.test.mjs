import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, appendFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { allTests, runOne } from '../src/core/runner.mjs';
import '../src/suites/seam.mjs';

const hash = (value) => createHash('sha256').update(value).digest('hex');
const call = (id, text = 'hi') => ({ id, method: 'tools/call', params: { name: 'echo', arguments: { text } } });
const entry = (payload) => ({ direction: 'client->server', payload });
const http = (payload, instance = 1, extra = {}) => ({ direction: 'http-client->server', instance, payload, headers: [], ...extra });
const scenario = (id) => allTests().find((item) => item.id === `SEAM.${id}`);

async function withArm(run) {
  const saved = process.env.MCP_SUBJECT_UPSTREAM_CONFIG_CMD;
  process.env.MCP_SUBJECT_UPSTREAM_CONFIG_CMD = 'fixture-arm';
  try { return await run(); }
  finally {
    if (saved === undefined) delete process.env.MCP_SUBJECT_UPSTREAM_CONFIG_CMD;
    else process.env.MCP_SUBJECT_UPSTREAM_CONFIG_CMD = saved;
  }
}

async function execute(id, behavior) {
  return withArm(async () => {
    const target = { serverLaunch: 'ordinary-server', spawnServer(env) {
      const peer = {
        send(message) { behavior.send?.(message, env); },
        async waitForId(requestId) { return behavior.reply?.(requestId) ?? { id: requestId, result: {} }; },
        async quiesce() {}, async stop() {}, serverRequests() { return []; },
      };
      behavior.start?.(env);
      return peer;
    } };
    const result = await runOne(scenario(id), target);
    assert.equal(target.serverLaunch, 'ordinary-server');
    return result;
  });
}

const write = (env, entries) => writeFileSync(env.MCP_FAKE_TRANSCRIPT, entries.map((item) => JSON.stringify(item)).join('\n') + '\n');

test('verification traffic cannot satisfy the seam tools/call observation', async () => {
  const result = await execute('NO-ID-PASSTHROUGH', { start(env) { write(env, [entry({ id: 1, method: 'tools/list' })]); } });
  assert.equal(result.verdict, 'ERROR');
});

test('an honest upstream cannot stand in for either required hostile frame', async () => {
  for (const id of ['UPSTREAM-SERVER-REQUEST-NOT-RELAYED', 'ROLE-ISOLATION-UNDER-UPSTREAM-CRASH']) {
    const result = await execute(id, { start(env) { write(env, [entry(call(7))]); } });
    assert.equal(result.verdict, 'ERROR');
  }
});

test('a throwing seam spawn always restores the ordinary launch command', async () => {
  await withArm(async () => {
    const target = { serverLaunch: 'ordinary-server', spawnServer() { throw new Error('fixture spawn failure'); } };
    assert.equal((await runOne(scenario('NO-ID-PASSTHROUGH'), target)).verdict, 'ERROR');
    assert.equal(target.serverLaunch, 'ordinary-server');
  });
});

async function collision(names, instances) {
  return execute('UPSTREAM-NAME-COLLISION', {
    start(env) { write(env, []); },
    send(message, env) {
      if (message.method === 'tools/call') appendFileSync(env.MCP_FAKE_TRANSCRIPT, JSON.stringify(http(
        call(message.id, message.params.arguments.text), message.id === 'collision-left' ? instances[0] : instances[1],
      )) + '\n');
    },
    reply(id) { return id === 1 ? { id, result: { tools: names.map((name) => ({ name })) } }
      : { id, result: { content: [{ type: 'text', text: id === 'collision-left' ? 'left-peer' : 'right-peer' }] } }; },
  });
}
test('collision sensitivity includes missing exports and misrouting both names to one upstream', async () => {
  assert.equal((await collision([], [1, 2])).verdict, 'FAIL');
  assert.equal((await collision(['echo'], [1, 2])).verdict, 'FAIL');
  assert.equal((await collision(['echo', 'seamright_echo'], [1, 1])).verdict, 'FAIL');
  assert.equal((await collision(['echo', 'seamright_echo'], [1, 2])).verdict, 'PASS');
});

test('credential seam needs an actual supplied Authorization witness and observes header/body leaks', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-credential-fixture-'));
  const token = 'valid-boot-credential-fixture';
  const saved = { file: process.env.MCP_SEAM_BEARER_FILE, front: process.env.MCP_SEAM_FRONT_TRANSCRIPT };
  process.env.MCP_SEAM_BEARER_FILE = join(dir, 'bearer');
  process.env.MCP_SEAM_FRONT_TRANSCRIPT = join(dir, 'front.jsonl');
  writeFileSync(process.env.MCP_SEAM_BEARER_FILE, token, { mode: 0o600 });
  try {
    for (const [front, matches, headers, verdict] of [
      [false, 0, [], 'ERROR'],
      [true, null, [], 'ERROR'],
      [true, 1, [{ name: 'authorization', sha256: hash(`Bearer ${token}`) }], 'FAIL'],
      [true, 1, [], 'FAIL'],
      [true, 0, [], 'PASS'],
    ]) {
      writeFileSync(process.env.MCP_SEAM_FRONT_TRANSCRIPT, '');
      const result = await execute('NO-CREDENTIAL-FORWARDING', {
        send(_message, env) {
          if (front) appendFileSync(process.env.MCP_SEAM_FRONT_TRANSCRIPT, JSON.stringify({
            method: 'tools/call', requestIdSha256: hash('1'), suppliedAuthorizationSha256: hash(`Bearer ${token}`),
          }) + '\n');
          write(env, [entry(call(9, 'hello')), http(call(9, 'hello'), 1, { credentialMatches: matches, headers })]);
        },
      });
      assert.equal(result.verdict, verdict);
      assert.ok(!JSON.stringify(result).includes(token), 'credential bytes cannot enter the report');
    }
  } finally {
    if (saved.file === undefined) delete process.env.MCP_SEAM_BEARER_FILE;
    else process.env.MCP_SEAM_BEARER_FILE = saved.file;
    if (saved.front === undefined) delete process.env.MCP_SEAM_FRONT_TRANSCRIPT;
    else process.env.MCP_SEAM_FRONT_TRANSCRIPT = saved.front;
    rmSync(dir, { recursive: true, force: true });
  }
});

test('cancellation waits for upstream start and measures the exact upstream id as advisory', async () => {
  for (const correlated of [false, true]) {
    let started = false;
    const result = await execute('DOWNSTREAM-CANCEL-PROPAGATES', {
      start(env) { write(env, []); },
      send(message, env) {
        if (message.method === 'tools/call') {
          setTimeout(() => { started = true; write(env, [entry(call('mapped-id'))]); }, 10);
        }
        if (message.method === 'notifications/cancelled') {
          assert.ok(started, 'the test must observe upstream work before sending cancellation');
          appendFileSync(env.MCP_FAKE_TRANSCRIPT, JSON.stringify(entry({
            method: 'notifications/cancelled', params: { requestId: correlated ? 'mapped-id' : 'unrelated-id' },
          })) + '\n');
        }
      },
    });
    assert.equal(result.verdict, 'PASS');
    assert.equal(result.recommendations.find((item) => item.key === 'seam.propagatesCancellation').ok, correlated);
  }
});

test('upstream terminal error representation remains variance instead of an invented MUST', async () => {
  const result = await execute('UPSTREAM-FAILURE-IS-TOOL-ERROR', {
    start(env) { write(env, [entry(call(7))]); },
    reply(id) { return { id, error: { code: -32603, message: 'fixture upstream failed' } }; },
  });
  assert.equal(result.verdict, 'PASS');
  assert.equal(result.variance.find((item) => item.key === 'seam.upstreamStall.answerKind').value, 'error:-32603');
});

test('an expired downstream wait after observed upstream start is an incomplete run', async () => {
  const result = await withArm(async () => runOne(scenario('UPSTREAM-FAILURE-IS-TOOL-ERROR'), {
    serverLaunch: 'ordinary-server', spawnServer(env) {
      write(env, [entry(call(7))]);
      return { send() {}, async waitForId() { throw new Error('fixture driver wait expired'); }, async stop() {} };
    },
  }));
  assert.equal(result.verdict, 'ERROR');
  assert.match(result.error, /INCOMPLETE/);
});

async function fixturePort() {
  const server = createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test('the HTTP observer catches real headers and escaped body credentials without retaining their bytes', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-http-credential-'));
  const token = 'ephemeral-credential-canary';
  const credentialFile = join(dir, 'bearer');
  const transcript = join(dir, 'upstream.jsonl');
  const control = join(dir, 'control.json');
  writeFileSync(credentialFile, token, { mode: 0o600 });
  writeFileSync(control, JSON.stringify({ mode: 'honest', credentialFile, transcript }));
  const port = await fixturePort();
  const fixture = fileURLToPath(new URL('../fakepeer/http-fake-server.mjs', import.meta.url));
  const child = spawn(process.execPath, [fixture, String(port), control], { stdio: ['ignore', 'ignore', 'pipe'] });
  const closed = new Promise((resolve) => child.once('close', resolve));
  let log = '';
  child.stderr.on('data', (chunk) => { log += chunk.toString('utf8'); });
  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('HTTP fixture did not listen')), 5000);
      child.once('error', (error) => { clearTimeout(timer); reject(error); });
      child.stderr.on('data', () => {
        if (log.includes(`listening on 127.0.0.1:${port},`)) { clearTimeout(timer); resolve(); }
      });
    });
    const body = JSON.stringify(call(7, token)).split(token).join('\\u0065phemeral-credential-canary');
    const response = await fetch(`http://127.0.0.1:${port}/mcp`, {
      method: 'POST', headers: { authorization: `Bearer ${token}`, 'x-copied-credential': token }, body,
    });
    await response.arrayBuffer();
    const raw = readFileSync(transcript, 'utf8');
    assert.ok(!raw.includes(token));
    assert.ok(!log.includes(token));
    const observed = raw.trim().split('\n').map((line) => JSON.parse(line)).find((item) => item.direction === 'http-client->server');
    assert.ok(observed.credentialMatches > 0);
    assert.equal(observed.headers.find((header) => header.name === 'authorization').sha256, hash(`Bearer ${token}`));
    assert.equal(observed.payload.params.arguments.text, '[REDACTED]');
  } finally {
    child.kill('SIGTERM');
    await closed;
    rmSync(dir, { recursive: true, force: true });
  }
});
