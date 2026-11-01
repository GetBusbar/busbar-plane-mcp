import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { StdioPeer } from '../src/core/stdio-peer.mjs';
import { Target } from '../src/core/target.mjs';
import { allTests, runOne } from '../src/core/runner.mjs';
import { request, notification } from '../src/core/jsonrpc.mjs';
import '../src/suites/server-conformance.mjs';
import '../src/suites/server-adversarial.mjs';

const bridge = fileURLToPath(new URL('./stdio-http-bridge.mjs', import.meta.url));
const fake = fileURLToPath(new URL('../fakepeer/fake-server.mjs', import.meta.url));
const hostile = fileURLToPath(new URL('../fakepeer/http-observation-fixture.mjs', import.meta.url));
const launch = (...args) => args.map((value) => JSON.stringify(value)).join(' ');
const metaIds = ['SRV.META.MISSING-PROTOCOL-VERSION', 'SRV.META.MISSING-CAPABILITIES',
  'ADV.META-NOT-AN-OBJECT'];
const invalidParams = (id) => ({ jsonrpc: '2.0', id,
  error: { code: -32602, message: 'Invalid params' } });

async function withHttp(answer, run) {
  const server = createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => answer(JSON.parse(body), res));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `http://127.0.0.1:${server.address().port}/mcp`;
  try { await run(url); }
  finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

function reply(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

async function exerciseMeta(id, serverLaunch) {
  const scenario = allTests().find((entry) => entry.id === id);
  assert.ok(scenario);
  return runOne(scenario, new Target({ name: 'controlled-http-status', serverLaunch,
    env: { MCP_FAKE_MODE: 'honest' } }));
}

// These tests use only pre-existing driver/runner methods. The new observations are
// inspected as optional properties, so old source reaches actual assertion failures.
for (const id of metaIds) {
  for (const status of [200, 400]) {
    test(`${id} distinguishes HTTP ${status} with the identical -32602 body`, async () => {
      await withHttp((message, res) => {
        if (message.id === 'health-probe') {
          reply(res, 200, { jsonrpc: '2.0', id: message.id, result: { resultType: 'complete' } });
        } else reply(res, status, invalidParams(message.id));
      }, async (url) => {
        const result = await exerciseMeta(id, launch(process.execPath, bridge, url));
        assert.equal(result.verdict, status === 400 ? 'PASS' : 'FAIL', JSON.stringify(result));
        assert.ok(result.assertions.some((entry) => entry.detail?.includes('requires HTTP 400')
          && entry.ok === (status === 400)), JSON.stringify(result));
      });
    });
  }
  test(`${id} retains the native stdio assertion without an HTTP claim`, async () => {
    const result = await exerciseMeta(id, launch(process.execPath, fake));
    assert.equal(result.verdict, 'PASS', JSON.stringify(result));
    assert.equal(result.assertions.some((entry) => entry.detail?.includes('requires HTTP 400')), false);
  });
}

for (const mode of ['invalid', 'truncated', 'missing']) {
  test(`a ${mode} status record cannot erase the malformed-meta HTTP assertion`, async () => {
    const result = await exerciseMeta(metaIds[0], launch(process.execPath, hostile, mode));
    assert.equal(result.verdict, 'ERROR', JSON.stringify(result));
    assert.match(result.error, /HTTP observation|HTTP status observation/);
  });
}

test('out-of-order HTTP responses keep status, id type, body and input ordinal correlated', async () => {
  const replies = new Map();
  let releaseFirst;
  await withHttp((message, res) => {
    replies.set(message.id, { message, res });
    // Both actual requests must arrive before either answer is released.
    if (replies.size !== 2) return;
    releaseFirst = () => reply(replies.get(7).res, 200, { jsonrpc: '2.0', id: 7,
      error: { code: -32603, message: 'Internal error' } });
    reply(replies.get('7').res, 400, invalidParams('7'));
  }, async (url) => {
    const peer = new StdioPeer(process.execPath, [bridge, url], {
      env: { MCP_BRIDGE_BEARER: 'fixture-bearer-do-not-record' },
    }).start();
    try {
      peer.send(request(7, 'tools/call', { name: 'failing_tool', arguments: {} }));
      peer.send(request('7', 'tools/list', {}, { protocolVersion: null }));
      assert.deepEqual(await peer.waitForId('7'), invalidParams('7'));
      assert.equal(peer.messages[0].id, '7');
      releaseFirst();
      assert.deepEqual(await peer.waitForId(7), { jsonrpc: '2.0', id: 7,
        error: { code: -32603, message: 'Internal error' } });
      await peer.stop();
      assert.equal(peer.httpTransport, true);
      assert.equal(peer.httpObservationError, null);
      assert.deepEqual(peer.httpStatuses?.slice().sort((a, b) => a.sequence - b.sequence), [
        { sequence: 1, id: 7, status: 200 }, { sequence: 2, id: '7', status: 400 },
      ]);
      assert.equal(peer.badLines.length, 0);
      assert.equal(peer.messages.length, 2);
      assert.equal(peer.stderr, '');
      assert.equal(JSON.stringify(peer.httpStatuses).includes('fixture-bearer'), false);
      assert.equal(peer.stdoutBytes.includes(Buffer.from('fixture-bearer')), false);
    } finally { await peer.stop(); }
  });
});

test('a broken observation pipe terminates the bridge before an unobserved body is emitted', async () => {
  await withHttp((message, res) => reply(res, 200, invalidParams(message.id)), async (url) => {
    const peer = new StdioPeer(process.execPath, [bridge, url]).start();
    try {
      peer.proc.stdio[3]?.destroy();
      peer.send(request(1, 'tools/list'));
      peer.closeStdin();
      await peer.waitForExit();
      assert.notEqual(peer.exitCode, 0);
      assert.equal(peer.responsesFor(1).length, 0);
    } finally { await peer.stop(); }
  });
});

test('a 202 notification records its HTTP status without synthesizing an RPC response', async () => {
  await withHttp((message, res) => {
    assert.equal(Object.hasOwn(message, 'id'), false);
    res.writeHead(202);
    res.end();
  }, async (url) => {
    const peer = new StdioPeer(process.execPath, [bridge, url]).start();
    try {
      peer.send(notification('notifications/cancelled', { requestId: 'never-issued' }));
      peer.closeStdin();
      await peer.waitForExit();
      assert.equal(peer.exitCode, 0);
      assert.deepEqual(peer.httpStatuses, [{ sequence: 1, id: null, status: 202 }]);
      assert.equal(peer.stdoutBytes.length, 0);
      assert.equal(peer.stderr, '');
    } finally { await peer.stop(); }
  });
});

test('SSE progress and pending results retain their HTTP status and exact RPC envelopes', async () => {
  const progress = notification('notifications/progress', { progressToken: 'work', progress: 1 });
  const pending = { jsonrpc: '2.0', id: 'pending', result: { resultType: 'pending', taskId: 'work' } };
  await withHttp((_message, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    res.end(`data: ${JSON.stringify(progress)}\n\ndata: ${JSON.stringify(pending)}\n\n`);
  }, async (url) => {
    const peer = new StdioPeer(process.execPath, [bridge, url]).start();
    try {
      peer.send(request('pending', 'tools/call', { name: 'work', arguments: {} }));
      assert.deepEqual(await peer.waitForId('pending'), pending);
      await peer.stop();
      assert.deepEqual(peer.messages, [progress, pending]);
      assert.deepEqual(peer.httpStatuses, [{ sequence: 1, id: 'pending', status: 200 }]);
      assert.equal(peer.badLines.length, 0);
      assert.equal(peer.stderr, '');
    } finally { await peer.stop(); }
  });
});
