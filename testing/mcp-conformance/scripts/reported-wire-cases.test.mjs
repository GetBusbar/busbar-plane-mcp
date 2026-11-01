import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { StdioPeer, parseLaunch } from '../src/core/stdio-peer.mjs';
const fixture = fileURLToPath(new URL('../fakepeer/wire-fixture.mjs', import.meta.url));
const bridge = fileURLToPath(new URL('./stdio-http-bridge.mjs', import.meta.url));
const request = (id) => ({ jsonrpc: '2.0', id, method: 'server/discover' });

test('a multibyte character survives distinct pipe reads', async () => {
  const peer = new StdioPeer(process.execPath, [fixture, 'split']).start();
  try {
    const first = once(peer.proc.stdout, 'data');
    peer.send(request(1));
    await first;
    peer.send(request(2));
    assert.equal((await peer.waitForId(1)).result.text, '雪');
    await peer.waitForExit();
  } finally { await peer.stop(); }
});

test('the final unterminated frame is drained before process completion', async () => {
  const peer = new StdioPeer(process.execPath, [fixture, 'final']).start();
  try {
    peer.send(request(1));
    await peer.waitForExit();
    assert.equal(peer.responsesFor(1)[0]?.result.final, true);
    assert.throws(() => peer.send(request(2)), /exited|writ|closed/i);
  } finally { await peer.stop(); }
});

test('quoted segments inside an argument reach the actual child unchanged', async () => {
  const launch = parseLaunch(`"${process.execPath}" "${fixture}" args --value="a b" ''`);
  const peer = new StdioPeer(launch.command, launch.args).start();
  try {
    peer.send(request(1));
    assert.deepEqual((await peer.waitForId(1)).result.args, ['--value=a b', '']);
  } finally { await peer.stop(); }
});

async function withHttp(reply, run) {
  const server = createServer(reply);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const peer = new StdioPeer(process.execPath, [bridge, `http://127.0.0.1:${server.address().port}/mcp`]).start();
  try { await run(peer); }
  finally { await peer.stop(); server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); }
}

for (const separator of ['\r', '\r\n', '\n']) {
  test(`multiline SSE data is one message with ${JSON.stringify(separator)} separators`, async () => {
    await withHttp((req, res) => {
      req.resume();
      req.on('end', () => {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end(['data: {"jsonrpc":"2.0","id":1,', 'data: "result":{"text":"joined"}}', '', ''].join(separator));
      });
    }, async (peer) => {
      peer.send(request(1));
      assert.equal((await peer.waitForId(1)).result.text, 'joined');
    });
  });
}

test('an HTTP failure cannot become a clean silent adapter', async () => {
  await withHttp((req, res) => { req.resume(); res.writeHead(502); res.end('upstream died'); }, async (peer) => {
    peer.send(request(1));
    await peer.waitForExit();
    assert.notEqual(peer.exitCode, 0);
    assert.equal(peer.responsesFor(1).length, 0);
  });
});

for (const [type, body] of [
  ['application/json', ' \r\n\t'],
  ['text/event-stream', ''],
  ['text/event-stream', ': upstream failure with no RPC event\n\n'],
]) {
  test(`an HTTP failure with no RPC frame remains unsuccessful for ${JSON.stringify([type, body])}`, async () => {
    await withHttp((req, res) => { req.resume(); res.writeHead(500, { 'content-type': type }); res.end(body); }, async (peer) => {
      peer.send(request(1));
      await peer.waitForExit();
      assert.notEqual(peer.exitCode, 0);
      assert.equal(peer.responsesFor(1).length, 0);
    });
  });
}

test('a successful SSE response without an RPC event is not reclassified as an HTTP failure', async () => {
  await withHttp((req, res) => { req.resume(); res.writeHead(200, { 'content-type': 'text/event-stream' }); res.end(': keepalive\n\n'); }, async (peer) => {
    peer.send(request(1));
    peer.closeStdin();
    await peer.waitForExit();
    assert.equal(peer.exitCode, 0);
    assert.equal(peer.responsesFor(1).length, 0);
  });
});
