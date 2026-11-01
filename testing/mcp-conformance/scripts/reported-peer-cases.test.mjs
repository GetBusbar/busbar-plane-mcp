import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { StdioPeer } from '../src/core/stdio-peer.mjs';

const fake = fileURLToPath(new URL('../fakepeer/fake-server.mjs', import.meta.url));

test('an unknown attack mode fails before it can behave like an honest peer', async () => {
  const peer = new StdioPeer(process.execPath, [fake], { env: { MCP_FAKE_MODE: 'misspelled-attack' } }).start();
  try {
    await peer.waitForExit();
    assert.equal(peer.exitCode, 2);
    assert.match(peer.stderr, /unknown MCP_FAKE_MODE/);
  } finally { await peer.stop(); }
});

test('scalar and null frames are refused without crashing the fake peer', async () => {
  const peer = new StdioPeer(process.execPath, [fake], { env: { MCP_FAKE_MODE: 'honest' } }).start();
  try {
    peer.sendRaw('null\n');
    assert.equal((await peer.waitForId(null)).error.code, -32600);
    peer.sendRaw('5\n');
    peer.send({ jsonrpc: '2.0', id: 'barrier', method: 'server/discover' });
    assert.ok((await peer.waitForId('barrier')).result);
    assert.equal(peer.responsesFor(null).length, 2);
    assert.equal(peer.exited, false);
  } finally { await peer.stop(); }
});

test('a failed transcript write stops the peer before any answer is trusted', async () => {
  const peer = new StdioPeer(process.execPath, [fake], {
    env: { MCP_FAKE_MODE: 'honest', MCP_FAKE_TRANSCRIPT: `${fake}/not-a-directory` },
  }).start();
  try {
    peer.send({ jsonrpc: '2.0', id: 1, method: 'server/discover' });
    await peer.waitForExit();
    assert.equal(peer.exitCode, 2);
    assert.equal(peer.responsesFor(1).length, 0);
    assert.match(peer.stderr, /cannot record fake-peer transcript/);
  } finally { await peer.stop(); }
});
