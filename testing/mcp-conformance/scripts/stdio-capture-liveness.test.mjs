import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { StdioPeer } from '../src/core/stdio-peer.mjs';
import { request } from '../src/core/jsonrpc.mjs';
import { runOne } from '../src/core/runner.mjs';

const fake = fileURLToPath(new URL('../fakepeer/fake-server.mjs', import.meta.url));

test('giant fixture is parsed and captured exactly with a linear chunk accumulator', async () => {
  const peer = new StdioPeer(process.execPath, [fake], { env: { MCP_FAKE_MODE: 'giant' } }).start();
  try {
    peer.send(request('giant', 'tools/list'));
    const reply = await peer.waitForId('giant', 5000);
    assert.equal(reply.result.content[0].text.length, 12 * 1024 * 1024);
    const wire = peer.stdoutBytes;
    assert.equal(wire.toString('utf8'), `${peer.rawLines[0]}\n`);
    assert.deepEqual(JSON.parse(wire), reply);
    assert.equal(peer.stdoutBytes, wire, 'snapshot is reused when no bytes arrive');
    assert.ok(peer._stdoutChunks.length > 1, 'large reply crossed pipe chunks');
  } finally { await peer.stop(); }
});

test('UTF-8 and newlines spanning chunks preserve complete lines and terminal bytes', () => {
  const peer = new StdioPeer('unused');
  const wire = Buffer.from('{"text":"😀"}\n{"last":true}');
  for (const byte of wire) peer._consumeStdout(peer._decoder.write(Buffer.from([byte])));
  peer._consumeStdout(peer._decoder.end());
  assert.deepEqual(peer.messages, [{ text: '😀' }]);
  assert.equal(peer._lineParts.join(''), '{"last":true}');
});

test('half-answer stdout EOF rejects a pending waiter before process exit and keeps raw bytes', async () => {
  const peer = new StdioPeer(process.execPath, [fake], { env: { MCP_FAKE_MODE: 'half-answer' } }).start();
  try {
    peer.send(request('half', 'tools/list'));
    await assert.rejects(peer.waitForId('half', 5000), /stdout ended/);
    assert.equal(peer.exited, false, 'fixture still holds stdin open');
    assert.equal(peer.stdoutEnded, true);
    assert.equal(peer.badLines.length, 1);
    assert.match(peer.stdoutBytes.toString('utf8'), /"resultType":"comp$/);
    await assert.rejects(peer.waitForId('another', 5000), /stdout ended/);
  } finally { await peer.stop(); }
});

test('stdout EOF remains ERROR without a scenario protocol assertion', async () => {
  const record = await runOne({ id: 'capture.eof', title: 'EOF capture', run: async () => {
    const peer = new StdioPeer(process.execPath, [fake], { env: { MCP_FAKE_MODE: 'half-answer' } }).start();
    try {
      peer.send(request('half', 'tools/list'));
      await peer.waitForId('half');
    } finally { await peer.stop(); }
  } }, {});
  assert.equal(record.verdict, 'ERROR');
  assert.match(record.error, /stdout ended/);
  assert.deepEqual(record.assertions, []);
});

test('malformed listing and successful subscription completion fail concrete clauses; honest prerequisites pass', async () => {
  const { allTests } = await import('../src/core/runner.mjs');
  const { Target } = await import('../src/core/target.mjs');
  await import('../src/suites/server-adversarial.mjs');
  await import('../src/suites/server-concurrency.mjs');
  const ids = ['ADV.DEEP-NESTING', 'ADV.NUL-AND-CONTROL-BYTES',
    'ADV.UNICODE-AND-SURROGATES', 'CONC.SUBSCRIPTION-ACK-FIRST'];
  for (const mode of ['honest', 'deep', 'malformed', 'mrtr-no-fields', 'mrtr-undeclared', 'evil-elicitation']) {
    const target = new Target({ name: mode, serverLaunch: `"${process.execPath}" "${fake}"`,
      env: { MCP_FAKE_MODE: mode } });
    for (const id of ids) {
      const record = await runOne(allTests().find(t => t.id === id), target);
      assert.equal(record.verdict, mode === 'honest' ? 'PASS' : 'FAIL', `${mode} ${id}: ${record.error}`);
      assert.equal(record.error, null);
      if (mode !== 'honest') {
        const clause = ['mrtr-no-fields', 'mrtr-undeclared', 'evil-elicitation'].includes(mode)
          ? 'PAT.MRTR.ONLY-SUPPORTED-METHODS'
          : id.startsWith('ADV.') ? 'TOOLS.LIST-RESPONDS' : 'SUB.ACK-FIRST';
        assert.ok(record.assertions.some(a => !a.ok && a.clause === clause), `${mode} ${id}`);
        if (mode === 'malformed' && id.startsWith('ADV.')) {
          assert.ok(record.assertions.some(a => !a.ok && a.clause === 'STDIO.STDOUT-ONLY-MCP'));
        }
      }
    }
  }
});
