import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { probeMode, CONTRACT } from './local-liveness-control.mjs';

const expected = {
  honest: null,
  stall: 'LOCAL.RESPONSE-BY-DEADLINE',
  truncate: 'LOCAL.COMPLETE-JSON-LINES',
  'half-answer': 'LOCAL.COMPLETE-JSON-LINES',
  'wrong-id': 'LOCAL.NO-UNREQUESTED-REPLY-ID',
  'dup-response': 'LOCAL.EXACTLY-ONE-REPLY',
  giant: 'LOCAL.REPLY-BYTE-BOUND',
  deep: 'LOCAL.JSON-DEPTH-BOUND',
  malformed: 'LOCAL.COMPLETE-JSON-LINES',
};
for (const [mode, failedClause] of Object.entries(expected)) {
  test(`${mode}: local contract records actual admission and causal bytes`, async () => {
    const directory = mkdtempSync(join(tmpdir(), 'mcp-local-contract-'));
    try {
      const receipt = await probeMode(mode, directory);
      assert.equal(receipt.localVerdict, failedClause ? 'FAIL' : 'PASS', receipt.error);
      assert.equal(receipt.error, null);
      assert.equal(receipt.expectationMatched, true);
      assert.equal(receipt.admission.parsedRecords, 1);
      assert.equal(receipt.admission.rawRecords, 1);
      assert.ok(receipt.observations.collectionElapsedMs >= CONTRACT.responseDeadlineMs);
      assert.deepEqual(receipt.originalBattery, { executed: false, modified: false, result: 'NOT MEASURED' });
      assert.equal(receipt.contract.normative, false);
      if (failedClause) assert.ok(receipt.assertions.some(a => a.id === failedClause && !a.ok));
      const raw = readFileSync(join(directory, mode, 'stdout.bin'));
      const stimulated = raw.subarray(receipt.observations.stdoutByteStart, receipt.observations.stdoutByteEnd);
      if (mode === 'stall') assert.equal(stimulated.length, 0);
      if (mode === 'truncate' || mode === 'half-answer') {
        assert.ok(stimulated.length > 0);
        assert.notEqual(stimulated.at(-1), 10);
      }
      assert.ok(receipt.artifacts['fixture.jsonl'].bytes > 0);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}

test('startup panic remains ERROR and cannot become an expected negative failure', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-local-panic-'));
  try {
    const broken = join(directory, 'panic.mjs');
    writeFileSync(broken, 'throw new Error("infrastructure panic");\n');
    const receipt = await probeMode('stall', directory, { fixture: broken });
    assert.equal(receipt.localVerdict, 'ERROR');
    assert.equal(receipt.expectationMatched, false);
    assert.equal(receipt.admission, null);
    assert.deepEqual(receipt.assertions, []);
    assert.match(readFileSync(join(directory, 'stall/stderr.txt'), 'utf8'), /infrastructure panic/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('stdin write without an independent admission record remains ERROR', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'mcp-local-admission-'));
  try {
    const incomplete = join(directory, 'no-observer.mjs');
    writeFileSync(incomplete, `import { createInterface } from 'node:readline';
const input = createInterface({ input: process.stdin });
input.on('line', line => { const request = JSON.parse(line);
  if (request.method === 'server/discover') console.log(JSON.stringify({ jsonrpc: '2.0', id: request.id,
    result: { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: { tools: {} } } }));
});`);
    const receipt = await probeMode('stall', directory, { fixture: incomplete });
    assert.equal(receipt.localVerdict, 'ERROR');
    assert.equal(receipt.expectationMatched, false);
    assert.equal(receipt.admission, null);
    assert.deepEqual(receipt.assertions, []);
    assert.ok(receipt.discovery, 'discovery alone does not prove the next request was admitted');
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
