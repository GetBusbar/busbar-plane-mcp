import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { judgeNegativePeer } from './judge-negative-peer.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const cli = fileURLToPath(new URL('../bin/mcp-battery.mjs', import.meta.url));
const fake = fileURLToPath(new URL('../fakepeer/fake-server.mjs', import.meta.url));
for (const mode of ['honest', 'stall', 'truncate', 'half-answer']) {
  test(`${mode}: exact injected observation is distinct from a conformance verdict`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'mcp-peer-observation-'));
    try {
      const transcriptPath = join(dir, 'fixture.jsonl');
      const result = spawnSync(process.execPath, [cli, 'run', '--name', mode,
        '--server-cmd', `"${process.execPath}" "${fake}"`, '--role', 'server',
        '--tier', 'push,pr', '--only', 'SRV.DISCOVER.IMPLEMENTED,SRV.TOOLS.LIST-SHAPE,CONC.CANCEL-STOPS-RESPONSE,CONC.SUBSCRIPTION-ACK-FIRST',
        '--out', join(dir, 'report.json'), '--checkpoint', join(dir, 'checkpoint.json')],
      { cwd: root, encoding: 'utf8', timeout: 30000, env: { ...process.env,
        MCP_FAKE_MODE: mode, MCP_FAKE_TRANSCRIPT: transcriptPath,
        ...(mode === 'honest' ? {} : { MCP_INJECTED_PEER_TIMEOUT_MS: '150' }) } });
      assert.ifError(result.error);
      assert.equal(result.status, mode === 'honest' ? 0 : 1, result.stdout + result.stderr);
      const report = JSON.parse(readFileSync(join(dir, 'report.json')));
      const checkpoint = JSON.parse(readFileSync(join(dir, 'checkpoint.json')));
      const transcript = readFileSync(transcriptPath, 'utf8').trim().split('\n').map(JSON.parse);
      assert.equal(report.results.length, 4);
      const caught = judgeNegativePeer(mode, report, checkpoint, transcript, result.status);
      assert.equal(caught, mode === 'honest' ? 0 : mode === 'stall' ? 2 : 3);
      if (mode === 'honest') return;
      assert.equal(report.results.find(row => row.id === 'SRV.TOOLS.LIST-SHAPE').verdict, 'ERROR');
      assert.equal(report.results.find(row => row.id === 'CONC.SUBSCRIPTION-ACK-FIRST').verdict, 'ERROR');
      // None of these may be mistaken for an intentionally observed peer fault.
      const mutations = [
        [r => { delete r.results[1].peerObservation; }, 'unmatched peer ERROR'],
        [r => { r.results[1].peerObservation.requestId = 'wrong'; }, 'admission not witnessed'],
        [r => { r.results[1].peerObservation.stdoutSha256 = 'wrong'; }, 'wire observation mismatch'],
      ];
      for (const [mutate, message] of mutations) {
        const changed = structuredClone(report); mutate(changed);
        const cp = { ...checkpoint, results: changed.results };
        assert.throws(() => judgeNegativePeer(mode, changed, cp, transcript, 1), new RegExp(message));
      }
      assert.throws(() => judgeNegativePeer(mode, report,
        { ...checkpoint, execution: { ...checkpoint.execution, completed: false } }, transcript, 1), /incomplete/);
      assert.throws(() => judgeNegativePeer(mode, report,
        { ...checkpoint, execution: { ...checkpoint.execution, selectedCases: 5 } }, transcript, 1), /incomplete/);
      assert.throws(() => judgeNegativePeer(mode, report, checkpoint, [], 1), /identity/);
      assert.throws(() => judgeNegativePeer(mode, report, checkpoint, transcript, 124), /incomplete/);
      assert.throws(() => judgeNegativePeer('honest', report, checkpoint, transcript, 1), /unrelated/);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
