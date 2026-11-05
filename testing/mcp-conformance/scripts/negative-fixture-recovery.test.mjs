import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cli = join(root, 'bin/mcp-battery.mjs');
const fake = join(root, 'fakepeer/fake-server.mjs');
const launch = `"${process.execPath}" "${fake}"`;
const fixtureCases = 'SRV.TOOLS.EXECUTION-ERROR-IS-RESULT,SRV.TOOLS.OUTPUTSCHEMA-CONFORMS';
function args(mode, out, checkpoint, only = fixtureCases) {
  return [cli, 'run', '--name', `recovery-${mode}`, '--server-cmd', launch,
    '--failing-tool', 'fail', '--tier', 'push,pr', '--role', 'server',
    '--only', only, '--out', out, '--checkpoint', checkpoint];
}
function run(mode, dir, only = fixtureCases) {
  const out = join(dir, `${mode}.json`), checkpoint = join(dir, `${mode}.checkpoint.json`);
  const result = spawnSync(process.execPath, args(mode, out, checkpoint, only), {
    cwd: root, encoding: 'utf8', timeout: 15000,
    env: { ...process.env, MCP_FAKE_MODE: mode, MCP_NO_SKIPS: '1', MCP_BATTERY_FAILSAFE_MS: mode === 'stall' ? '1000' : '5000' },
  });
  assert.ifError(result.error);
  return { result, report: JSON.parse(readFileSync(out)), checkpoint: JSON.parse(readFileSync(checkpoint)) };
}

test('honest and injection fixtures exercise both required capabilities under NO_SKIPS', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-capabilities-'));
  try {
    for (const mode of ['honest', 'injection']) {
      const { result, report, checkpoint } = run(mode, dir);
      assert.equal(result.status, 0, result.stdout + result.stderr);
      assert.deepEqual(report.results.map(r => r.verdict), ['PASS', 'PASS']);
      assert.ok(report.results[0].assertions.length > 0);
      assert.ok(report.results[1].assertions.some(a => a.clause === 'TOOLS.OUTPUTSCHEMA-CONFORMANCE' && a.ok));
      assert.deepEqual(checkpoint.execution, { completed: true, selectedCases: 2, recordedCases: 2 });
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('outputschema-lie remains a real failed conformance assertion', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-output-lie-'));
  try {
    const { result, report } = run('outputschema-lie', dir);
    assert.equal(result.status, 1);
    const failure = report.results.find(r => r.id === 'SRV.TOOLS.OUTPUTSCHEMA-CONFORMS');
    assert.equal(failure.verdict, 'FAIL');
    assert.equal(failure.error, null);
    assert.ok(failure.assertions.some(a => a.clause === 'TOOLS.OUTPUTSCHEMA-CONFORMANCE' && !a.ok));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('request failsafe remains ERROR in both complete report and checkpoint', () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-stall-error-'));
  try {
    const { result, report, checkpoint } = run('stall', dir, 'SRV.TOOLS.LIST-SHAPE');
    assert.equal(result.status, 1);
    assert.equal(report.results.length, 1);
    assert.equal(report.results[0].verdict, 'ERROR');
    assert.match(report.results[0].error, /failsafe timeout/);
    assert.equal(checkpoint.results[0].verdict, 'ERROR');
    assert.equal(checkpoint.execution.completed, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('interruption preserves incomplete checkpoint and terminates owned detached peer', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-interrupted-'));
  const peerFile = join(dir, 'peer.mjs'), pidFile = join(dir, 'pid');
  const checkpoint = join(dir, 'checkpoint.json'), out = join(dir, 'out.json');
  writeFileSync(peerFile, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(pidFile)}, String(process.pid)); setInterval(() => {}, 1000);`);
  const argv = args('stall', out, checkpoint, 'SRV.TOOLS.LIST-SHAPE');
  argv[argv.indexOf('--server-cmd') + 1] = `"${process.execPath}" "${peerFile}"`;
  const child = spawn(process.execPath, argv, { cwd: root, stdio: 'ignore',
    env: { ...process.env, MCP_BATTERY_FAILSAFE_MS: '15000' } });
  const exited = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
  let peerPid;
  try {
    const deadline = Date.now() + 5000;
    while (!existsSync(pidFile) && Date.now() < deadline) await new Promise(r => setTimeout(r, 20));
    assert.ok(existsSync(pidFile), 'fixture process started');
    peerPid = Number(readFileSync(pidFile, 'utf8'));
    child.kill('SIGTERM');
    assert.deepEqual(await exited, { code: 143, signal: null });
    const partial = JSON.parse(readFileSync(checkpoint));
    assert.deepEqual(partial.execution, { completed: false, selectedCases: 1, recordedCases: 0 });
    assert.deepEqual(partial.results, []);
    assert.equal(existsSync(out), false);
    const compare = spawnSync(process.execPath, [cli, 'compare', '--control', checkpoint, '--subject', checkpoint], { encoding: 'utf8' });
    assert.equal(compare.status, 1);
    assert.match(compare.stderr, /interrupted checkpoint is incomplete/);
    // Wait for the killed child to be reaped by the OS before inspecting its PID.
    const reapDeadline = Date.now() + 3000;
    let alive = true;
    while (alive && Date.now() < reapDeadline) {
      try { process.kill(peerPid, 0); await new Promise(r => setTimeout(r, 20)); }
      catch { alive = false; }
    }
    assert.equal(alive, false, 'owned detached peer terminated');
  } finally {
    child.kill('SIGKILL');
    if (peerPid) { try { process.kill(peerPid, 'SIGKILL'); } catch {} }
    rmSync(dir, { recursive: true, force: true });
  }
});
