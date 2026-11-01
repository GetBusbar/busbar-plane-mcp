import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { cite } from '../src/core/spec.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const battery = join(root, 'bin/mcp-battery.mjs');
const row = (id, role, verdict = 'PASS', assertions = [], error = null) => ({
  id, title: id, role, verdict, assertions, error, variance: [], catches: 'Controlled outcome fixture.',
});

function compareWithoutSeamControl(subject) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-outcome-compare-'));
  try {
    const controlPath = join(dir, 'control.json');
    const subjectPath = join(dir, 'subject.json');
    const output = join(dir, 'compared.json');
    const server = row('fixture.server', 'server');
    writeFileSync(controlPath, JSON.stringify({ target: { name: 'python-control' },
      roleAudit: { selected: ['server'], unarmed: ['seam'] }, results: [server] }));
    writeFileSync(subjectPath, JSON.stringify({ target: { name: 'gateway-subject' },
      roleAudit: { selected: ['server', 'seam'], unarmed: [] }, results: [server, subject] }));
    const child = spawnSync(process.execPath, [battery, 'compare', '--control', controlPath,
      '--subject', subjectPath, '--out', output], { encoding: 'utf8', timeout: 15000 });
    assert.ifError(child.error);
    return { status: child.status, report: JSON.parse(readFileSync(output, 'utf8')),
      output: child.stdout + child.stderr };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

for (const verdict of ['ERROR', 'FAIL']) {
  test(`an unexplored control role cannot excuse a subject seam ${verdict}`, () => {
    const result = compareWithoutSeamControl(row('fixture.seam', 'seam', verdict, [], 'peer exited before reply'));
    assert.equal(result.status, 1, result.output);
    assert.equal(result.report.incomplete?.[0]?.testId, 'fixture.seam');
    assert.equal(result.report.explainedMissing[0]?.id, 'fixture.seam');
  });
}

test('a subject seam assertion fails without inventing a control outcome', () => {
  const result = compareWithoutSeamControl(row('fixture.seam', 'seam', 'FAIL', [
    { ...cite('PAT.SERVER-NO-REQUESTS'), clause: 'PAT.SERVER-NO-REQUESTS', ok: false,
      detail: 'Controlled forbidden upstream request reached the front door.' },
  ]));
  assert.equal(result.status, 1, result.output);
  assert.equal(result.report.failures[0]?.controlSatisfiedSameClause, null);
  assert.match(result.output, /NOT MEASURED/);
  assert.doesNotMatch(result.output, /the control fails it too/);
});

test('a valid subject seam observation still permits a legitimately absent control role', () => {
  const result = compareWithoutSeamControl(row('fixture.seam', 'seam'));
  assert.equal(result.status, 0, result.output);
  assert.equal(result.report.explainedMissing[0]?.id, 'fixture.seam');
  assert.equal(result.report.failures.length, 0);
  assert.equal(result.report.incomplete?.length || 0, 0);
});

function negativeControlWithPeerStartup(errorMode) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-outcome-negative-'));
  try {
    for (const subdir of ['scripts', 'bin', 'fakepeer']) mkdirSync(join(dir, subdir));
    copyFileSync(join(root, 'scripts/negative-control.sh'), join(dir, 'scripts/negative-control.sh'));
    // Use the actual battery and actual StdioPeer process path, selecting an existing request
    // scenario so a peer startup failure is an ERROR-only report, rather than a fabricated log.
    writeFileSync(join(dir, 'bin/mcp-battery.mjs'),
      `process.argv.push('--only', 'SRV.DISCOVER.IMPLEMENTED');\nawait import(${JSON.stringify(pathToFileURL(battery).href)});\n`);
    writeFileSync(join(dir, 'fakepeer/fake-server.mjs'), `
import { createInterface } from 'node:readline';
if (process.argv[2] === '--list-modes') {
  process.stdout.write('honest\\ninjection\\n');
} else {
  if (process.env.MCP_FAKE_MODE === process.env.MCP_OUTCOME_ERROR_MODE) {
    throw new Error('Controlled peer startup failure');
  }
  createInterface({ input: process.stdin }).on('line', (line) => {
    const message = JSON.parse(line);
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id,
      result: { resultType: 'complete', supportedVersions: ['2026-07-28'], capabilities: {} } }) + '\\n');
  });
}
`);
    const child = spawnSync('bash', [join(dir, 'scripts/negative-control.sh')], {
      env: { ...process.env, MCP_OUTCOME_ERROR_MODE: errorMode }, encoding: 'utf8', timeout: 30000,
    });
    assert.ifError(child.error);
    return { status: child.status, output: child.stdout + child.stderr };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

for (const mode of ['honest', 'injection']) {
  test(`a real peer startup ERROR cannot be accepted for ${mode} by negative control`, () => {
    const result = negativeControlWithPeerStartup(mode);
    assert.equal(result.status, 1, result.output);
    assert.match(result.output, /0 fail, 1 error/);
    assert.match(result.output, /did not complete without harness errors/);
    assert.doesNotMatch(result.output, /negative control behaved:/);
  });
}

test('negative control still accepts complete healthy honest and declared-unobservable exchanges', () => {
  const result = negativeControlWithPeerStartup('no-error-mode');
  assert.equal(result.status, 0, result.output);
  assert.match(result.output, /negative control behaved:/);
});
