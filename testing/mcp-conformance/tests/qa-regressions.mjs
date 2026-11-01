import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { allTests, runOne } from '../src/core/runner.mjs';
import { validateAgainstSchema } from '../src/suites/server-conformance.mjs';
import '../src/suites/server-concurrency.mjs';
import '../src/suites/client-role.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const scenario = (id) => {
  const found = allTests().find((t) => t.id === id);
  assert.ok(found, `existing scenario ${id} must be registered`);
  return found;
};
const client = (payload) => ({ direction: 'client->server', payload });
const server = (payload) => ({ direction: 'server->client', payload });
const req = (id) => ({ jsonrpc: '2.0', id, method: 'tools/list' });
const reply = (id) => ({ jsonrpc: '2.0', id, result: {} });

async function idReplies(messages, rejectedId = undefined) {
  return runOne(scenario('CONC.ID-TYPES'), {
    spawnServer() {
      return {
        messages, send() {}, async stop() {},
        async waitForId(id) {
          if (id === rejectedId) throw new Error('fixture wait failed before aggregate replies');
          const found = messages.find((m) => m.id === id && ('result' in m || 'error' in m));
          if (!found) throw new Error(`fixture timeout for ${JSON.stringify(id)}`);
          return found;
        },
      };
    },
  });
}
const goodReplies = () => [1, '1', 0, -7, ''].map((id) => ({
  jsonrpc: '2.0', id,
  result: typeof id === 'string' && id === '1' ? { tools: [] } : { supportedVersions: ['2026-07-28'] },
}));

test('CONC.ID-TYPES rejects silence and a missing legal id, accepts correlated replies', async () => {
  assert.equal((await idReplies([])).verdict, 'FAIL');
  assert.equal((await idReplies(goodReplies().filter((m) => m.id !== ''))).verdict, 'FAIL');
  assert.equal((await idReplies(goodReplies())).verdict, 'PASS');
  assert.equal((await idReplies(goodReplies(), 1)).verdict, 'FAIL');
});
test('CONC.ID-TYPES rejects swapped, duplicated and invented replies', async () => {
  const swapped = goodReplies();
  [swapped[0].result, swapped[1].result] = [swapped[1].result, swapped[0].result];
  assert.equal((await idReplies(swapped)).verdict, 'FAIL');
  const good = goodReplies();
  assert.equal((await idReplies([...good, good[0]])).verdict, 'FAIL');
  assert.equal((await idReplies([...good, { ...good[0], id: 'never-sent' }])).verdict, 'FAIL');
});

async function clientIds(entries) {
  return runOne(scenario('CLI.IDS.UNIQUE-WHILE-IN-FLIGHT'), {
    hasClientRole: true,
    spawnClient(_launch, env) {
      writeFileSync(env.MCP_FAKE_TRANSCRIPT, entries.map((e) => JSON.stringify(e)).join('\n'));
      return { exitCode: 0, stderr: '', stdoutBytes: Buffer.alloc(0), async waitForExit() {}, async stop() {} };
    },
  });
}
test('pending ids fail on overlap, including a response for the wrong typed id', async () => {
  for (const entries of [
    [client(req(1)), client(req(1))],
    [client(req(1)), server(reply('1')), client(req(1))],
    [client(req(1)), server(req(1)), client(req(1))],
  ]) {
    const result = await clientIds(entries);
    assert.equal(result.verdict, 'FAIL');
    assert.ok(result.assertions.some((a) => a.clause === 'BASE.REQ.ID-UNIQUE' && !a.ok));
  }
});
test('pending ids allow typed ids, out-of-order completion and reuse after result or error', async () => {
  for (const response of [reply(1), { jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'fixture' } }]) {
    assert.equal((await clientIds([
      client(req(1)), client(req('1')), server(reply('1')), server(response), client(req(1)),
    ])).verdict, 'PASS');
  }
});

for (const [name, value, schema] of [
  ['false schema', 1, false], ['const', { x: 2 }, { const: { x: 1 } }],
  ['minimum', -1, { type: 'number', minimum: 0 }], ['maximum', 2, { maximum: 1 }],
  ['maxLength', 'long', { type: 'string', maxLength: 3 }],
  ['minLength', '', { minLength: 1 }],
  ['additionalProperties', { ok: 1, extra: 2 }, { properties: { ok: {} }, additionalProperties: false }],
  ['nested false', { x: 1 }, { properties: { x: false } }],
  ['array length', [], { minItems: 1 }], ['uniqueItems', [{ a: 1 }, { a: 1 }], { uniqueItems: true }],
]) {
  test(`output schema rejects violation of ${name}`, () => assert.equal(validateAgainstSchema(value, schema).valid, false));
}
test('schema positive controls preserve unicode lengths, object equality and true schema', () => {
  for (const [value, schema] of [
    ['😀', { minLength: 1, maxLength: 1 }], [{ a: 1, b: 2 }, { const: { b: 2, a: 1 } }],
    [{ a: 1 }, { properties: { a: { minimum: 0 } }, additionalProperties: false }], [1, true],
  ]) assert.equal(validateAgainstSchema(value, schema).valid, true);
});
test('JSON numeric equality equates signed zero recursively for const, enum and uniqueItems', () => {
  const negativeZero = JSON.parse('-0');
  for (const [value, schema] of [
    [negativeZero, { const: 0 }], [negativeZero, { enum: [0] }],
    [{ nested: [negativeZero] }, { const: { nested: [0] } }],
    [[{ nested: negativeZero }], { enum: [[{ nested: 0 }]] }],
  ]) assert.equal(validateAgainstSchema(value, schema).valid, true);
  for (const value of [[0, negativeZero], [{ nested: [0] }, { nested: [negativeZero] }]]) {
    assert.equal(validateAgainstSchema(value, { uniqueItems: true }).valid, false);
  }
});
test('unimplemented semantics cannot silently count as a validated schema', () => {
  for (const schema of [{ unevaluatedProperties: false }, { properties: { unused: { $ref: '#/$defs/x' } } }]) {
    const result = validateAgainstSchema({}, schema);
    assert.equal(result.valid, false);
    assert.equal(result.supported, false);
  }
});
test('the actual output-schema scenario exercises boolean false and reports unsupported schemas', async () => {
  for (const [schema, expected] of [[false, 'FAIL'], [{ unevaluatedProperties: false }, 'ERROR'], [true, 'PASS']]) {
    const result = await runOne(scenario('SRV.TOOLS.OUTPUTSCHEMA-CONFORMS'), {
      spawnServer() {
        return { send() {}, async stop() {}, async waitForId(id) {
          return id === 1
            ? { id, result: { tools: [{ name: 'fixture', inputSchema: { type: 'object' }, outputSchema: schema }] } }
            : { id, result: { structuredContent: { x: 1 } } };
        } };
      },
    });
    assert.equal(result.verdict, expected);
  }
});

function baselineRun({ entries, raw, clause, id = 'CLI.NO-RESPONSES-SENT', clauses }) {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-qa-baseline-'));
  try {
    const launcher = join(dir, 'client.mjs');
    writeFileSync(launcher, `import { writeFileSync } from 'node:fs';\nwriteFileSync(process.env.MCP_FAKE_TRANSCRIPT, ${JSON.stringify(raw ?? entries.map((e) => JSON.stringify(e)).join('\n'))});\n`);
    const baseline = join(dir, 'baseline.json');
    writeFileSync(baseline, JSON.stringify({ control: 'fixture', expectedFailures: [{ testId: id, clause, ...(clauses ? { clauses } : {}), judgement: 'Fixture deviation.' }] }));
    const out = join(dir, 'report.json');
    const child = spawnSync(process.execPath, [join(root, 'bin/mcp-battery.mjs'), 'run', '--name', 'fixture', '--role', 'client', '--tier', 'all', '--only', id,
      '--client-cmd', `${JSON.stringify(process.execPath)} ${JSON.stringify(launcher)}`, '--expected-failures', baseline, '--out', out, '--quiet'], { encoding: 'utf8', timeout: 15000 });
    assert.ifError(child.error);
    return { status: child.status, report: JSON.parse(readFileSync(out, 'utf8')), output: child.stdout + child.stderr };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}
const responseEntries = [server(reply(1)), client(reply(1))];
test('a baseline accepts precisely its documented failed clause', () => {
  const result = baselineRun({ entries: responseEntries, clause: 'STDIO.CLIENT-NO-RESPONSES' });
  assert.equal(result.report.results[0].verdict, 'FAIL');
  assert.equal(result.status, 0, result.output);
});
test('a matching test id cannot excuse a different clause or transcript parse error', () => {
  for (const fixture of [
    { entries: responseEntries, clause: 'BASE.REQ.ID-UNIQUE' },
    { raw: '{not-json}\n', clause: 'STDIO.CLIENT-NO-RESPONSES' },
  ]) {
    const result = baselineRun(fixture);
    assert.equal(result.status, 1, result.output);
  }
});
test('a baseline cannot excuse extra clauses or missing stimulus; an explicit complete clause set can', () => {
  const id = 'CLI.HOSTILE.SERVER-INITIATED-REQUEST-IS-NOT-ANSWERED';
  const entries = [server({ id: 'server-initiated-1', method: 'sampling/createMessage' }), client(reply('server-initiated-1'))];
  for (const fixture of [{ entries, id }, { entries: [client(reply('server-initiated-1'))], id }]) {
    const result = baselineRun({ ...fixture, clause: 'STDIO.CLIENT-NO-RESPONSES' });
    assert.equal(result.status, 1, result.output);
  }
  const matched = baselineRun({ entries, id, clause: 'STDIO.CLIENT-NO-RESPONSES', clauses: ['STDIO.CLIENT-NO-RESPONSES', 'PAT.SERVER-NO-REQUESTS'] });
  assert.equal(matched.status, 0, matched.output);
});
