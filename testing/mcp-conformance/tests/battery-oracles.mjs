import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
const base = process.env.BATTERY_SOURCE ? pathToFileURL(`${process.env.BATTERY_SOURCE}/`) : new URL('../', import.meta.url);
const { sampleArgsFromSchema } = await import(new URL('src/suites/server-conformance.mjs', base));
await import(new URL('src/suites/server-adversarial.mjs', base));
const { allTests, runOne } = await import(new URL('src/core/runner.mjs', base));
async function run(id, respond) {
  return runOne(allTests().find(t => t.id === id), { spawnServer() { return {
    send() {}, async stop() {}, async waitForId(id) { return respond(id); },
  }; } });
}
test('tool-list shape rejects missing and null tools', async () => {
  for (const tools of [undefined, null, []]) {
    const result = await run('SRV.TOOLS.LIST-SHAPE', id => ({ result: id === 1
      ? { capabilities: { tools: {} } } : { resultType: 'complete', tools } }));
    assert.equal(result.verdict, Array.isArray(tools) ? 'PASS' : 'FAIL');
  }
});
test('cache TTL must be finite numeric and nonnegative', async () => {
  for (const ttlMs of [null, 'forever', -1, Infinity, 0, 5]) {
    const result = await run('SRV.CACHE.HINTS-ON-CACHEABLE-RESULTS', () => ({ result: {
      resultType: 'complete', ttlMs, cacheScope: 'public',
    } }));
    assert.equal(result.verdict, Number.isFinite(ttlMs) && ttlMs >= 0 ? 'PASS' : 'FAIL');
  }
});
test('schema samples never claim unsupported constrained arguments are legal', () => {
  for (const property of [
    { type: 'string', maxLength: 1 }, { type: 'string', pattern: '^z+$' },
    { type: 'number', maximum: 0 }, { type: 'number', exclusiveMinimum: 1 },
    { type: 'number', multipleOf: 2 }, { const: 1, maximum: 0 },
  ]) assert.equal(sampleArgsFromSchema({ type: 'object', properties: { x: property }, required: ['x'] }), null);
  assert.deepEqual(sampleArgsFromSchema({ type: 'object', properties: { x: { type: 'boolean' } }, required: ['x'] }), { x: true });
});
test('forged-cursor error code is advisory', async () => {
  const scenario = allTests().find(t => t.run.toString().includes('PAGE.INVALID-CURSOR-32602'));
  const result = await run(scenario.id, id => String(id).startsWith('cur-')
    ? { error: { code: -32000, message: 'invalid cursor' } }
    : { id, result: { resultType: 'complete', supportedVersions: ['2026-07-28'] } });
  assert.equal(result.verdict, 'PASS');
  assert.equal(result.recommendations.filter(r => r.key === 'PAGE.INVALID-CURSOR-32602' && !r.ok).length, 4);
});
