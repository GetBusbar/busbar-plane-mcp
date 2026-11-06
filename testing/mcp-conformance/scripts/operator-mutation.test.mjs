import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { operatorMutation, MUTATIONS } from '../mcp-subject/operator-mutation.mjs';

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-operator-mutation-'));
  const config = join(dir, 'config.yaml');
  const original = [...MUTATIONS.values()].map(({ before }) => `description: "${before}"`).join('\n') + '\n';
  writeFileSync(config, original);
  return { dir, config, original };
}

test('fixture mutations change only the intended published list and perform real authenticated reloads', async () => {
  const state = fixture();
  const observed = [];
  const admin = createServer((req, res) => {
    observed.push({ url: req.url, method: req.method, auth: req.headers.authorization, config: readFileSync(state.config, 'utf8') });
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ reloaded: true, config_version: observed.length + 1 }));
  });
  admin.listen(0, '127.0.0.1');
  await once(admin, 'listening');
  try {
    const mutate = operatorMutation({ config: state.config, adminPort: admin.address().port,
      token: 'private-admin-fixture', receipt: join(state.dir, 'receipt.jsonl') });
    assert.equal(await mutate('unknown_tool'), false);
    assert.equal(observed.length, 0);
    await mutate('test_trigger_tool_change');
    assert.ok(observed[0].config.includes('Returns a single text content block. Operator revision 1.'));
    assert.ok(observed[0].config.includes('description: "A simple prompt for testing."'));
    await mutate('test_trigger_prompt_change');
    await mutate('test_trigger_tool_change');
    assert.equal(observed.length, 3);
    assert.ok(observed.every((row) => row.url === '/api/v1/admin/config/reload' && row.method === 'POST' && row.auth === 'Bearer private-admin-fixture'));
    assert.ok(readFileSync(state.config, 'utf8').includes('Operator revision 3.'));
    assert.equal(readFileSync(join(state.dir, 'receipt.jsonl'), 'utf8').includes('private-admin-fixture'), false);
  } finally {
    admin.closeAllConnections();
    await new Promise((done) => admin.close(done));
    rmSync(state.dir, { recursive: true, force: true });
  }
});

test('failed reload restores the exact preimage and cannot become a mutation receipt', async () => {
  const state = fixture();
  try {
    const mutate = operatorMutation({ config: state.config, reload: async () => { throw new Error('reload refused'); } });
    await assert.rejects(mutate('test_trigger_tool_change'), /reload refused/);
    assert.equal(readFileSync(state.config, 'utf8'), state.original);
  } finally { rmSync(state.dir, { recursive: true, force: true }); }
});

test('each mutation selects exactly one actual boot configuration description', () => {
  const boot = readFileSync(new URL('../mcp-subject/boot.sh', import.meta.url), 'utf8');
  for (const [name, { before }] of MUTATIONS) {
    assert.equal(boot.split(`description: "${before}"`).length, 2);
    assert.ok(boot.includes(`${name.slice('test_'.length)}:`));
  }
});
