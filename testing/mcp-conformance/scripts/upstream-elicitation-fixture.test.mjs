import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

const fixture = fileURLToPath(new URL('../mcp-subject/diagnostic-upstream.mjs', import.meta.url));
test('ordinary upstream MRTR accepts known and extra answers equivalently and reasks invalid answers', async () => {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1'); await once(reservation, 'listening');
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  const env = { ...process.env }; delete env.MCP_FIXTURE_TLS_CERT; delete env.MCP_FIXTURE_TLS_KEY;
  const child = spawn(process.execPath, [fixture, String(port)], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  const closed = once(child, 'close');
  try {
    await Promise.race([once(child.stdout, 'data'), new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('upstream did not start')), 3000); timer.unref();
    })]);
    let id = 0;
    async function call(responses, name = 'input_required_result_elicitation') {
      const body = { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: {},
        ...(responses === undefined ? {} : { inputResponses: responses }), _meta: {
          'io.modelcontextprotocol/protocolVersion': '2026-07-28',
          'io.modelcontextprotocol/clientCapabilities': { elicitation: { form: {} } },
        } } };
      const response = await fetch(`http://127.0.0.1:${port}/mcp/test`, { method: 'POST',
        headers: { 'content-type': 'application/json', 'mcp-method': 'tools/call', 'mcp-name': name,
          'mcp-protocol-version': '2026-07-28' }, body: JSON.stringify(body), signal: AbortSignal.timeout(3000) });
      return response.json();
    }
    const known = { user_name: { action: 'accept', content: { name: 'Alice' } } };
    const baseline = await call(known);
    const extras = await call({ ...known, unknown_extra_key: { action: 'accept', content: { foo: 'bar' } },
      another_unexpected: { action: 'accept', content: { baz: 123 } } });
    assert.equal(baseline.result.resultType, 'complete');
    assert.deepEqual(extras.result, baseline.result);
    const missing = await call();
    assert.equal(missing.result.resultType, 'input_required');
    assert.equal(missing.result.inputRequests.user_name.method, 'elicitation/create');
    for (const malformed of [null, 3, []]) {
      assert.equal((await call(malformed)).error.code, -32602);
    }
    for (const invalid of [{ user_name: 12345 }, { user_name: { action: 'accept', content: { name: 123 } } }]) {
      const reasked = await call(invalid);
      assert.equal(reasked.result.resultType, 'input_required', 'invalid known answers cannot complete the tool');
      assert.deepEqual(reasked.result.inputRequests, missing.result.inputRequests);
      assert.equal(reasked.result.inputRequests.user_name.params.requestedSchema.properties.name.type, 'string');
      assert.equal(reasked.result.isError, undefined);
    }
    const signed = await call(undefined, 'signed_input_required_result_elicitation');
    assert.equal(signed.result.resultType, 'complete', 'the separate operator gate is implemented by Busbar before this alias runs');
  } finally { child.kill('SIGTERM'); await closed; }
});
