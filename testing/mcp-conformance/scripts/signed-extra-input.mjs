#!/usr/bin/env node
// Additive native observation; never rewrites the official scenario or verdict.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

const [url, bearerFile, output] = process.argv.slice(2);
if (!url || !bearerFile || !output) throw new Error('usage: signed-extra-input.mjs <actual-mcp-url> <bearer-file> <receipt.json>');
const token = readFileSync(bearerFile, 'utf8').trim();
if (!token) throw new Error('empty bearer file');
const hash = (value) => createHash('sha256').update(value).digest('hex');
const transcript = [];
const inputResponses = {
  user_name: { action: 'accept', content: { name: 'Alice' } },
  unknown_extra_key: { action: 'accept', content: { foo: 'bar' } },
  another_unexpected: { action: 'accept', content: { baz: 123 } },
};
async function call(id, suppliedInputs, requestState) {
  const message = { jsonrpc: '2.0', id, method: 'tools/call', params: {
    name: 'test_input_required_result_elicitation', arguments: {}, inputResponses: suppliedInputs,
    ...(requestState === undefined ? {} : { requestState }),
    _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
      'io.modelcontextprotocol/clientCapabilities': { elicitation: { form: {} } },
      'io.modelcontextprotocol/clientInfo': { name: 'signed-extra-input-regression', version: '1.0.0' } },
  } };
  const response = await fetch(url, { method: 'POST', headers: {
    authorization: `Bearer ${token}`, 'content-type': 'application/json', accept: 'application/json, text/event-stream',
    'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/call', 'mcp-name': message.params.name,
  }, body: JSON.stringify(message), signal: AbortSignal.timeout(15000) });
  const body = await response.json();
  const recorded = structuredClone(body);
  if (typeof recorded.result?.requestState === 'string') {
    recorded.result.requestStateSha256 = hash(recorded.result.requestState);
    delete recorded.result.requestState;
  }
  transcript.push({ request: { id, method: message.method, params: { ...message.params,
    ...(requestState === undefined ? {} : { requestState: '[hash recorded separately]', requestStateSha256: hash(requestState) }) } },
  status: response.status, response: recorded });
  assert.equal(body.id, id, 'the actual product must correlate its response');
  return body;
}
let error;
try {
  const known = { user_name: inputResponses.user_name };
  const noStateKnown = await call('no-state-known-only', known);
  const noStateExtras = await call('no-state-plus-extras', inputResponses);
  for (const result of [noStateKnown, noStateExtras]) {
    assert.equal(result.result?.resultType, 'input_required', 'neither initial input variant may bypass the signed gate');
    assert.equal(typeof result.result.requestState, 'string');
    assert.ok(result.result.requestState.length > 0);
    assert.ok(result.result.inputRequests?.user_name);
  }
  assert.deepEqual(noStateKnown.result.inputRequests, noStateExtras.result.inputRequests,
    'unknown keys must not change the initial challenge');
  assert.notEqual(noStateKnown.result.requestState, noStateExtras.result.requestState,
    'the two trials require separately issued state');
  const baseline = await call('signed-known-only', known, noStateKnown.result.requestState);
  const withExtras = await call('signed-plus-extras', inputResponses, noStateExtras.result.requestState);
  for (const result of [baseline, withExtras]) {
    assert.equal(result.result?.resultType, 'complete');
    assert.notEqual(result.result.isError, true);
    assert.ok(result.result.content?.some((item) => item.type === 'text' && item.text.includes('input_required_result_elicitation completed')));
  }
  assert.deepEqual(baseline.result, withExtras.result,
    'a valid signed retry with unknown keys must complete equivalently to the known-only retry');
  for (const [id, suppliedInputs, requestState] of [
    ['spent-known-only-state', known, noStateKnown.result.requestState],
    ['spent-extra-state', inputResponses, noStateExtras.result.requestState],
  ]) {
    const replay = await call(id, suppliedInputs, requestState);
    assert.ok(replay.error, 'successful signed confirmation remains single-use');
  }
} catch (caught) { error = String(caught.stack || caught); process.exitCode = 1; }
writeFileSync(output, JSON.stringify({ verdict: error ? 'FAIL' : 'PASS',
  scope: 'paired actual product observations: no-state known-only/extra variants challenge equivalently; separately issued signed retries complete equivalently; both spent states reject',
  retainedControls: 'No changes to signed-state, tamper, principal, TTL or request-binding controls; original official scenarios remain unmodified. This probe does not independently retest all those controls.',
  originalOfficialWarningDisposition: 'unchanged; this additive observation does not make the original official run green',
  transcript, ...(error ? { error } : {}) }, null, 2) + '\n');
if (error) console.error(error);
