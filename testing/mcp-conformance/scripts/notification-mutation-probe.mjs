#!/usr/bin/env node
// Additive raw observation of real product subscriptions and trusted mutations.
// Missing notifications remain failures; no frames or verdicts are synthesized.
import { readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const [url, bearerFile, output] = process.argv.slice(2);
if (!url || !bearerFile || !output) throw new Error('usage: notification-mutation-probe.mjs <actual-url> <bearer-file> <receipt>');
const token = readFileSync(bearerFile, 'utf8').trim();
const meta = { 'io.modelcontextprotocol/protocolVersion': '2026-07-28',
  'io.modelcontextprotocol/clientCapabilities': {},
  'io.modelcontextprotocol/clientInfo': { name: 'native-notification-observer', version: '1.0.0' } };
let seq = 0;
async function post(method, params, signal) {
  const id = `notification-observer-${++seq}`;
  const body = { jsonrpc: '2.0', id, method, params: { ...params, _meta: meta } };
  const headers = { authorization: `Bearer ${token}`, 'content-type': 'application/json',
    accept: 'application/json, text/event-stream', 'mcp-method': method, 'mcp-protocol-version': '2026-07-28' };
  if (params?.name) headers['mcp-name'] = params.name;
  const response = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body), signal });
  return { response, id };
}
async function rpc(method, params) {
  const { response, id } = await post(method, params, AbortSignal.timeout(15000));
  const text = await response.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { non_json: text }; }
  return { id, status: response.status, body };
}
const trials = [];
for (const [kind, filter, tool, target] of [
  ['tools', 'toolsListChanged', 'test_trigger_tool_change', 'test_simple_text'],
  ['prompts', 'promptsListChanged', 'test_trigger_prompt_change', 'test_simple_prompt'],
]) {
  const trial = { kind, started_at: new Date().toISOString(), frames: [], raw_chunks: [], stream_ended_before_abort: false };
  trials.push(trial);
  const controller = new AbortController();
  const started = Date.now();
  let reader, pump;
  let ackResolve, changedResolve;
  const ack = new Promise((resolve) => { ackResolve = resolve; });
  const changed = new Promise((resolve) => { changedResolve = resolve; });
  const wait = (promise, ms) => new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), ms);
    promise.then((value) => { clearTimeout(timer); resolve(value); });
  });
  try {
    const before = await rpc(`${kind}/list`, {});
    trial.before = before;
    assert.equal(before.status, 200);
    const initial = before.body.result?.[kind]?.find((entry) => entry.name === target);
    assert.ok(initial, 'target item must exist before mutation');
    const opened = await post('subscriptions/listen', { notifications: { [filter]: true } }, controller.signal);
    trial.subscription_id = opened.id;
    trial.subscription_http_status = opened.response.status;
    assert.equal(opened.response.status, 200);
    reader = opened.response.body.getReader();
    pump = (async () => {
      let pending = '';
      const decoder = new TextDecoder();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) { trial.stream_ended_before_abort = !controller.signal.aborted; trial.stream_end_ms = Date.now() - started; break; }
          const text = decoder.decode(value, { stream: true });
          trial.raw_chunks.push({ elapsed_ms: Date.now() - started, text });
          pending += text;
          const lines = pending.split(/\r?\n/); pending = lines.pop();
          for (const line of lines) {
            if (!line.startsWith('data:')) continue;
            const frame = JSON.parse(line.slice(5).trim());
            trial.frames.push({ elapsed_ms: Date.now() - started, message: frame });
            if (frame.method === 'notifications/subscriptions/acknowledged') ackResolve(true);
            if (frame.method === `notifications/${kind}/list_changed`) changedResolve(true);
          }
        }
      } catch (error) { if (!controller.signal.aborted) trial.stream_error = String(error); }
    })();
    assert.equal(await wait(ack, 2000), true, 'real subscription must acknowledge before mutation');
    trial.mutation_started_ms = Date.now() - started;
    trial.mutation = await rpc('tools/call', { name: tool, arguments: {} });
    assert.equal(trial.mutation.status, 200, 'operator/routed mutation must succeed');
    assert.ok(trial.mutation.body.result && !trial.mutation.body.result.isError);
    trial.after = await rpc(`${kind}/list`, {});
    const actual = trial.after.body.result?.[kind]?.find((entry) => entry.name === target);
    assert.ok(actual, 'target item must remain present after mutation');
    assert.notEqual(actual.description, initial.description, 'actual product catalogue must change');
    trial.catalogue_changed = true;
    assert.equal(await wait(changed, 2500), true, 'actual product must deliver matching list_changed');
    trial.verdict = 'PASS';
  } catch (error) { trial.verdict = 'FAIL'; trial.error = String(error.stack || error); }
  finally { controller.abort(); if (pump) await pump; reader?.releaseLock(); }
}
const verdict = trials.every((trial) => trial.verdict === 'PASS') ? 'PASS' : 'FAIL';
writeFileSync(output, JSON.stringify({ verdict, scope: 'additive raw native subscription observation; original official checks unchanged', trials }, null, 2) + '\n');
if (verdict !== 'PASS') process.exitCode = 1;
