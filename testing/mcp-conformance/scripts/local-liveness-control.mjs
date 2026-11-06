#!/usr/bin/env node
// This is a LOCAL fixture responsiveness/resource contract, not MCP conformance.
// It never edits, replaces, or rescoring any original battery scenario.
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { spawnSync } from 'node:child_process';
import { StdioPeer } from '../src/core/stdio-peer.mjs';
import { request } from '../src/core/jsonrpc.mjs';
import { REVISION } from '../src/core/spec.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = join(root, 'fakepeer/fake-server.mjs');
export const CONTRACT = Object.freeze({
  id: 'LOCAL.FIXTURE.RESPONSIVENESS.v1',
  responseDeadlineMs: 1000,
  discoveryFailsafeMs: 5000,
  maximumReplyBytes: 8 * 1024 * 1024,
  maximumCapturedBytes: 16 * 1024 * 1024,
  maximumJsonDepth: 128,
  normative: false,
  scope: 'One admitted tools/list request after a healthy server/discover barrier, observed for 1000ms.',
  guarantee: 'Exactly one correlated JSON-RPC reply within the local deadline; no malformed, partial, or unsolicited reply; bounded reply size and nesting.',
  uncertainty: 'MCP defines no universal response deadline, byte limit, or nesting limit. A local FAIL does not establish an MCP normative violation. Original battery ERROR/incomplete outcomes remain unchanged.',
});
const NEGATIVE_CONTROLS = new Set(['stall', 'truncate', 'half-answer', 'wrong-id',
  'dup-response', 'giant', 'deep', 'malformed']);
export const DEFAULT_MODES = ['honest', ...NEGATIVE_CONTROLS];
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

function exceedsDepth(value, limit) {
  const pending = [[value, 0]];
  while (pending.length) {
    const [entry, depth] = pending.pop();
    if (!entry || typeof entry !== 'object') continue;
    if (depth > limit) return true;
    for (const child of Object.values(entry)) pending.push([child, depth + 1]);
  }
  return false;
}
function killPeer(peer) {
  try {
    if (process.platform === 'win32') peer.proc.kill('SIGKILL');
    else process.kill(-peer.proc.pid, 'SIGKILL');
  } catch { /* already exited */ }
}

export async function probeMode(mode, output, options = {}) {
  if (!/^[a-z][a-z0-9-]*$/.test(mode)) throw new Error('invalid fixture mode');
  mkdirSync(output, { recursive: true });
  const directory = join(output, mode);
  mkdirSync(directory); // Immutable evidence: refuse to overwrite a prior mode.
  const transcriptPath = join(directory, 'fixture.jsonl');
  const peer = new StdioPeer(process.execPath, [options.fixture || fixture], {
    env: { MCP_FAKE_MODE: mode, MCP_FAKE_TRANSCRIPT: transcriptPath },
  }).start();
  const receipt = {
    mode, contract: CONTRACT, localVerdict: 'ERROR', assertions: [], error: null,
    expectedLocalVerdict: mode === 'honest' ? 'PASS' : NEGATIVE_CONTROLS.has(mode) ? 'FAIL' : null,
    originalBattery: { executed: false, modified: false, result: 'NOT MEASURED' },
    discovery: null, admission: null, observations: null, artifacts: {},
  };
  let captureStopped = false;
  let observed = null;
  let requested = null;
  let beforeBytes = 0;
  let beforeMessages = 0;
  let probeStarted = null;
  let arrivals = [];
  let timedMessages = [];
  let messageCursor = 0;
  // Even a broken fixture cannot grow the retained wire indefinitely. Crossing
  // the local cap is observed before killing the owned child; it is not a timeout.
  const captureGuard = (chunk) => {
    if (probeStarted !== null) {
      const atMs = performance.now() - probeStarted;
      arrivals.push({ atMs, bytes: chunk.length,
        parsedMessages: peer.messages.length - beforeMessages });
      for (const message of peer.messages.slice(messageCursor)) timedMessages.push({ atMs, message });
      messageCursor = peer.messages.length;
    }
    if (peer._stdoutLength > CONTRACT.maximumCapturedBytes) {
      captureStopped = true;
      peer.proc.stdout.destroy();
      killPeer(peer);
    }
  };
  peer.proc.stdout.on('data', captureGuard);
  try {
    peer.send(request('local-discover', 'server/discover'));
    const discovery = await peer.waitForId('local-discover', CONTRACT.discoveryFailsafeMs);
    if (discovery.jsonrpc !== '2.0' || discovery.result?.resultType !== 'complete'
      || !discovery.result?.supportedVersions?.includes(REVISION)
      || !discovery.result?.capabilities?.tools || peer.badLines.length || captureStopped) {
      throw new Error('healthy discovery barrier not established');
    }
    receipt.discovery = discovery;
    beforeBytes = peer._stdoutLength;
    beforeMessages = peer.messages.length;
    messageCursor = beforeMessages;
    requested = request('local-list', 'tools/list');
    probeStarted = performance.now();
    peer.send(requested);
    // The collection window is an explicit local contract, not a hidden failsafe
    // converted to a normative assertion. Always collect the full window so a
    // duplicate following the first response cannot escape observation.
    // Timers may wake fractionally early; the monotonic clock, not timer
    // rounding, defines the contractual endpoint.
    while (performance.now() - probeStarted < CONTRACT.responseDeadlineMs) {
      const remaining = CONTRACT.responseDeadlineMs - (performance.now() - probeStarted);
      await new Promise(resolve => setTimeout(resolve, Math.max(1, Math.ceil(remaining))));
    }
    const timelyBytes = arrivals.filter(a => a.atMs <= CONTRACT.responseDeadlineMs)
      .reduce((count, arrival) => count + arrival.bytes, 0);
    observed = {
      elapsedMs: performance.now() - probeStarted,
      bytes: peer.stdoutBytes.subarray(beforeBytes, beforeBytes + timelyBytes),
      messages: timedMessages.filter(m => m.atMs <= CONTRACT.responseDeadlineMs).map(m => m.message),
      lateMessages: timedMessages.filter(m => m.atMs > CONTRACT.responseDeadlineMs).length,
      stdoutEnded: peer.stdoutEnded,
      exited: peer.exited,
      exitCode: peer.exitCode,
      exitSignal: peer.exitSignal,
      arrivals: [...arrivals],
    };
    // Admission is proved by the independent fake-peer transcript, never by
    // successful stdin.write or the driver's expectation about its chosen mode.
    const entries = readFileSync(transcriptPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    const admissions = entries.filter(e => e.direction === 'client->server' && same(e.payload, requested));
    const rawAdmissions = entries.filter(e => e.direction === 'client->server-raw'
      && e.payload === JSON.stringify(requested));
    if (admissions.length !== 1 || rawAdmissions.length !== 1) {
      throw new Error('exact request admission was not independently observed');
    }
    receipt.admission = { request: requested, parsedRecords: admissions.length,
      rawRecords: rawAdmissions.length, source: 'fixture.jsonl' };
    if (peer.spawnError || peer.writeError || peer.stdoutError) {
      throw peer.spawnError || peer.writeError || peer.stdoutError;
    }
    if (observed.exited && !captureStopped && observed.exitCode !== 0) {
      throw new Error(`fixture process failed: code=${observed.exitCode} signal=${observed.exitSignal}`);
    }
    const wire = observed.bytes.toString('utf8');
    const lines = wire.split('\n');
    const tail = lines.pop();
    const malformed = lines.filter(line => {
      if (!line.trim()) return false;
      try { JSON.parse(line); return false; } catch { return true; }
    });
    const replies = observed.messages.filter(m => m && typeof m === 'object'
      && ('result' in m || 'error' in m));
    const correlated = replies.filter(m => m.id === requested.id);
    const unexpected = replies.filter(m => m.id !== requested.id);
    const check = (id, ok, evidence) => receipt.assertions.push({ id, ok: Boolean(ok), normative: false, evidence });
    check('LOCAL.RESPONSE-BY-DEADLINE', correlated.length >= 1,
      { admittedRequestId: requested.id, deadlineMs: CONTRACT.responseDeadlineMs,
        collectionElapsedMs: observed.elapsedMs, correlatedReplies: correlated.length });
    check('LOCAL.EXACTLY-ONE-REPLY', correlated.length === 1, { correlatedReplies: correlated.length });
    check('LOCAL.NO-UNREQUESTED-REPLY-ID', unexpected.length === 0,
      { unexpectedIds: unexpected.map(m => m.id) });
    check('LOCAL.COMPLETE-JSON-LINES', malformed.length === 0 && tail.length === 0,
      { malformedLines: malformed.length, pendingUtf8Bytes: Buffer.byteLength(tail),
        stdoutEnded: observed.stdoutEnded, wireSha256: digest(observed.bytes) });
    check('LOCAL.REPLY-BYTE-BOUND', !captureStopped && observed.bytes.length <= CONTRACT.maximumReplyBytes,
      { observedBytes: observed.bytes.length, maximumReplyBytes: CONTRACT.maximumReplyBytes, captureStopped });
    check('LOCAL.JSON-DEPTH-BOUND', !observed.messages.some(m => exceedsDepth(m, CONTRACT.maximumJsonDepth)),
      { maximumJsonDepth: CONTRACT.maximumJsonDepth });
    check('LOCAL.JSONRPC-REPLY-ENVELOPE', replies.every(m => m.jsonrpc === '2.0'
      && Object.hasOwn(m, 'result') !== Object.hasOwn(m, 'error')), { replyCount: replies.length });
    receipt.localVerdict = receipt.assertions.some(a => !a.ok) ? 'FAIL' : 'PASS';
  } catch (error) {
    receipt.error = error.stack || String(error);
  } finally {
    try { await peer.stop(); }
    catch (error) { receipt.localVerdict = 'ERROR'; receipt.error = error.stack || String(error); }
    if (peer.exited && !captureStopped && peer.exitCode !== 0) {
      receipt.localVerdict = 'ERROR';
      receipt.error ||= `fixture process failed during observation/cleanup: code=${peer.exitCode} signal=${peer.exitSignal}`;
    }
    peer.proc.stdout.off('data', captureGuard);
    const raw = peer.stdoutBytes;
    for (const [name, bytes] of [['stdout.bin', raw], ['stderr.txt', Buffer.from(peer.stderr)]]) {
      writeFileSync(join(directory, name), bytes);
      receipt.artifacts[name] = { bytes: bytes.length, sha256: digest(bytes) };
    }
    if (existsSync(transcriptPath)) {
      const bytes = readFileSync(transcriptPath);
      receipt.artifacts['fixture.jsonl'] = { bytes: bytes.length, sha256: digest(bytes) };
    }
    receipt.observations = observed ? {
      collectionElapsedMs: observed.elapsedMs, stdoutByteStart: beforeBytes,
      stdoutByteEnd: beforeBytes + observed.bytes.length, stdoutEnded: observed.stdoutEnded,
      processExitedAtDeadline: observed.exited, captureStopped, arrivals: observed.arrivals,
      lateMessagesExcluded: observed.lateMessages,
      observedRequestReplyIds: observed.messages.filter(m => m && Object.hasOwn(m, 'id')).map(m => m.id),
    } : { captureStopped };
    receipt.expectationMatched = receipt.expectedLocalVerdict === null ? null
      : receipt.localVerdict === receipt.expectedLocalVerdict;
    writeFileSync(join(directory, 'receipt.json'), JSON.stringify(receipt, null, 2) + '\n');
  }
  return receipt;
}

async function main() {
  const args = process.argv.slice(2);
  const outAt = args.indexOf('--out');
  if (outAt < 0 || !args[outAt + 1]) throw new Error('usage: local-liveness-control.mjs --out NEW_DIRECTORY [--modes comma,list | --all-modes]');
  const output = resolve(args[outAt + 1]);
  if (existsSync(output)) throw new Error('output directory already exists; evidence cannot be overwritten');
  let modes = DEFAULT_MODES;
  const modeAt = args.indexOf('--modes');
  if (modeAt >= 0) modes = args[modeAt + 1].split(',');
  if (args.includes('--all-modes')) {
    const listed = spawnSync(process.execPath, [fixture, '--list-modes'], { encoding: 'utf8', timeout: 5000 });
    if (listed.error || listed.status !== 0) throw new Error('cannot enumerate fixture modes');
    modes = listed.stdout.trim().split('\n');
  }
  if (!modes.includes('honest')) throw new Error('honest positive control is required');
  const results = [];
  for (const mode of modes) {
    const result = await probeMode(mode, output);
    results.push(result);
    console.log(`${mode}: LOCAL ${result.localVerdict}; expected=${result.expectedLocalVerdict || 'not a designated local sensitivity control'}`);
  }
  const errors = results.filter(r => r.localVerdict === 'ERROR').length;
  const mismatches = results.filter(r => r.expectationMatched === false).length;
  const omittedControls = DEFAULT_MODES.filter(mode => !modes.includes(mode));
  const summary = { contract: CONTRACT, designatedControls: DEFAULT_MODES, selectedModes: modes,
    omittedDesignatedControls: omittedControls,
    controlStatus: errors ? 'ERROR' : mismatches ? 'FAIL' : omittedControls.length ? 'INCOMPLETE' : 'PASS',
    originalBattery: { executed: false, modified: false, result: 'NOT MEASURED' },
    results: results.map(r => ({ mode: r.mode, localVerdict: r.localVerdict,
      expectedLocalVerdict: r.expectedLocalVerdict, expectationMatched: r.expectationMatched,
      receipt: `${r.mode}/receipt.json` })) };
  writeFileSync(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  process.exitCode = errors ? 2 : mismatches || omittedControls.length ? 1 : 0;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const [signal, status] of [['SIGTERM', 143], ['SIGINT', 130]]) {
    process.once(signal, () => { StdioPeer.terminateOwnedPeers(); process.exit(status); });
  }
  main().catch(error => { console.error(error.stack || error); process.exitCode = 2; });
}
