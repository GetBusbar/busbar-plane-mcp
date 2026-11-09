// Judge sensitivity to explicitly injected transport faults. Scenario ERRORs stay ERRORs.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function judgeNegativePeer(mode, report, checkpoint, transcript, status) {
  if (!report.results?.every(row => ['PASS', 'FAIL', 'ERROR', 'SKIP'].includes(row.verdict))
    || ![0, 1].includes(status) || !Array.isArray(report.results) || !report.results.length
    || checkpoint.execution?.completed !== true
    || checkpoint.execution.selectedCases !== report.results.length
    || checkpoint.execution.recordedCases !== report.results.length
    || JSON.stringify(checkpoint.results) !== JSON.stringify(report.results)) {
    throw new Error('missing or incomplete negative-control verdict');
  }
  const errors = report.results.filter(row => row.verdict === 'ERROR');
  if (!errors.length) return 0;
  if (!['stall', 'truncate', 'half-answer'].includes(mode)) throw new Error('unrelated negative-control ERROR');
  for (const row of errors) {
    const o = row.peerObservation;
    const expectedKind = mode === 'half-answer' ? 'stdout-eof' : 'response-timeout';
    if (!o || o.kind !== expectedKind || !Number.isSafeInteger(o.peerPid)
      || o.requestId === undefined
      || o.stdoutEnded !== (mode === 'half-answer')) throw new Error(`unmatched peer ERROR: ${row.id}`);
    const entries = transcript.filter(entry => entry.peerPid === o.peerPid);
    if (!entries.length || entries.some(entry => entry.mode !== mode)) throw new Error('wrong injected peer identity');
    let injected = entries.find(entry => entry.direction === 'injected-fault'
      && entry.payload?.kind === mode && entry.payload.requestId === o.requestId && entry.payload.method === o.method);
    // An admitted partial answer corrupts or closes a later discovery barrier.
    // Prove both request identities and their order.
    if (!injected && mode !== 'stall' && o.method === 'server/discover') {
      injected = entries.find(entry => entry.direction === 'injected-fault' && entry.payload?.kind === mode
        && entries.some(admission => admission.direction === 'client->server'
          && admission.payload?.id === entry.payload.requestId && admission.payload.method === entry.payload.method)
        && entries.indexOf(entry) < entries.findIndex(admission => admission.direction === 'client->server'
          && admission.payload?.id === o.requestId && admission.payload.method === o.method));
    }
    const admitted = entries.find(entry => entry.direction === 'client->server'
      && entry.payload?.id === o.requestId && entry.payload.method === o.method);
    if (!injected || !admitted || !entries.some(entry => entry.direction === 'client->server-raw'
      && entry.payload === JSON.stringify(admitted.payload))) throw new Error('injected request admission not witnessed');
    const writes = entries.filter(entry => ['server->client', 'server->client-raw'].includes(entry.direction));
    const bytes = writes.map(entry => entry.direction === 'server->client-raw'
      ? entry.payload : `${typeof entry.payload === 'string' ? entry.payload : JSON.stringify(entry.payload)}\n`).join('');
    if (createHash('sha256').update(bytes).digest('hex') !== o.stdoutSha256) throw new Error('peer wire observation mismatch');
    const raw = writes.filter(entry => entry.direction === 'server->client-raw').map(entry => entry.payload);
    if (mode === 'stall' && raw.length !== 0) throw new Error('stall unexpectedly wrote partial bytes');
    const partial = mode === 'truncate' ? '{"jsonrpc":"2.0","id":"x","result":{"resultTy'
      : `{"jsonrpc":"2.0","id":${JSON.stringify(injected.payload.requestId)},"result":{"resultType":"comp`;
    if (mode !== 'stall' && !raw.includes(partial)) throw new Error('injected partial frame absent');
  }
  return errors.length;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, reportPath, checkpointPath, transcriptPath, status] = process.argv.slice(2);
    const transcript = readFileSync(transcriptPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
    const count = judgeNegativePeer(mode, JSON.parse(readFileSync(reportPath)),
      JSON.parse(readFileSync(checkpointPath)), transcript, Number(status));
    console.log(count);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
