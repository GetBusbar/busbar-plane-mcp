// SUBJECT ACTS AS MCP CLIENT. We are the server it connects to.
//
// OBSERVATION MODEL: we do not ask the client to report on itself. The fake
// server records everything the client puts on the wire into a JSONL
// transcript, and we assert on that. This means a subject needs to satisfy
// exactly ONE contract to be testable in its client role:
//
//   it must be launchable with a command that connects to a stdio MCP server
//   whose launch command is supplied as the final argv element and in
//   MCP_TARGET_SERVER_COMMAND, and it must then do some ordinary work
//   (discover, list tools, call a tool).
//
// That contract is unavoidable: MCP standardises the wire, not how a host is
// told which server to talk to. It is the one place the harness asks anything
// of the subject, and it is configuration, not code.

import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from '../core/runner.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const FAKE = resolve(HERE, '../../fakepeer/fake-server.mjs');

function fakeLaunch() {
  return `${process.execPath} ${FAKE}`;
}

/**
 * Run the subject's client against the fake server in a given mode, wait for
 * the client process to exit, and return the observed transcript.
 */
async function driveClient(ctx, mode, { failsafeMs = 20000, armListing = false, observeStall = false } = {}) {
  if (!ctx.target.hasClientRole) ctx.skip('target has no client role configured');
  const dir = mkdtempSync(join(tmpdir(), 'mcp-battery-'));
  const transcript = join(dir, 'transcript.jsonl');
  const peer = ctx.target.spawnClient(fakeLaunch(), {
    MCP_FAKE_MODE: mode,
    MCP_FAKE_TRANSCRIPT: transcript,
    // Asked for EXPLICITLY by the one scenario that reads a listing off the transcript
    // (CLI.CACHE.TOLERATES-ABSENT-HINTS). Driving a listing out of a gateway-shaped subject is an
    // operator verb behind a small per-minute mutation budget, so a launcher that armed it on
    // every test spent the budget before the scenario that needed it got its turn.
    ...(armListing ? { MCP_ARM_LISTING: '1' } : {}),
  });
  let exited = true;
  let waitError;
  try {
    await peer.waitForExit(failsafeMs);
  } catch (err) {
    if (err?.message !== `failsafe timeout after ${failsafeMs}ms waiting for peer exit`) throw err;
    exited = false;
    waitError = err;
  } finally {
    await peer.stop();
  }
  const lines = existsSync(transcript)
    ? readFileSync(transcript, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  ctx.note('client.driver', {
    mode, exitedBeforeCleanup: exited, exitCode: peer.exitCode,
    exitSignal: peer.exitSignal, transcript, waitError: waitError?.message || null,
  });
  if (peer.spawnError) throw peer.spawnError;
  if (waitError && !observeStall) throw waitError;
  return {
    exited,
    waitError,
    exitCode: peer.exitCode,
    stderr: peer.stderr,
    stdout: peer.stdoutBytes.toString('utf8'),
    entries: lines,
    fromClient: lines.filter((e) => e.direction === 'client->server').map((e) => e.payload),
    rawFromClient: lines.filter((e) => e.direction === 'client->server-raw').map((e) => e.payload),
    unparseable: lines.filter((e) => e.direction === 'client->server-unparseable').map((e) => e.payload),
    // THE OTHER HALF OF THE TRANSCRIPT, and it is what makes an absence row mean something. Every
    // hostile scenario below is of the form "the client did not do X after the server did Y";
    // without Y in evidence, the row passes on a client that never connected and a peer that
    // therefore never attacked. See `stimulated` and Ctx.evidence.
    fromServer: lines.filter((e) => e.direction === 'server->client').map((e) => e.payload),
    rawFromServer: lines.filter((e) => e.direction === 'server->client-raw').map((e) => e.payload),
  };
}

/**
 * THE EVIDENCE EVERY CLIENT SCENARIO OWES, in one place.
 *
 * `pred` is the mode's own attack, read off the SERVER half of the transcript: it answers "was the
 * thing this scenario is named for actually put on the wire?". The second half answers "did the
 * subject act at all?". A scenario passes on the conjunction and nothing weaker, so a subject that
 * exits immediately — `/usr/bin/true` scored 9 of 14 PASS before this existed — now scores none.
 */
function stimulated(ctx, obs, mode, pred, what) {
  const delivered = obs.fromServer.some(pred) || obs.rawFromServer.some(pred);
  ctx.evidence(`stimulus.${mode}`, delivered,
    `the peer never put ${what} on the wire, so nothing this scenario is named for was tested`);
  ctx.evidence(`subject.acted.${mode}`, obs.fromClient.length > 0,
    'the subject sent nothing at all to the peer; its silence cannot satisfy an absence row');
  return delivered;
}

const PV = 'io.modelcontextprotocol/protocolVersion';
const CC = 'io.modelcontextprotocol/clientCapabilities';
const CI = 'io.modelcontextprotocol/clientInfo';

// Associate retries with the request that actually received this input request. A capability
// declaration on some other request, or a response to another input key, is not evidence here.
function inputRetries(obs, inputKey, inputMethod) {
  const sent = new Map();
  const challenges = new Map();
  const retries = [];
  for (const entry of obs.entries) {
    const m = entry.payload;
    if (!m || typeof m !== 'object') continue;
    if (entry.direction === 'client->server' && m.method && m.id !== undefined) {
      const candidates = challenges.get(m.method) || [];
      if (candidates.length > 0 && Object.hasOwn(m.params?.inputResponses || {}, inputKey)) {
        // The peer reuses input keys. Concurrent calls of the same method cannot be paired
        // uniquely from those keys alone; retain the response without inventing its parent.
        const challenge = candidates.length === 1 ? candidates[0] : {};
        retries.push({ request: challenge.request, result: challenge.result, retry: m,
          response: m.params.inputResponses[inputKey] });
        challenges.delete(m.method);
      }
      sent.set(m.id, m);
    } else if (entry.direction === 'server->client' && m.id !== undefined && !m.method) {
      const request = sent.get(m.id);
      sent.delete(m.id);
      if (request && m.result?.resultType === 'input_required'
        && m.result.inputRequests?.[inputKey]?.method === inputMethod) {
        const candidates = challenges.get(request.method) || [];
        candidates.push({ request, result: m.result });
        challenges.set(request.method, candidates);
      }
    }
  }
  return retries;
}

function assertRetry(ctx, { request, result, retry }) {
  if (!request) {
    ctx.note('client.retry-correlation', 'Concurrent input requests reused the same input key; '
      + 'the parent request is ambiguous, so retry id/state assertions are unavailable.');
    return;
  }
  ctx.assert('PAT.MRTR.NEW-ID', retry.id !== request.id,
    `retry of ${request.method} reused its original id`);
  if (Object.hasOwn(result, 'requestState')) {
    ctx.assert('PAT.MRTR.ECHO-STATE', retry.params.requestState === result.requestState,
      `retry of ${request.method} did not echo the server's requestState`);
  } else {
    ctx.assert('PAT.MRTR.NO-STATE-INVENTION', !Object.hasOwn(retry.params, 'requestState'),
      `retry of ${request.method} invented requestState`);
  }
}

test({
  id: 'CLI.META.EVERY-REQUEST-CARRIES-VERSION-AND-CAPS',
  title: 'every client request carries protocolVersion and clientCapabilities in _meta',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A client that sends _meta once and relies on connection state, which stateless servers reject with -32602.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'honest');
    const requests = obs.fromClient.filter((m) => m.id !== undefined && m.method);
    if (requests.length === 0) ctx.skip(`client sent no requests to the fake server; driver stderr: ${JSON.stringify(String(obs.stderr || '').slice(-800))}`);
    ctx.evidence('subject.sentRequests', requests.length > 0,
      'no request from the subject means no _meta to judge');
    for (const r of requests) {
      const meta = (r.params && r.params._meta) || {};
      ctx.assert('BASE.META.REQUIRED-FIELDS', meta[PV] !== undefined,
        `request ${r.method} (id ${JSON.stringify(r.id)}) has no ${PV}`);
      ctx.assert('BASE.META.REQUIRED-FIELDS', meta[CC] !== undefined,
        `request ${r.method} (id ${JSON.stringify(r.id)}) has no ${CC}`);
    }
    ctx.variance('client.methodsUsed', [...new Set(requests.map((r) => r.method))].sort());
    ctx.variance('client.declaredCapabilities',
      Object.keys(((requests[0].params || {})._meta || {})[CC] || {}).sort());
    ctx.variance('client.protocolVersions',
      [...new Set(requests.map((r) => ((r.params || {})._meta || {})[PV]))]);
    // clientInfo is SHOULD, not MUST.
    ctx.recommend('client.sendsClientInfo',
      requests.every((r) => ((r.params || {})._meta || {})[CI] !== undefined),
      'Spec SHOULD: clients include io.modelcontextprotocol/clientInfo on every request.');
  },
});

test({
  id: 'CLI.IDS.UNIQUE-WHILE-IN-FLIGHT',
  title: 'the client never reuses a request id that is still unanswered',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'An id allocator that wraps or resets, so two in-flight requests collide and results cross-deliver.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'honest');
    const requests = obs.fromClient.filter((m) => m.id !== undefined && m.method);
    if (requests.length === 0) ctx.skip(`client sent no requests; driver stderr: ${JSON.stringify(String(obs.stderr || '').slice(-800))}`);
    ctx.evidence('subject.sentRequests', requests.length > 0,
      'no request from the subject means no id allocation to judge');
    const pending = new Set();
    const reused = [];
    for (const entry of obs.entries) {
      const m = entry.payload;
      if (!m || m.id === undefined) continue;
      const key = `${typeof m.id}:${JSON.stringify(m.id)}`;
      if (entry.direction === 'server->client' && !m.method && ('result' in m || 'error' in m)) {
        pending.delete(key);
      } else if (entry.direction === 'client->server' && m.method) {
        ctx.assert('BASE.REQ.ID-NOT-NULL', m.id !== null, `request ${m.method} used id null`);
        ctx.assert('BASE.REQ.ID-PRESENT',
          typeof m.id === 'string' || (typeof m.id === 'number' && Number.isInteger(m.id)),
          `request ${m.method} id is ${JSON.stringify(m.id)}`);
        const collision = pending.has(key);
        ctx.assert('BASE.REQ.ID-UNIQUE', !collision,
          `request ${m.method} reused pending ${typeof m.id} id ${JSON.stringify(m.id)}`);
        if (collision) reused.push(m.id);
        pending.add(key);
      }
    }
    ctx.variance('client.reusedIds', reused);
    ctx.variance('client.idType', typeof requests[0].id);
  },
});

test({
  id: 'CLI.NO-RESPONSES-SENT',
  title: 'the client never writes a JSON-RPC response to the server',
  role: 'client', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A client carried forward from 2025-11-25 answering server-initiated requests, which is forbidden in 2026-07-28.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'server-request');
    const responses = obs.fromClient.filter(
      (m) => m.id !== undefined && !m.method && ('result' in m || 'error' in m),
    );
    // "It sent no responses" is true of a subject that sent nothing. The row means "it talked to
    // the server AND none of what it sent was a response".
    stimulated(ctx, obs, 'server-request',
      (m) => m && m.id === 'server-initiated-1' && m.method,
      'the forbidden server-initiated request');
    ctx.assert('STDIO.CLIENT-NO-RESPONSES', responses.length === 0,
      `client sent JSON-RPC responses: ${JSON.stringify(responses).slice(0, 300)}`);
  },
});

test({
  id: 'CLI.HOSTILE.SERVER-INITIATED-REQUEST-IS-NOT-ANSWERED',
  title: 'a forbidden server-initiated request is not answered by the client',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that still answers server-initiated requests, giving a hostile server an unsolicited sampling channel.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'server-request');
    stimulated(ctx, obs, 'server-request',
      (m) => m && m.id === 'server-initiated-1' && m.method,
      'the forbidden server-initiated request');
    const answers = obs.fromClient.filter(
      (m) => m.id === 'server-initiated-1' && ('result' in m || 'error' in m),
    );
    ctx.assert('PAT.SERVER-NO-REQUESTS', answers.length === 0,
      `client answered a forbidden server-initiated request: ${JSON.stringify(answers)}`);
    ctx.assert('STDIO.CLIENT-NO-RESPONSES', answers.length === 0);
    ctx.variance('hostile.serverRequest.clientSurvived', obs.exited || obs.fromClient.length > 0);
  },
});

test({
  id: 'CLI.HOSTILE.MALFORMED-SERVER-FRAME-SURVIVED',
  title: 'the client survives an unparseable frame from the server',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client whose JSON parse error is fatal, so one bad byte from any server kills the host.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'malformed');
    stimulated(ctx, obs, 'malformed',
      (m) => typeof m === 'string' && m.includes('"jsonrpc"') && !m.trim().endsWith('}'),
      'the unparseable frame');
    // Refusing to send a JSON-RPC response is observable; process recovery is not.
    ctx.assert('STDIO.CLIENT-NO-RESPONSES',
      obs.unparseable.length === 0,
      `client emitted unparseable frames after a malformed server frame: ${JSON.stringify(obs.unparseable.slice(0, 2))}`);
    ctx.assert('STDIO.CLIENT-NO-RESPONSES',
      !obs.fromClient.some((m) => m.id !== undefined && !m.method && ('result' in m || 'error' in m)),
      'client emitted a forbidden JSON-RPC response after a malformed server frame');
    ctx.variance('hostile.malformed.clientExited', obs.exited);
    ctx.variance('hostile.malformed.requestsSent', obs.fromClient.length);
    ctx.note('limitation', 'The no-response assertion above does not establish client survival. A malformed '
      + 'server frame may legitimately terminate this driver; proving host recovery needs a '
      + 'client-side completion or recovery hook.');
  },
});

test({
  id: 'CLI.HOSTILE.STALLING-SERVER-DOES-NOT-HANG-FOREVER',
  title: 'the client does not wait forever on a server that never answers',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A client with no request timeout, so one stalling server hangs the host indefinitely.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'stall', { failsafeMs: 25000, observeStall: true });
    // The stimulus in `stall` is an ABSENCE — the peer's silence — so it cannot be read off the
    // server half of the transcript. What CAN be read is that the subject put a request in flight
    // and that the peer never answered it: without those two, "the client exited" says nothing
    // about timeouts, because a client that never asked anything has nothing to wait for.
    const sent = obs.fromClient.filter((m) => m.method && m.id !== undefined);
    const answered = new Set(obs.fromServer.filter((m) => m && m.id !== undefined && !m.method)
      .map((m) => JSON.stringify(m.id)));
    ctx.evidence('subject.requestInFlight', sent.length > 0,
      'the subject never sent a request, so it was never waiting on this peer');
    ctx.evidence('stimulus.stall', sent.some((m) => !answered.has(JSON.stringify(m.id))),
      'every request the subject sent was answered, so the stalling peer never stalled it');
    // Spec: implementations SHOULD establish timeouts for all sent requests.
    // SHOULD, so advisory, but a strong signal in a differential run.
    ctx.recommend('client.driverCompletedAgainstStall', obs.exited,
      'The driver exited before the harness failsafe. This does not establish a per-request timeout.');
    ctx.variance('hostile.stall.clientExitedWithin25s', obs.exited);
    ctx.variance('hostile.stall.exitCode', obs.exitCode);
    ctx.note('limitation', 'Request timeouts are advisory. Driver exit or harness termination cannot prove '
      + 'that a request timeout fired; proving that needs a correlated client-side timeout event.');
    // The peer's silence is intentional; an interrupted driver run is still not a completed
    // observation. Preserve the stimulus/advice above, then report the original harness error.
    if (obs.waitError) throw obs.waitError;
  },
});

test({
  id: 'CLI.HOSTILE.HALF-ANSWER-DISCONNECT',
  title: 'the client survives a server that closes stdout mid-frame',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that hangs or crashes when a server dies mid-response, the commonest real-world server failure.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'half-answer');
    stimulated(ctx, obs, 'half-answer',
      (m) => typeof m === 'string' && m.includes('"result"') && !m.trim().endsWith('}'),
      'the half-written frame followed by a closed stdout');
    ctx.variance('hostile.halfAnswer.clientExited', obs.exited);
    ctx.variance('hostile.halfAnswer.exitCode', obs.exitCode);
    ctx.note('limitation', 'Mid-frame EOF may legitimately terminate the driver. Exit alone cannot distinguish '
      + 'handled disconnection from a crash; proving recovery needs a client-side completion hook.');
  },
});

test({
  id: 'CLI.HOSTILE.EVIL-ELICITATION-PASSWORD',
  title: 'a form-mode elicitation asking for a password is not silently satisfied',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that auto-fills credential elicitations, handing secrets to any server that asks.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'evil-elicitation');
    stimulated(ctx, obs, 'evil-elicitation',
      (m) => m && m.result && m.result.resultType === 'input_required'
        && JSON.stringify(m.result.inputRequests || {}).includes('password'),
      'the form-mode elicitation asking for a password');
    // The SERVER is the violator here (form mode MUST NOT request secrets).
    // The client-side question is whether it leaked anything back.
    const retries = inputRetries(obs, 'creds', 'elicitation/create');
    const leaked = [];
    for (const r of retries) {
      assertRetry(ctx, r);
      const v = r.response;
      if (v?.action === 'accept' && v.content && typeof v.content === 'object') {
        const fields = ['password', 'apiKey'].filter((key) => Object.hasOwn(v.content, key));
        if (fields.length > 0) leaked.push(...fields);
      }
    }
    ctx.recommend('client.doesNotAutoFillCredentials', leaked.length === 0,
      'Servers MUST NOT request secrets in form mode; a client that auto-accepts such a form leaks them.');
    ctx.variance('hostile.evilElicitation.retried', retries.length > 0);
    ctx.variance('hostile.evilElicitation.leakedFields', [...new Set(leaked)].sort());
    ctx.note('limitation', 'The registered form-secret prohibition constrains the server. Correlated client '
      + 'disclosures are recorded above, but no registered clause makes client refusal mandatory; '
      + 'this row cannot certify credential protection or user consent over stdio.');
  },
});

test({
  id: 'CLI.HOSTILE.MRTR-UNDECLARED-CAPABILITY',
  title: 'the client does not satisfy an MRTR request for a capability it never declared',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that answers sampling requests without declaring the sampling capability, bypassing its own consent gate.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'mrtr-undeclared');
    const requests = obs.fromClient.filter((m) => m.method && m.id !== undefined);
    if (requests.length === 0) ctx.skip(`client sent no requests; driver stderr: ${JSON.stringify(String(obs.stderr || '').slice(-800))}`);
    stimulated(ctx, obs, 'mrtr-undeclared',
      (m) => m && m.result && m.result.resultType === 'input_required'
        && JSON.stringify(m.result.inputRequests || {}).includes('sampling/createMessage'),
      'the MRTR request for an undeclared sampling capability');
    const retries = inputRetries(obs, 'sample', 'sampling/createMessage');
    for (const retry of retries) assertRetry(ctx, retry);
    const fulfilled = retries.filter(({ response }) => response
      && typeof response === 'object' && !response.error
      && (Object.hasOwn(response, 'model') || Object.hasOwn(response, 'stopReason')));
    const declaredSampling = fulfilled.length === 0 ? null : fulfilled.every(({ request }) => request &&
      (((request.params || {})._meta || {})[CC] || {}).sampling !== undefined);
    const answeredSampling = fulfilled.length > 0;
    ctx.recommend('client.honoursOwnCapabilityDeclaration',
      declaredSampling || !answeredSampling,
      'A client that did not declare sampling should not fulfil a sampling inputRequest.');
    ctx.variance('hostile.mrtrUndeclared.declaredSampling', declaredSampling);
    ctx.variance('hostile.mrtrUndeclared.answeredSampling', answeredSampling);
    ctx.note('limitation', 'The registered undeclared-capability prohibition constrains the server. Sampling '
      + 'responses are correlated above with the triggering request declaration, but no registered '
      + 'client clause requires refusal; client consent needs an in-process hook.');
  },
});

test({
  id: 'CLI.HOSTILE.RUGPULL-SCHEMA-CHANGE',
  title: 'tool definitions changing between discovery and invocation are observable',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that caches a tool list forever and never notices a server swapping schemas underneath it.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'rugpull');
    const lists = obs.fromClient.filter((m) => m.method === 'tools/list');
    const calls = obs.fromClient.filter((m) => m.method === 'tools/call');
    // The rug-pull only exists once the subject has read a listing: "it did not re-list" is
    // meaningless about a subject that never listed once.
    ctx.evidence('subject.readAListing', lists.length > 0,
      'the subject never called tools/list, so no listing of its could be pulled out from under it');
    ctx.evidence('stimulus.rugpull', obs.fromServer.some((m) => m && m.result && m.result.tools),
      'the peer never served a tool listing');
    // Purely observational: there is no spec rule requiring re-validation.
    // The variance point is what a human needs to see.
    ctx.recommend('client.refreshesToolsAfterCall', lists.length > 1,
      'RECOMMENDATION (this battery): re-reading tools/list after a call limits the window for a schema rug-pull.');
    ctx.variance('hostile.rugpull.listCount', lists.length);
    ctx.variance('hostile.rugpull.callCount', calls.length);
    ctx.note('limitation', 'Re-listing after a call is not required by the protocol. Listing counts do not prove '
      + 'that a changed schema was detected; that needs a client-side schema or invocation hook.');
  },
});

test({
  id: 'CLI.HOSTILE.OUTPUTSCHEMA-VIOLATION-DETECTED',
  title: 'a server violating its own declared outputSchema is observable to the client',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that trusts structuredContent without validating it, so malformed data reaches the model as fact.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'outputschema-lie');
    stimulated(ctx, obs, 'outputschema-lie',
      (m) => m && m.result && m.result.structuredContent
        && m.result.structuredContent.count === 'not-an-integer',
      'the result that violates the declared outputSchema');
    ctx.variance('hostile.outputSchemaLie.clientExited', obs.exited);
    ctx.variance('hostile.outputSchemaLie.requestCount', obs.fromClient.length);
    ctx.note('limitation',
      'Whether the client validated structuredContent is NOT observable from the server side. '
      + 'Proving validation requires an in-process hook in the client.');
    ctx.note('limitation', 'Earlier client traffic does not prove validation or post-result survival. Proving '
      + 'the advisory outputSchema check needs a client-side validation hook.');
  },
});

test({
  id: 'CLI.HOSTILE.GIANT-RESULT',
  title: 'a very large tool result does not kill the client',
  role: 'client', area: 'hostile', tier: 'prerelease', peer: 'fake',
  catches: 'An unbounded read buffer in the client, so a hostile server can exhaust host memory with one reply.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'giant', { failsafeMs: 40000 });
    stimulated(ctx, obs, 'giant',
      (m) => JSON.stringify(m || '').length > 1024 * 1024,
      'the multi-megabyte result');
    ctx.variance('hostile.giant.clientExited', obs.exited);
    ctx.variance('hostile.giant.exitCode', obs.exitCode);
    ctx.variance('hostile.giant.unparseableFrames', obs.unparseable.length);
    ctx.note('limitation', 'Silence after a giant result does not prove survival or bounded buffering. Proving '
      + 'either needs a client-side completion or memory observation; no size cap is imposed here.');
  },
});

test({
  id: 'CLI.HOSTILE.BAD-ICON-SCHEME',
  title: 'the client does not fetch a javascript: icon URI',
  role: 'client', area: 'hostile', tier: 'pr', peer: 'fake',
  catches: 'A client that renders or fetches server-supplied icon URIs without scheme checking, an XSS and SSRF vector.',
  run: async (ctx) => {
    const obs = await driveClient(ctx, 'bad-icon');
    stimulated(ctx, obs, 'bad-icon',
      (m) => JSON.stringify(m || '').includes('javascript:alert(1)'),
      'the tool listing carrying a javascript: icon URI');
    // Not observable from the server side either; recorded as a limitation.
    ctx.variance('hostile.badIcon.clientExited', obs.exited);
    ctx.note('limitation',
      'Icon fetching happens outside the MCP stdio channel. Detecting a fetch needs a network sinkhole, '
      + 'which is in the HTTP half of the battery, not the stdio half.');
    ctx.note('limitation', 'Offering an unsafe URI does not observe fetching or rendering. Icon-scheme '
      + 'conformance requires a network sinkhole or rendering hook outside this stdio transcript.');
  },
});

test({
  id: 'CLI.CACHE.TOLERATES-ABSENT-HINTS',
  title: 'the client tolerates a server that omits ttlMs and cacheScope',
  role: 'client', area: 'conformance', tier: 'pr', peer: 'fake',
  catches: 'A client that hard-rejects results without caching hints, breaking against every older or minimal server.',
  run: async (ctx) => {
    // A LONGER FAILSAFE THAN THE DEFAULT, for this scenario alone. Driving a listing out of a
    // gateway-shaped client is an operator's verb, and operator verbs sit behind a per-minute
    // mutation budget the driver may legitimately have to wait out (its own stderr says when it
    // is doing so). The failsafe is a ceiling on waiting for the driver to EXIT, not a slackening
    // of anything asserted: the transcript judged below is still only what genuinely reached the
    // peer.
    const withHints = await driveClient(ctx, 'honest', { failsafeMs: 120000, armListing: true });
    const without = await driveClient(ctx, 'no-cache-hints', { failsafeMs: 120000, armListing: true });
    const listedWithHints = withHints.fromClient.some((m) => m.method === 'tools/list');
    // The driver's stderr rides the skip, because this skip is a GATE FAILURE under MCP_NO_SKIPS
    // and "did not call" has two very different causes — a client that genuinely never lists, and
    // a driver whose listing leg failed — distinguishable only by what the driver printed.
    if (!listedWithHints) {
      ctx.skip('client did not call tools/list even against an honest server; driver stderr: '
        + JSON.stringify(String(withHints.stderr || '').slice(-800)));
    }

    // The spec is explicit that clients SHOULD default an absent ttlMs to 0
    // rather than treating it as an error, precisely so newer clients keep
    // working against older servers. SHOULD, so this is advisory, but it is a
    // high-value signal in a differential run.
    ctx.evidence('subject.listedWithHints', listedWithHints,
      'the subject never listed against the honest peer, so there is no with-hints run to compare');
    ctx.evidence('stimulus.no-cache-hints',
      without.fromServer.some((m) => m && m.result && m.result.tools
        && m.result.ttlMs === undefined && m.result.cacheScope === undefined),
      'the peer served no hint-free listing, so the tolerance this row is named for was never tested');

    ctx.variance('cache.requestsWithHints', withHints.fromClient.filter((m) => m.method).length);
    ctx.variance('cache.requestsWithoutHints', without.fromClient.filter((m) => m.method).length);
    ctx.note('spec-clause', 'CACHE.CLIENT-TOLERATES-ABSENT-TTL');
    ctx.note('limitation', 'Absent-TTL tolerance is advisory. Cross-run request counts do not establish '
      + 'whether a listing was accepted; proving that needs a correlated client-side listing result.');
  },
});
