#!/usr/bin/env node
// THE HOSTILE UPSTREAM, ON THE TRANSPORT THE SUBJECT ACTUALLY SPEAKS: streamable HTTP in,
// `fake-server.mjs` on stdio out.
//
// WHY THIS EXISTS, AND WHY IT IS NOT A SECOND FAKE SERVER.
//
// `fakepeer/fake-server.mjs` is the battery's hostility: twenty-odd named attacks, each emitting
// exact bytes no SDK would produce. It speaks stdio, because the battery's own client driver
// (`src/core/stdio-peer.mjs`) does. busbar's MCP CLIENT direction speaks ONE transport —
// streamable HTTP, revision `2026-07-28` — and deliberately no other: `transport: stdio` is refused
// at config validation and there is no child supervisor in the build to resurrect. So the seam
// tests, which need busbar to MOUNT a hostile server as an upstream, had no peer they could mount.
//
// The answer is the MIRROR of `scripts/stdio-http-bridge.mjs`, which is how the battery reaches
// busbar's front door. That file turns the battery's stdio into HTTP; this one turns HTTP back into
// the fake server's stdio. Between the two, the battery's bytes and the fake server's bytes are
// unchanged and busbar sits in the middle speaking only the transport it ships.
//
// A SECOND, HTTP-NATIVE HOSTILE SERVER WAS THE OTHER OPTION AND IS THE WRONG ONE. Twenty-odd
// attacks re-implemented against a second wire is twenty-odd chances for the two to disagree, and
// the moment they disagree the negative-control leg is proving something about a file no seam test
// runs. One source of hostility, two transports.
//
// WHAT THIS FILE DOES NOT DO, which is the same list as its mirror:
//
//   * IT NEVER REPAIRS A BODY. The bytes of the POST body are the bytes written to the fake
//     server's stdin, and the fake server's bytes are the bytes written back. A NUL byte, a lone
//     surrogate, a truncated frame: all survive.
//   * IT NEVER SYNTHESISES A RESULT. `stall` mode answers nothing, so this file answers nothing and
//     holds the socket open until the client gives up — which is what a stalled upstream IS. It
//     does not invent a 504 to be tidy, because a 504 is an answer and the point is that there
//     isn't one.
//   * IT NEVER TIDIES A DEATH. `half-answer` writes half a frame and closes stdout; this file
//     writes those bytes and DESTROYS the socket. A clean `Content-Length`-framed 200 carrying half
//     a frame would be a well-formed HTTP response, and busbar would be judged on parsing rather
//     than on surviving a peer that died mid-frame.
//
// MODE SELECTION IS A FILE, NOT AN ENVIRONMENT VARIABLE, and that is what makes one long-lived
// busbar serve every seam test. The seam suite picks a fresh mode per test; an env-selected mode
// would mean a fresh upstream process, a fresh registration and therefore a fresh busbar per test,
// and a busbar booted per test could never demonstrate `ROLE-ISOLATION-UNDER-UPSTREAM-CRASH` at
// all — "the front door still works" is only a claim about a process that was already serving when
// the upstream died. So the control file carries `{ "mode": ..., "transcript": ... }`, it is read on
// every request, and a CHANGE respawns the fake-server child — as does the child DYING, which
// `half-answer` does by contract: every request meets a live attacker in the armed mode, so a
// second request in a killing mode is killed the same way rather than silently never observed.
//
// Usage:  node http-fake-server.mjs <port> <control-file>

import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { readFileSync, appendFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const PORT = Number(process.argv[2]);
const CONTROL = process.argv[3];
if (!PORT || !CONTROL) {
  process.stderr.write('usage: http-fake-server.mjs <port> <control-file>\n');
  process.exit(2);
}
const FAKE = resolve(dirname(fileURLToPath(import.meta.url)), 'fake-server.mjs');

// How long to keep listening for MORE frames after the one that answers this request.
// `dup-response` and `wrong-id` both emit two, and a response that closed on the first would hide
// exactly the defect those modes exist to plant. Small, and only ever ADDS latency to a request
// that has already been answered.
const EXTRA_FRAME_WINDOW_MS = 120;

// ── THE CHILD ───────────────────────────────────────────────────────────────────────────────────

let child = null;          // the running fake-server, or null
let childKey = null;       // the `mode\0transcript` it was started with
let pending = [];          // requests awaiting frames, oldest first
let lineBuf = Buffer.alloc(0);

function readControl() {
  const c = JSON.parse(readFileSync(CONTROL, 'utf8'));
  if (!c || typeof c !== 'object' || typeof c.mode !== 'string' || !c.mode) {
    throw new Error(`invalid fake-peer control file ${CONTROL}`);
  }
  return {
    mode: c.mode,
    transcript: c.transcript ? String(c.transcript) : '',
    credentialFile: c.credentialFile ? String(c.credentialFile) : '',
  };
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex');
}

// Header values never enter a transcript. The credential probe also keeps its
// body out of the child transcript: a forwarding defect must not publish the
// very credential it detects. Only redacted payloads and match counts survive.
function observeRequest(control, req, body) {
  if (!control.transcript) return;
  const token = control.credentialFile ? readFileSync(control.credentialFile, 'utf8').trim() : '';
  if (control.credentialFile && !token) throw new Error('empty credential probe file');
  const text = body.toString('utf8');
  const headers = Object.entries(req.headers).map(([name, value]) => ({
    name,
    sha256: digest(Array.isArray(value) ? value.join(', ') : String(value)),
  }));
  const rawValues = Object.values(req.headers).flat().map(String);
  let credentialMatches = token
    ? rawValues.filter((value) => value.includes(token)).length + Number(text.includes(token))
    : null;
  const safeValue = (value) => {
    if (typeof value === 'string') {
      if (token && value.includes(token)) {
        credentialMatches += 1;
        return value.split(token).join('[REDACTED]');
      }
      return value;
    }
    if (Array.isArray(value)) return value.map(safeValue);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [safeValue(key), safeValue(item)]));
    }
    return value;
  };
  let payload = null;
  try { payload = safeValue(JSON.parse(text)); } catch { /* malformed bodies remain unmodified on the wire */ }
  appendFileSync(control.transcript, `${JSON.stringify({
    direction: 'http-client->server', instance: PORT, headers, credentialMatches, payload,
  })}\n`);
  if (control.credentialFile) {
    appendFileSync(control.transcript, `${JSON.stringify({
      direction: 'client->server', instance: PORT, mode: control.mode, payload,
    })}\n`);
  }
}

/**
 * Ensure a fake-server child is running for `want`. Respawns on a mode change, and FAILS EVERY
 * PENDING REQUEST when it does: those requests belong to the previous test, and letting the new
 * child answer them would let one test's peer answer another test's question.
 */
function ensureChild(want) {
  const key = `${want.mode}\0${want.transcript}\0${want.credentialFile}`;
  // Output EOF ends this peer's custody even if its process still reads stdin. A later
  // request must meet a fresh attacker in the armed mode, including repeated half-answers.
  if (child && childKey === key && !child.killed && child.exitCode === null
      && !child.stdout.readableEnded && !child.stdout.destroyed
      && !child.stdin.writableEnded && !child.stdin.destroyed) return;
  if (child) {
    for (const p of pending.splice(0)) p.abandon();
    const retiring = child;
    child = null;                                // retired FIRST, so its late events are ignored
    try { retiring.kill('SIGKILL'); } catch { /* already gone */ }
  }
  lineBuf = Buffer.alloc(0);
  childKey = key;
  const env = { ...process.env, MCP_FAKE_MODE: want.mode };
  if (want.transcript && !want.credentialFile) env.MCP_FAKE_TRANSCRIPT = want.transcript;
  else delete env.MCP_FAKE_TRANSCRIPT;
  const spawned = spawn(process.execPath, [FAKE], { stdio: ['pipe', 'pipe', 'inherit'], env });
  // A dead child's stdin errors ASYNCHRONOUSLY (EPIPE on a later tick), and an unhandled `error`
  // on any stream is fatal to the process. Swallowed, because the death itself is already
  // delivered to the requests in flight by the `end`/`exit` handlers below -- this handler
  // exists so the messenger survives the message.
  spawned.stdin.on('error', () => {});
  spawned.on('error', (error) => {
    process.stderr.write(`fake-peer spawn failed: ${error}\n`);
  });
  child = spawned;
  // EVERY HANDLER IS GUARDED ON `child === spawned`, AND THAT GUARD IS LOAD-BEARING.
  //
  // `kill()` is not synchronous: a SIGKILLed child's `end` and `exit` fire on a LATER tick, by
  // which time the request that triggered the respawn is already in `pending`. Unguarded, the DEAD
  // child's death handler reached into the shared array and destroyed the LIVE request's socket —
  // so the subject saw `error sending request` for every seam call, the fake server's transcript
  // stayed empty, and the six clauses reported "the seam was never crossed" against a subject that
  // had crossed it correctly every time. A defect in the harness that reads exactly like a defect
  // in the subject.
  spawned.stdout.on('data', (chunk) => { if (child === spawned) onChildBytes(chunk); });
  // STDOUT CLOSING IS THE DEATH SIGNAL, and it is delivered to the request in flight rather than
  // swallowed: `half-answer` ends stdout mid-frame on purpose.
  spawned.stdout.on('end', () => {
    if (child !== spawned) return;               // a retired child's death is nobody's business
    const partial = lineBuf;
    // Retire before failing requests: their callbacks may admit the next request, and late
    // exit/end events from this child must never consume that new peer's pending queue.
    child = null;
    childKey = null;
    lineBuf = Buffer.alloc(0);
    try { spawned.kill('SIGKILL'); } catch { /* already gone */ }
    const p = pending.shift();
    if (p) p.die(partial);
    for (const q of pending.splice(0)) q.die(Buffer.alloc(0));
  });
  // `close` follows stdout's final data/end; `exit` may precede their delivery.
  spawned.on('close', () => {
    if (child !== spawned) return;
    child = null;
    childKey = null;
    lineBuf = Buffer.alloc(0);
    for (const q of pending.splice(0)) q.die(Buffer.alloc(0));
  });
}

/**
 * Frames off the child, split on 0x0A and kept as BYTES. The fake server emits deliberate
 * malformations, and a round trip through a JS string would sanitise the input under test.
 */
function onChildBytes(chunk) {
  lineBuf = Buffer.concat([lineBuf, chunk]);
  let i;
  while ((i = lineBuf.indexOf(0x0a)) >= 0) {
    const line = lineBuf.subarray(0, i);
    lineBuf = lineBuf.subarray(i + 1);
    if (line.toString('utf8').trim() === '') continue;
    deliverFrame(Buffer.from(line));
  }
}

/**
 * One frame goes to the request WHOSE ID IT ANSWERS when such a request is in flight, and to the
 * OLDEST in-flight request otherwise.
 *
 * The fallback is load-bearing for the attacks: `wrong-id` answers with an id nobody asked for and
 * `unsolicited-notif` emits id-less notifications, and both must still reach a request's response
 * so the subject can be observed refusing them — routing them nowhere would delete the attack.
 *
 * The id match is load-bearing for everything else: the subject legitimately holds MORE THAN ONE
 * request open against this peer at once (a drift-check `tools/list` beside a dispatch
 * `tools/call`), and oldest-first attribution under that concurrency handed each caller the
 * other's answer. The subject then refused BOTH — correctly, on id correlation — and the refusals
 * read as upstream failures of the harness's own making.
 */
function deliverFrame(frame) {
  let parsedFrame = null;
  try { parsedFrame = JSON.parse(frame.toString('utf8')); } catch { /* not id-routable */ }
  const answersId = parsedFrame && typeof parsedFrame === 'object' && !Array.isArray(parsedFrame)
    && parsedFrame.id !== undefined && ('result' in parsedFrame || 'error' in parsedFrame)
    ? parsedFrame.id : undefined;
  const byId = answersId === undefined
    ? undefined
    : pending.find((q) => q.requestId === answersId);
  const p = byId || pending[0];
  if (!p) return;                                  // an unsolicited frame with nothing to attach to
  p.frames.push(frame);
  let parsed = null;
  try { parsed = JSON.parse(frame.toString('utf8')); } catch { /* stays a frame, unparsed */ }
  const answersUs = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    && ('result' in parsed || 'error' in parsed);
  if (answersUs && !p.closing) {
    p.closing = true;
    setTimeout(() => p.finish(), EXTRA_FRAME_WINDOW_MS).unref();
  }
}

// ── THE HTTP FACE ───────────────────────────────────────────────────────────────────────────────

/**
 * ONE frame is answered as `application/json`; TWO OR MORE as `text/event-stream`.
 *
 * Both are legal answers to a POST in this revision, and the choice is forced rather than stylistic:
 * a single JSON body cannot carry two frames, and the modes that matter here (`dup-response`,
 * `wrong-id`, `server-request`, `unsolicited-notif`) are DEFINED by emitting two. Collapsing them to
 * one would delete the attack.
 */
function respond(res, frames) {
  if (frames.length === 0) { res.writeHead(202).end(); return; }
  if (frames.length === 1) {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(frames[0]);
    return;
  }
  res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store' });
  for (const f of frames) {
    res.write(Buffer.concat([Buffer.from('data: '), f, Buffer.from('\n\n')]));
  }
  res.end();
}

const server = createServer((req, res) => {
  // EVERY REQUEST IS LOGGED, on stderr, before anything else. A seam verdict is read off the
  // TRANSCRIPT the fake server's child writes, and a transcript can be empty for two completely
  // different reasons -- the subject never called, or the subject called and this process never
  // handed the bytes on. Without a line here those are indistinguishable, and the first debugging
  // session on this file lost an hour to exactly that.
  process.stderr.write(`http-fake-server: ${new Date().toISOString()} ${req.method}\n`);
  if (req.method !== 'POST') { res.writeHead(405).end(); return; }
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const body = Buffer.concat(chunks);
    let control;
    try { control = readControl(); }
    catch (error) {
      process.stderr.write(`fake-peer control failed: ${error}\n`);
      res.writeHead(503, { 'content-type': 'text/plain' });
      res.end('fake-peer control is unavailable');
      return;
    }
    try { observeRequest(control, req, body); }
    catch {
      res.writeHead(503).end('fake-peer observation unavailable');
      return;
    }
    ensureChild(control);

    let parsed = null;
    try { parsed = JSON.parse(body.toString('utf8')); } catch { /* forwarded verbatim anyway */ }
    const isNotification = parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      && parsed.id === undefined && typeof parsed.method === 'string';

    if (isNotification) {
      // The fake server answers nothing to a notification, by design. 202 with no body is what an
      // accepted notification looks like on this transport; waiting for a frame that cannot come
      // would hang every `notifications/cancelled` the seam sends.
      try { child.stdin.write(Buffer.concat([body, Buffer.from('\n')])); } catch { /* dead child */ }
      res.writeHead(202).end();
      return;
    }

    const entry = {
      // The id this request awaits, for the id-routing above. `undefined` for an unparseable body,
      // which then only ever receives oldest-first frames — the honest reading of a request whose
      // id nobody can know.
      requestId: parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed.id : undefined,
      frames: [],
      closing: false,
      done: false,
      finish() {
        if (this.done) return;
        this.done = true;
        pending = pending.filter((x) => x !== this);
        respond(res, this.frames);
      },
      // The child died mid-frame. Write whatever bytes it managed and TEAR THE SOCKET DOWN: the
      // client must see a broken response, because that is what happened.
      die(partial) {
        if (this.done) return;
        this.done = true;
        pending = pending.filter((x) => x !== this);
        try {
          res.writeHead(200, { 'content-type': 'application/json' });
          for (const f of this.frames) res.write(f);
          if (partial.length) res.write(partial);
        } catch { /* headers already sent */ }
        try { res.socket.destroy(); } catch { /* already gone */ }
      },
      // The mode changed under us: this request belongs to a peer that no longer exists.
      abandon() {
        if (this.done) return;
        this.done = true;
        try { res.socket.destroy(); } catch { /* already gone */ }
      },
    };
    pending.push(entry);
    process.stderr.write(`http-fake-server: ${new Date().toISOString()} -> child mode=${control.mode} pending=${pending.length}\n`);
    // NO TIMEOUT HERE, and that is the `stall` mode contract: an upstream that never answers is
    // answered by nothing. busbar's own per-upstream deadline is what ends this, and making that
    // deadline observable is the whole of SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR.
    res.on('close', () => { entry.done = true; pending = pending.filter((x) => x !== entry); });
    try {
      child.stdin.write(Buffer.concat([body, Buffer.from('\n')]));
    } catch {
      entry.die(Buffer.alloc(0));                  // stdin already closed: the peer is dead
    }
  });
});

// NEVER REAP AN IDLE CONNECTION. Node's default is to FIN a keep-alive connection idle for
// five seconds, while the subject's client pools its upstream connections far longer -- so a
// request landing just as the FIN does is an `error sending request` that never reaches this
// process, and a seam verdict then rests on which side of a five-second timer the test ran.
// The subject is entitled to reuse a connection this peer offered to keep alive.
server.keepAliveTimeout = 0;
// AND THE HEADER TIMEOUT, which is the OTHER idle reaper: with the keep-alive timeout
// disabled, Node still closes a connection that has carried no request HEADERS for
// `headersTimeout` (60s default) since the previous request ended -- so a subject whose pool
// reuses a connection idle for just over a minute (boot-time arming, then a quiet suite
// phase) hit a FIN mid-send and failed with `error sending request` before a byte reached
// this process. Zero disables it; `requestTimeout` likewise, so a deliberately stalled
// request is ended by the SUBJECT's own deadline, which is the thing under test.
server.headersTimeout = 0;
server.requestTimeout = 0;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (child) { try { child.kill('SIGTERM'); } catch { /* already exited */ } }
  server.close();
  process.exit(0);
});
server.listen(PORT, '127.0.0.1', () => {
  process.stderr.write(`http-fake-server: listening on 127.0.0.1:${PORT}, control ${CONTROL}\n`);
});
