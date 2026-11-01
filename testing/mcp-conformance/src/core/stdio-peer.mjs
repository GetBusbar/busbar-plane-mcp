// A raw stdio MCP client.
//
// This is NOT an SDK client. It is a byte-level driver, because half the
// battery consists of sending things an SDK would refuse to send. It gives
// tests:
//
//   * sendRaw(string)      -- exact bytes, no framing help, no validation
//   * send(obj)            -- one JSON object, newline framed
//   * waitFor(predicate)   -- deterministic synchronisation on a received
//                             message, NOT on elapsed time
//   * all messages, stdout bytes and stderr bytes retained for assertions
//
// Deterministic synchronisation note: every wait in this file is a wait for an
// OBSERVABLE EVENT (a matching message, or process exit). The only timeouts are
// failsafes to stop a hung CI job, and a test that relies on a failsafe firing
// is marked TIMING in its definition.

import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { classify } from './jsonrpc.mjs';

const FAILSAFE_MS = Number(process.env.MCP_BATTERY_FAILSAFE_MS || 15000);
if (!Number.isFinite(FAILSAFE_MS) || FAILSAFE_MS <= 0) {
  throw new Error('MCP_BATTERY_FAILSAFE_MS must be a positive finite duration');
}

export class StdioPeer {
  constructor(command, args = [], opts = {}) {
    this.command = command;
    this.args = args;
    this.opts = opts;
    this.messages = [];        // parsed messages, in arrival order
    this.rawLines = [];        // every stdout line as received, pre-parse
    this.badLines = [];        // stdout lines that did not parse as JSON
    this.stderr = '';
    this.stdoutBytes = Buffer.alloc(0);
    this.exited = false;
    this.exitCode = null;
    this.exitSignal = null;
    this._buf = '';
    this._decoder = new StringDecoder('utf8');
    this.httpTransport = false;
    this.httpStatuses = [];
    this.httpObservationError = null;
    this._httpBuf = '';
    this._httpDecoder = new StringDecoder('utf8');
    this._waiters = [];
    this._exitWaiters = [];
  }

  start() {
    this.proc = spawn(this.command, this.args, {
      stdio: ['pipe', 'pipe', 'pipe', 'pipe'],
      detached: process.platform !== 'win32',
      env: { ...process.env, ...(this.opts.env || {}), MCP_BATTERY_HTTP_STATUS_FD: '3' },
      cwd: this.opts.cwd,
    });
    this.proc.stdout.on('data', (chunk) => {
      this.stdoutBytes = Buffer.concat([this.stdoutBytes, chunk]);
      this._buf += this._decoder.write(chunk);
      let idx;
      while ((idx = this._buf.indexOf('\n')) >= 0) {
        const line = this._buf.slice(0, idx);
        this._buf = this._buf.slice(idx + 1);
        this._onLine(line);
      }
    });
    this.proc.stderr.on('data', (c) => { this.stderr += c.toString('utf8'); });
    this.proc.stdio[3].on('data', (chunk) => {
      this._httpBuf += this._httpDecoder.write(chunk);
      let idx;
      while ((idx = this._httpBuf.indexOf('\n')) >= 0) {
        const line = this._httpBuf.slice(0, idx);
        this._httpBuf = this._httpBuf.slice(idx + 1);
        this._onHttpLine(line);
      }
    });
    this.proc.stdio[3].on('error', (error) => { this.httpObservationError = error; });
    this.proc.stdin.on('error', (err) => {
      this.writeError = err;
      for (const w of this._waiters.splice(0)) w.reject(err);
    });
    // `close` follows stdout/stderr/status drain; `exit` may precede the final pipe data.
    this.proc.on('close', (code, signal) => {
      this._buf += this._decoder.end();
      if (this._buf !== '') { this._onLine(this._buf); this._buf = ''; }
      this._httpBuf += this._httpDecoder.end();
      if (this._httpBuf !== '') {
        this.httpObservationError = new Error('HTTP observation ended inside a record');
        this._httpBuf = '';
      }
      this.exited = true;
      this.exitCode = code;
      this.exitSignal = signal;
      for (const w of this._exitWaiters.splice(0)) w.resolve();
      // Wake message waiters so they fail fast instead of hanging to failsafe.
      for (const w of this._waiters.splice(0)) {
        w.reject(new Error(`peer exited (code=${code} signal=${signal}) while waiting for: ${w.label}`));
      }
    });
    this.proc.on('error', (err) => {
      this.spawnError = err;
      this.exited = true;
      for (const w of this._exitWaiters.splice(0)) w.resolve();
      for (const w of this._waiters.splice(0)) w.reject(err);
    });
    return this;
  }

  _onLine(line) {
    this.rawLines.push(line);
    const trimmed = line.replace(/\r$/, '');
    if (trimmed.trim() === '') return;      // blank line: recorded, not parsed
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      this.badLines.push(line);
      return;
    }
    this.messages.push(msg);
    for (let i = this._waiters.length - 1; i >= 0; i--) {
      const w = this._waiters[i];
      if (w.predicate(msg)) {
        this._waiters.splice(i, 1);
        w.resolve(msg);
      }
    }
  }

  _onHttpLine(line) {
    try {
      const observed = JSON.parse(line);
      if (!this.httpTransport && observed?.transport === 'http'
        && Object.keys(observed).length === 1) {
        this.httpTransport = true;
        return;
      }
      if (!this.httpTransport || !observed || !Number.isSafeInteger(observed.sequence)
        || observed.sequence <= 0 || !Number.isInteger(observed.status)
        || observed.status < 100 || observed.status > 599 || !Object.hasOwn(observed, 'id')
        || (observed.id !== null && !['string', 'number'].includes(typeof observed.id))
        || Object.keys(observed).length !== 3
        || this.httpStatuses.some((record) => record.sequence === observed.sequence)) {
        throw new Error('invalid HTTP observation record');
      }
      this.httpStatuses.push(observed);
    } catch { this.httpObservationError = new Error('invalid HTTP observation record'); }
  }

  // Inspect after stop()/waitForExit(): independent pipes can drain in either order.
  httpStatusesFor(id) {
    return this.httpStatuses.filter((record) => record.id === id);
  }

  /** Exact bytes. No newline appended. Tests append their own framing. */
  sendRaw(text) {
    if (this.writeError) throw this.writeError;
    if (this.exited || !this.proc || this.proc.stdin.destroyed || this.proc.stdin.writableEnded) {
      throw new Error('peer exited or its input is no longer writable');
    }
    this.proc.stdin.write(text);
    return this;
  }

  /** One JSON object as one newline-delimited frame. */
  send(obj) {
    this.sendRaw((typeof obj === 'string' ? obj : JSON.stringify(obj)) + '\n');
    return this;
  }

  closeStdin() {
    this.proc.stdin.end();
    return this;
  }

  /**
   * Deterministic wait: resolves when a message matching `predicate` arrives.
   * Already-received messages are considered first, so there is no race
   * between sending and waiting.
   */
  waitFor(predicate, label = 'message', failsafeMs = FAILSAFE_MS) {
    for (const m of this.messages) {
      if (predicate(m)) return Promise.resolve(m);
    }
    if (this.spawnError || this.writeError) return Promise.reject(this.spawnError || this.writeError);
    if (this.exited) return Promise.reject(new Error(`peer exited while waiting for: ${label}`));
    return new Promise((resolve, reject) => {
      const w = { predicate, resolve, reject, label };
      this._waiters.push(w);
      const t = setTimeout(() => {
        const i = this._waiters.indexOf(w);
        if (i >= 0) this._waiters.splice(i, 1);
        reject(new Error(`failsafe timeout after ${failsafeMs}ms waiting for: ${label}`));
      }, failsafeMs);
      const clear = () => clearTimeout(t);
      const origResolve = w.resolve;
      const origReject = w.reject;
      w.resolve = (v) => { clear(); origResolve(v); };
      w.reject = (e) => { clear(); origReject(e); };
    });
  }

  /** Wait for the response (result or error) to a specific request id. */
  waitForId(id, failsafeMs = FAILSAFE_MS) {
    return this.waitFor(
      (m) => m && m.id === id && ('result' in m || 'error' in m),
      `response to id ${JSON.stringify(id)}`,
      failsafeMs,
    );
  }

  waitForExit(failsafeMs = FAILSAFE_MS) {
    if (this.exited) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const w = { resolve };
      this._exitWaiters.push(w);
      const t = setTimeout(() => {
        const i = this._exitWaiters.indexOf(w);
        if (i >= 0) this._exitWaiters.splice(i, 1);
        reject(new Error(`failsafe timeout after ${failsafeMs}ms waiting for peer exit`));
      }, failsafeMs);
      w.resolve = () => { clearTimeout(t); resolve(); };
    });
  }

  /**
   * Settle point. There is no observable event for "the peer has decided not
   * to reply", so tests that assert an ABSENCE need a bounded quiet period.
   * Any test using this is marked TIMING. Prefer waitFor wherever an event
   * exists.
   */
  async quiesce(ms = 400) {
    const before = this.messages.length;
    await new Promise((r) => setTimeout(r, ms));
    return this.messages.slice(before);
  }

  responsesFor(id) {
    return this.messages.filter((m) => m && m.id === id && ('result' in m || 'error' in m));
  }

  serverRequests() {
    return this.messages.filter((m) => classify(m) === 'request');
  }

  async stop() {
    if (this.exited || !this.proc) return;
    try { this.proc.stdin.end(); } catch { /* already closed */ }
    try {
      await this.waitForExit(2000);
    } catch {
      try {
        if (process.platform === 'win32') this.proc.kill('SIGKILL');
        else process.kill(-this.proc.pid, 'SIGKILL');
      } catch { /* the owned process group is gone */ }
      await this.waitForExit(2000);
    }
  }
}

/** Parse a target spec like "python control_server.py" into command+args. */
export function parseLaunch(launch) {
  const parts = [];
  let word = '', quote = null, active = false;
  for (let i = 0; i < launch.length; i += 1) {
    const c = launch[i];
    if (quote === "'") {
      if (c === "'") quote = null; else word += c;
      continue;
    }
    if (c === '\\') {
      const next = launch[i + 1];
      if (next === undefined) throw new Error('launch command ends in an escape');
      if (quote === '"' && !['"', '\\', '$', '`', '\n'].includes(next)) {
        word += c;
      } else {
        i += 1;
        if (next !== '\n') word += next;
      }
      active = true;
      continue;
    }
    if (quote === '"') {
      if (c === '"') quote = null; else word += c;
    } else if (c === '"' || c === "'") {
      quote = c; active = true;
    } else if (/\s/.test(c)) {
      if (active) { parts.push(word); word = ''; active = false; }
    } else {
      word += c; active = true;
    }
  }
  if (quote) throw new Error('launch command has an unterminated quote');
  if (active) parts.push(word);
  if (!parts[0]) throw new Error('launch command is empty');
  return { command: parts[0], args: parts.slice(1) };
}
