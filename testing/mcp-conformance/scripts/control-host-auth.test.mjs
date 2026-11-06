import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
test('reference host rejects absent/wrong credentials before upstream dispatch', { timeout: 15000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'control-host-auth-'));
  const bearer = randomBytes(24).toString('hex');
  const tokenFile = join(dir, 'bearer');
  const front = join(dir, 'front.jsonl');
  const back = join(dir, 'back.jsonl');
  writeFileSync(tokenFile, bearer, { mode: 0o600 });
  const child = spawn(process.execPath, [join(root, 'control/control_host.mjs')], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, MCP_SEAM_BEARER_FILE: tokenFile, MCP_SEAM_FRONT_TRANSCRIPT: front,
      MCP_FAKE_TRANSCRIPT: back, MCP_FAKE_MODE: 'honest', MCP_SEAM_CREDENTIAL_PROBE: '1',
      MCP_SEAM_UPSTREAM_CMD: `${process.execPath} ${join(root, 'fakepeer/fake-server.mjs')}` },
  });
  try {
    const url = await new Promise((done, reject) => {
      const timer = setTimeout(() => reject(new Error('host readiness timed out')), 7000);
      let logs = '';
      child.stderr.on('data', (data) => {
        logs += data.toString();
        const found = logs.match(/reference-host: (http:\/\/127\.0\.0\.1:\d+\/mcp)/);
        if (found) { clearTimeout(timer); done(found[1]); }
      });
      child.once('error', (error) => { clearTimeout(timer); reject(error); });
      child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`host exited ${code}: ${logs}`)); });
    });
    const body = JSON.stringify({ jsonrpc: '2.0', id: 'auth-check', method: 'tools/call',
      params: { name: 'echo', arguments: { text: 'actual upstream response' } } });
    for (const authorization of [undefined, 'Bearer invalid']) {
      const headers = { 'content-type': 'application/json', ...(authorization ? { authorization } : {}) };
      const response = await fetch(url, { method: 'POST', headers, body });
      assert.equal(response.status, 401);
      await response.arrayBuffer();
    }
    assert.equal(existsSync(back), false, 'unauthenticated requests must not reach upstream');
    assert.equal(existsSync(front), false, 'unauthenticated requests must not create accepted witnesses');
    const response = await fetch(url, { method: 'POST', body,
      headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` } });
    assert.equal(response.status, 200);
    const reply = await response.json();
    assert.equal(reply.id, 'auth-check');
    assert.equal(reply.result.content[0].text, 'actual upstream response');
    const upstream = readFileSync(back, 'utf8');
    const accepted = readFileSync(front, 'utf8');
    assert.ok(upstream.includes('http-client->server'));
    assert.equal(upstream.includes(bearer), false);
    assert.equal(accepted.includes(bearer), false);
    const rows = upstream.trim().split('\n').map(JSON.parse).filter((row) => row.direction === 'http-client->server');
    assert.ok(rows.length > 0);
    assert.ok(rows.every((row) => row.credentialMatches === 0 && row.payload.id !== 'auth-check'));
  } finally {
    await new Promise((done) => {
      if (child.exitCode !== null || child.signalCode !== null) { done(); return; }
      const timer = setTimeout(() => { child.kill('SIGKILL'); done(); }, 2500);
      child.once('close', () => { clearTimeout(timer); done(); });
      child.kill('SIGTERM');
    });
    rmSync(dir, { recursive: true, force: true });
  }
});
