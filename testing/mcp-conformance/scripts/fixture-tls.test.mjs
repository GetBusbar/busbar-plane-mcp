import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash, X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const setup = fileURLToPath(new URL('../mcp-subject/fixture-tls.sh', import.meta.url));
const factory = new URL('../mcp-subject/fixture-server.mjs', import.meta.url).href;

async function material(dir) {
  // Execute the real setup helper only when this regression is explicitly run.
  const child = spawn('bash', ['-c', 'source "$1"; mcp_fixture_prepare_tls "$2" || exit; printf "%s\\n" "$MCP_FIXTURE_KEY_PIN"', 'fixture-tls', setup, dir]);
  let output = '', errors = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { errors += chunk; });
  const [code] = await once(child, 'close');
  assert.equal(code, 0, errors);
  return { ca: readFileSync(join(dir, 'ca.pem')), cert: join(dir, 'leaf.pem'), key: join(dir, 'leaf.key'), pin: output.trim() };
}

function get(port, ca, servername = 'localhost') {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, ca, servername, agent: false }, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve(body));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.setTimeout(3000, () => req.destroy(new Error('fixture TLS request timed out')));
    req.end();
  });
}

test('fixture TLS uses the actual SPKI and retains chain and name verification', { timeout: 30000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-fixture-tls-'));
  let server;
  try {
    const first = await material(join(dir, 'first'));
    const other = await material(join(dir, 'other'));
    const certificate = new X509Certificate(readFileSync(first.cert));
    const spki = certificate.publicKey.export({ type: 'spki', format: 'der' });
    assert.equal(first.pin, `sha256/${createHash('sha256').update(spki).digest('base64')}`);
    assert.notEqual(first.pin, other.pin);
    assert.equal(statSync(first.key).mode & 0o077, 0, 'ephemeral private key must not be group/world readable');
    server = spawn(process.execPath, ['--input-type=module', '-e', `
      import { createServer } from ${JSON.stringify(factory)};
      const server = createServer((_req, res) => res.end('fixture TLS'));
      server.listen(0, '127.0.0.1', () => console.log(server.address().port));
    `], { env: { ...process.env, MCP_FIXTURE_TLS_CERT: first.cert, MCP_FIXTURE_TLS_KEY: first.key } });
    let output = '';
    const port = await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.once('exit', (code) => reject(new Error(`TLS fixture exited ${code}`)));
      server.stdout.on('data', (chunk) => {
        output += chunk;
        if (output.includes('\n')) resolve(Number(output.trim()));
      });
    });
    assert.equal(await get(port, first.ca), 'fixture TLS');
    await assert.rejects(get(port, other.ca), /certificate|issuer|verify/i);
    await assert.rejects(get(port, first.ca, 'not-localhost.invalid'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' });
  } finally {
    if (server && server.exitCode === null && server.signalCode === null) {
      const closed = once(server, 'close');
      server.kill('SIGTERM');
      await closed;
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
