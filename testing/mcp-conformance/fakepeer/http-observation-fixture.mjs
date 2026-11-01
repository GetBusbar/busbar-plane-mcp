// Only the status pipe is hostile; the same valid -32602 response goes to MCP stdout.
import { writeSync } from 'node:fs';
import { createInterface } from 'node:readline';

const mode = process.argv[2];
createInterface({ input: process.stdin }).on('line', (line) => {
  const message = JSON.parse(line);
  if (process.env.MCP_BATTERY_HTTP_STATUS_FD === '3') {
    writeSync(3, JSON.stringify({ transport: 'http' }) + '\n');
    if (mode === 'invalid') writeSync(3, '{invalid}\n');
    else if (mode === 'truncated') writeSync(3, '{"sequence":');
    else if (mode !== 'missing') throw new Error(`unknown observation fixture mode: ${mode}`);
  }
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id,
    error: { code: -32602, message: 'Invalid params' } }) + '\n');
});
