// Protocol fixtures for the transport adapter's actual pipe and HTTP boundaries.
import { createInterface } from 'node:readline';
const mode = process.argv[2];
let rest = null;
createInterface({ input: process.stdin }).on('line', (line) => {
  const message = JSON.parse(line);
  if (mode === 'split' && rest === null) {
    const bytes = Buffer.from(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { text: '雪' } }) + '\n');
    const at = bytes.indexOf(Buffer.from('雪')) + 1;
    rest = bytes.subarray(at);
    process.stdout.write(bytes.subarray(0, at));
  } else if (mode === 'split') {
    process.stdout.write(rest, () => process.exit(0));
  } else if (mode === 'args') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { args: process.argv.slice(3) } }) + '\n');
  } else if (mode === 'final') {
    process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { final: true } }), () => process.exit(0));
  } else {
    process.stderr.write(`unknown fixture mode ${mode}\n`);
    process.exit(2);
  }
});
