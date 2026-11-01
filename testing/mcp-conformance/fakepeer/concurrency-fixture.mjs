// Controlled MCP server for observable cancellation and subscription stimuli.
// No sleeps: held work completes only when cancelled or explicitly released.
import { createInterface } from 'node:readline';
import { REVISION } from '../src/core/spec.mjs';
import { SUBSCRIPTION_ID_KEY, PROTOCOL_VERSION_KEY, CLIENT_CAPS_KEY } from '../src/core/jsonrpc.mjs';

const mode = process.argv[2] || 'honest';
const modes = new Set(['honest', 'reply-after-cancel', 'progress-after-cancel',
  'filter-leak', 'subscription-progress', 'subscription-log', 'publisher-error', 'exit-on-request']);
if (!modes.has(mode)) {
  process.stderr.write(`unknown concurrency fixture mode ${mode}\n`);
  process.exit(2);
}
const subscriptions = new Map();
const pending = new Map();
let lastWork = null;
const out = (message) => process.stdout.write(JSON.stringify(message) + '\n');
const ok = (id, result) => out({ jsonrpc: '2.0', id, result: { resultType: 'complete', ...result } });
const error = (id, code, message) => out({ jsonrpc: '2.0', id, error: { code, message } });
const progress = (token, value) => out({ jsonrpc: '2.0', method: 'notifications/progress',
  params: { progressToken: token, progress: value, total: 1 } });
const tools = ['hold', 'release', 'publish_resource'].map((name) => ({
  name, description: `Controlled ${name} operation.`, inputSchema: { type: 'object' },
}));

function startWork(id, token) {
  let finish;
  const completion = new Promise((resolve) => { finish = resolve; });
  const work = { id, token, finish, started: true, cancelSeen: false, completed: false };
  pending.set(id, work);
  lastWork = work;
  work.done = completion.then((cancelled) => {
    if (!cancelled || mode === 'reply-after-cancel') {
      ok(id, { content: [{ type: 'text', text: 'held work finished' }], isError: false });
    }
    if (cancelled && mode === 'progress-after-cancel') progress(token, 1);
    work.completed = true;
    pending.delete(id);
  });
  progress(token, 0);
}

async function handle(message) {
  if (message?.method === 'notifications/cancelled' && message.id === undefined) {
    const work = pending.get(message.params?.requestId);
    if (work) {
      work.cancelSeen = true;
      work.finish(true);
      await work.done;
    }
    subscriptions.delete(message.params?.requestId);
    return;
  }
  if (!message || typeof message !== 'object' || Array.isArray(message)) {
    error(null, -32600, 'Invalid Request');
    return;
  }
  if (message.id === undefined) return;
  if (mode === 'exit-on-request') { process.exit(0); return; }
  const { id, method, params } = message;
  const meta = params?._meta;
  if (meta?.[PROTOCOL_VERSION_KEY] !== REVISION || !meta?.[CLIENT_CAPS_KEY]) {
    error(id, -32602, 'Invalid params: missing modern metadata');
    return;
  }
  if (method === 'server/discover') {
    ok(id, { supportedVersions: [REVISION],
      capabilities: { tools: { listChanged: true }, resources: { subscribe: true } } });
  } else if (method === 'tools/list') {
    ok(id, { tools });
  } else if (method === 'subscriptions/listen') {
    subscriptions.set(id, params.notifications || {});
    out({ jsonrpc: '2.0', method: 'notifications/subscriptions/acknowledged',
      params: { _meta: { [SUBSCRIPTION_ID_KEY]: id }, notifications: params.notifications || {} } });
  } else if (method === 'tools/call' && params.name === 'hold') {
    startWork(id, meta.progressToken);
  } else if (method === 'tools/call' && params.name === 'release') {
    if (!lastWork) { error(id, -32602, 'No held work was started'); return; }
    lastWork.finish(false);
    await lastWork.done;
    ok(id, { content: [{ type: 'text', text: 'joined held work' }], isError: false,
      structuredContent: { started: lastWork.started, cancelSeen: lastWork.cancelSeen,
        completed: lastWork.completed, active: pending.has(lastWork.id) } });
  } else if (method === 'tools/call' && params.name === 'publish_resource') {
    if (mode === 'publisher-error') {
      ok(id, { content: [{ type: 'text', text: 'publisher failed' }], isError: true });
      return;
    }
    const uri = params.arguments?.uri;
    for (const [subscriptionId, filter] of subscriptions) {
      if (filter.resourceSubscriptions?.includes(uri) || mode === 'filter-leak') {
        out({ jsonrpc: '2.0', method: 'notifications/resources/updated',
          params: { uri, _meta: { [SUBSCRIPTION_ID_KEY]: subscriptionId } } });
      }
      if (filter.toolsListChanged && ['subscription-progress', 'subscription-log'].includes(mode)) {
        out({ jsonrpc: '2.0', method: mode === 'subscription-progress'
          ? 'notifications/progress' : 'notifications/message',
        params: { progressToken: 'unrelated', progress: 1, level: 'info', data: 'leaked',
          _meta: { [SUBSCRIPTION_ID_KEY]: subscriptionId } } });
      }
    }
    ok(id, { content: [{ type: 'text', text: 'resource update published' }], isError: false });
  } else if (method === 'tools/call') {
    error(id, -32602, 'Unknown tool');
  } else {
    error(id, -32601, 'Method not found');
  }
}

let handlers = Promise.resolve();
const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
input.on('line', (line) => {
  handlers = handlers.then(async () => {
    let message;
    try { message = JSON.parse(line); } catch { error(null, -32700, 'Parse error'); return; }
    await handle(message);
  }).catch((cause) => {
    process.stderr.write(`concurrency fixture failure: ${cause.message}\n`);
    process.exitCode = 1;
    input.close();
  });
});
input.on('close', () => {
  handlers.finally(() => {
    for (const work of pending.values()) work.finish(true);
  });
});
