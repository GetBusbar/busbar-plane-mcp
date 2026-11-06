// Trusted fixture-operator action. Never loaded by the untrusted diagnostic peer.
// Mutate the actual operator catalogue and ask the product to reload it. Only
// the product's subscription implementation may generate list_changed frames.
import { readFileSync, writeFileSync, renameSync, appendFileSync } from 'node:fs';

export const MUTATIONS = new Map([
  ['test_trigger_tool_change', { before: 'Returns a single text content block.', kind: 'tools' }],
  ['test_trigger_prompt_change', { before: 'A simple prompt for testing.', kind: 'prompts' }],
]);

export function operatorMutation({ config, adminPort, token, receipt, reload }) {
  let tail = Promise.resolve();
  let sequence = 0;
  const current = new Map();
  const performReload = reload || (async () => {
    const response = await fetch(`http://127.0.0.1:${adminPort}/api/v1/admin/config/reload`, {
      method: 'POST', headers: { authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(10000),
    });
    const result = await response.json();
    if (!response.ok || result.reloaded !== true || result.reload_to_apply?.length) {
      const error = new Error(`operator reload failed: HTTP ${response.status}; code=${result.error?.code || ''}; Retry-After=${response.headers.get('retry-after') || ''}; reload acknowledged=${result.reloaded === true}; restart required=${Boolean(result.reload_to_apply?.length)}`);
      error.observation = { http_status: response.status, code: result.error?.code, retry_after: response.headers.get('retry-after'), reloaded: result.reloaded, reload_to_apply: result.reload_to_apply };
      throw error;
    }
    return result;
  });
  return (name) => {
    const change = MUTATIONS.get(name);
    if (!change) return Promise.resolve(false);
    const work = tail.then(async () => {
      const before = current.get(name) || change.before;
      const after = `${change.before} Operator revision ${++sequence}.`;
      const text = readFileSync(config, 'utf8');
      const needle = `description: "${before}"`;
      if (text.split(needle).length !== 2) throw new Error(`operator mutation needs exactly one ${change.kind} description`);
      const next = text.replace(needle, `description: "${after}"`);
      const temp = `${config}.mutation`;
      writeFileSync(temp, next, { mode: 0o600 });
      renameSync(temp, config);
      let result;
      try { result = await performReload(); }
      catch (error) {
        writeFileSync(temp, text, { mode: 0o600 });
        renameSync(temp, config);
        if (receipt) appendFileSync(receipt, JSON.stringify({ kind: change.kind, outcome: 'failed', timestamp: new Date().toISOString(), error: error.message, observation: error.observation }) + '\n', { mode: 0o600 });
        throw error;
      }
      current.set(name, after);
      if (receipt) appendFileSync(receipt, JSON.stringify({ kind: change.kind, outcome: 'applied', timestamp: new Date().toISOString(),
        config_version: result.config_version, description_before: before, description_after: after,
      }) + '\n', { mode: 0o600 });
      return true;
    });
    tail = work.catch(() => {});
    return work;
  };
}
