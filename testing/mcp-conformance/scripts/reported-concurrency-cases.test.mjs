import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { Target } from '../src/core/target.mjs';
import { allTests, runOne } from '../src/core/runner.mjs';
import '../src/suites/server-concurrency.mjs';

const fixture = fileURLToPath(new URL('../fakepeer/concurrency-fixture.mjs', import.meta.url));
const uri = 'fixture://resource/one';
const cancellationProbe = {
  call: { name: 'hold', arguments: {} },
  release: { name: 'release', arguments: {} },
};
const subscriptionProbe = {
  uri, publish: { name: 'publish_resource', arguments: { uri } },
};

async function exercise(id, mode, descriptors = {}) {
  const target = new Target({
    name: `controlled-concurrency-${mode}`,
    serverLaunch: `${JSON.stringify(process.execPath)} ${JSON.stringify(fixture)} ${mode}`,
  });
  // These tools exist on this controlled target. Ordinary targets are never
  // presumed to implement a hold, release, or event-publication tool.
  Object.assign(target, descriptors);
  const scenario = allTests().find((entry) => entry.id === id);
  assert.ok(scenario);
  return runOne(scenario, target);
}

test('cancellation observes started work, then joins the cancelled operation without a reply', async () => {
  const result = await exercise('CONC.CANCEL-STOPS-RESPONSE', 'honest', { cancellationProbe });
  assert.equal(result.verdict, 'PASS', JSON.stringify(result));
  const started = result.notes.find((entry) => entry.key === 'cancel.startedProgress')?.value;
  assert.equal(started?.params?.progressToken, 'cancel-started-progress');
  const release = result.notes.find((entry) => entry.key === 'cancel.release')?.value;
  assert.deepEqual(release?.result?.structuredContent,
    { started: true, cancelSeen: true, completed: true, active: false });
});

for (const mode of ['reply-after-cancel', 'progress-after-cancel']) {
  test(`cancellation rejects ${mode} after the observed start`, async () => {
    const result = await exercise('CONC.CANCEL-STOPS-RESPONSE', mode, { cancellationProbe });
    assert.equal(result.verdict, 'FAIL', JSON.stringify(result));
    assert.ok(result.assertions.some((entry) => entry.clause === 'CANCEL.NO-FURTHER-MESSAGES'
      && !entry.ok));
    const release = result.notes.find((entry) => entry.key === 'cancel.release')?.value;
    assert.equal(release?.result?.structuredContent?.cancelSeen, true);
  });
}

test('a failed release cannot stand in for an observed cancellation completion', async () => {
  const result = await exercise('CONC.CANCEL-STOPS-RESPONSE', 'honest', {
    cancellationProbe: { ...cancellationProbe, release: { name: 'not_a_release', arguments: {} } },
  });
  assert.equal(result.verdict, 'ERROR', JSON.stringify(result));
  assert.match(result.error, /did not establish completion/);
});

test('a published resource update reaches its requested stream and stays off the tools stream', async () => {
  const result = await exercise('CONC.SUBSCRIPTION-NO-UNREQUESTED-TYPES', 'honest', { subscriptionProbe });
  assert.equal(result.verdict, 'PASS', JSON.stringify(result));
  const delivered = result.notes.find((entry) => entry.key === 'subscriptions.deliveredControlEvent')?.value;
  assert.equal(delivered?.params?.uri, uri);
  assert.equal(delivered?.params?._meta?.['io.modelcontextprotocol/subscriptionId'], 61);
});

for (const mode of ['filter-leak', 'subscription-progress', 'subscription-log']) {
  test(`subscription filtering rejects ${mode} while a real resource event is delivered`, async () => {
    const result = await exercise('CONC.SUBSCRIPTION-NO-UNREQUESTED-TYPES', mode, { subscriptionProbe });
    assert.equal(result.verdict, 'FAIL', JSON.stringify(result));
    assert.ok(result.notes.some((entry) => entry.key === 'subscriptions.deliveredControlEvent'));
    assert.ok(result.assertions.some((entry) => entry.clause === 'SUB.NO-UNREQUESTED-TYPES' && !entry.ok));
  });
}

test('an unavailable publisher produces no subscription-filtering pass', async () => {
  const result = await exercise('CONC.SUBSCRIPTION-NO-UNREQUESTED-TYPES', 'publisher-error', { subscriptionProbe });
  assert.equal(result.verdict, 'ERROR', JSON.stringify(result));
  assert.match(result.error, /did not establish publication/);
});

test('the ordinary cancellation path reports its narrower race observation', async () => {
  const result = await exercise('CONC.CANCEL-STOPS-RESPONSE', 'honest');
  assert.equal(result.verdict, 'PASS', JSON.stringify(result));
  assert.ok(result.notes.some((entry) => entry.key === 'cancel.startedWorkCoverage'));
  assert.equal(result.notes.some((entry) => entry.key === 'cancel.startedProgress'), false);
});

test('the no-server-cancellation check accepts answered unsupported methods', async () => {
  const result = await exercise('CONC.SERVER-CANCELLED-ONLY-FOR-SUBSCRIPTIONS', 'honest');
  assert.equal(result.verdict, 'PASS', JSON.stringify(result));
});

test('the no-server-cancellation check refuses a peer that exits before answering', async () => {
  const result = await exercise('CONC.SERVER-CANCELLED-ONLY-FOR-SUBSCRIPTIONS', 'exit-on-request');
  assert.notEqual(result.verdict, 'PASS', JSON.stringify(result));
  assert.ok(result.assertions.some((entry) => entry.clause === 'BASE.RES.ID-MATCHES' && !entry.ok));
});
