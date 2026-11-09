// SUBJECT ACTS AS MCP SERVER. Area: stateful and concurrent behaviour.
//
// Note on ordering: the spec nowhere requires responses to arrive in request
// order. Out-of-order completion is LEGAL. So ordering is a variance point,
// never an assertion. What IS assertable is that every id is answered exactly
// once and no id is invented.

import { test } from '../core/runner.mjs';
import { request, notification, ERR, SUBSCRIPTION_ID_KEY } from '../core/jsonrpc.mjs';

async function withServer(ctx, fn) {
  const peer = ctx.target.spawnServer();
  try { return await fn(peer); } finally { await peer.stop(); }
}

// Optional adapter probes describe work and event publishers that the target
// actually provides. They are not MCP methods every server must implement.
// The focused controlled-peer cases supply these descriptors; the ordinary
// target never gains a claimed started-work or event-publication observation.
export async function probeStartedCancellation(ctx, peer, probe) {
  const id = 'cancel-started';
  const progressToken = 'cancel-started-progress';
  peer.send(request(id, 'tools/call', probe.call, { progressToken }));
  const started = await peer.waitFor((m) => m?.method === 'notifications/progress'
    && m.params?.progressToken === progressToken, 'progress from the held request');
  ctx.note('cancel.startedProgress', started);
  if (peer.responsesFor(id).length !== 0) {
    throw new Error('the held work completed before cancellation; started-work coverage was not established');
  }
  const afterStart = peer.messages.length;
  peer.send(notification('notifications/cancelled', { requestId: id }));
  // The adapter's release tool joins the held work and reports only after the
  // cancel/release handlers have run. A discovery reply alone cannot do this.
  peer.send(request('cancel-release', 'tools/call', probe.release));
  const released = await peer.waitForId('cancel-release');
  ctx.note('cancel.release', released);
  if (!released.result || released.result.isError) {
    throw new Error('the held-work release tool did not establish completion');
  }
  const afterCancel = peer.messages.slice(afterStart).filter((m) => m
    && (m.id === id || (m.method === 'notifications/progress'
      && m.params?.progressToken === progressToken)));
  ctx.assert('CANCEL.NO-FURTHER-MESSAGES', afterCancel.length === 0,
    `held request emitted messages after cancellation: ${JSON.stringify(afterCancel)}`);
}

function assertRequestedSubscriptionTypes(ctx, messages, id) {
  const onSubscription = messages.filter((m) => m?.method?.startsWith('notifications/')
    && m.params?._meta?.[SUBSCRIPTION_ID_KEY] === id);
  const allowed = new Set([
    'notifications/subscriptions/acknowledged',
    'notifications/tools/list_changed',
  ]);
  const unrequested = onSubscription.filter((m) => !allowed.has(m.method));
  ctx.assert('SUB.NO-UNREQUESTED-TYPES', unrequested.length === 0,
    `unrequested types on subscription ${id}: ${JSON.stringify(unrequested)}`);
}

export async function probePublishedSubscription(ctx, peer, probe) {
  // The second stream is the positive delivery control: publishing a resource
  // update must be observable there, but must not leak to the tools-only stream.
  peer.send(request(61, 'subscriptions/listen', {
    notifications: { resourceSubscriptions: [probe.uri] },
  }));
  await peer.waitFor((m) => m?.method === 'notifications/subscriptions/acknowledged'
    && m.params?._meta?.[SUBSCRIPTION_ID_KEY] === 61, 'resource subscription acknowledgement');
  peer.send(request('subscription-publish', 'tools/call', probe.publish));
  const published = await peer.waitForId('subscription-publish');
  ctx.note('subscriptions.publisherReply', published);
  if (!published.result || published.result.isError) {
    throw new Error('the event-publisher tool did not establish publication');
  }
  const delivered = await peer.waitFor((m) => m?.method === 'notifications/resources/updated'
    && m.params?.uri === probe.uri
    && m.params?._meta?.[SUBSCRIPTION_ID_KEY] === 61, 'published resource update on its requested stream');
  ctx.note('subscriptions.deliveredControlEvent', delivered);
  if (peer.responsesFor(60).length || peer.messages.some((m) => m?.method === 'notifications/cancelled'
    && m.params?.requestId === 60)) {
    throw new Error('the tools-only subscription ended before the publication observation');
  }
  const subscriptionEvents = peer.messages.filter((m) => m?.method?.startsWith('notifications/')
    && ['notifications/subscriptions/acknowledged', 'notifications/tools/list_changed',
      'notifications/prompts/list_changed', 'notifications/resources/list_changed',
      'notifications/resources/updated'].includes(m.method));
  for (const event of subscriptionEvents) {
    ctx.assert('SUB.ID-ON-EVERY-NOTIFICATION',
      event.params?._meta?.[SUBSCRIPTION_ID_KEY] !== undefined,
      `subscription notification lacks its subscription id: ${JSON.stringify(event)}`);
  }
  assertRequestedSubscriptionTypes(ctx, peer.messages, 60);
}

test({
  id: 'CONC.INTERLEAVED-REQUESTS',
  title: 'many interleaved requests are each answered exactly once',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'A dispatcher that drops or double-answers a request under pipelining, the classic single-slot response bug.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const N = 25;
    const ids = [];
    for (let i = 0; i < N; i++) {
      const id = `c-${i}`;
      ids.push(id);
      peer.send(request(id, i % 2 === 0 ? 'server/discover' : 'tools/list'));
    }
    // Deterministic barrier: wait for every id, not for a duration.
    for (const id of ids) await peer.waitForId(id, 20000);

    const counts = new Map();
    for (const m of peer.messages) {
      if (m && m.id !== undefined && ('result' in m || 'error' in m)) {
        counts.set(m.id, (counts.get(m.id) || 0) + 1);
      }
    }
    const doubled = ids.filter((id) => (counts.get(id) || 0) > 1);
    const missing = ids.filter((id) => !counts.has(id));
    const invented = [...counts.keys()].filter((id) => !ids.includes(id));

    ctx.assert('BASE.RES.ID-MATCHES', doubled.length === 0, `answered more than once: ${doubled}`);
    ctx.assert('BASE.RES.ID-MATCHES', missing.length === 0, `never answered: ${missing}`);
    ctx.assert('BASE.RES.ID-MATCHES', invented.length === 0, `responses to ids never sent: ${invented}`);

    // Ordering is legal either way. Record it so the differential run shows
    // control-ordered vs subject-reordered without failing anyone.
    const order = peer.messages
      .filter((m) => m && ids.includes(m.id))
      .map((m) => m.id);
    ctx.variance('interleaved.responsesInRequestOrder',
      JSON.stringify(order) === JSON.stringify(ids));
  }),
});

test({
  id: 'CONC.ID-TYPES',
  title: 'string, integer and unusual-but-legal ids are all correlated correctly',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'An id compared with == or coerced to string, so request 1 and request "1" collide and cross-deliver.',
  run: (ctx) => withServer(ctx, async (peer) => {
    // 1 and "1" are DIFFERENT ids in JSON-RPC. A server that stringifies its
    // id table will cross-deliver these two.
    peer.send(request(1, 'server/discover'));
    peer.send(request('1', 'this/method/does/not/exist'));
    peer.send(request(0, 'server/discover'));
    peer.send(request(-7, 'server/discover'));
    peer.send(request('', 'server/discover'));

    const wanted = [1, '1', 0, -7, ''];
    for (const id of wanted) {
      try {
        await peer.waitForId(id, 8000);
      } catch (error) {
        ctx.assert('BASE.RES.ID-MATCHES', false,
          `waiting for ${typeof id} id ${JSON.stringify(id)} failed: ${error.message}`);
      }
    }
    for (const id of wanted) {
      const replies = peer.messages.filter((m) => m
        && typeof m.id === typeof id && m.id === id
        && ('result' in m || 'error' in m));
      ctx.assert('BASE.RES.ID-MATCHES', replies.length === 1,
        `id ${JSON.stringify(id)} (${typeof id}) answered ${replies.length} times`);
      ctx.variance(`idTypes.${typeof id}.${JSON.stringify(id)}.answered`, replies.length === 1);
      if (id !== '1') {
        ctx.assert('VER.DISCOVER-REQUIRED',
          Array.isArray(replies[0]?.result?.supportedVersions),
          `discovery for ${typeof id} id ${JSON.stringify(id)} did not return supportedVersions`);
      }
    }
    const invented = peer.messages.filter((m) => m && ('result' in m || 'error' in m)
      && !wanted.some((id) => typeof m.id === typeof id && m.id === id));
    ctx.assert('BASE.RES.ID-MATCHES', invented.length === 0,
      `responses to ids never sent: ${JSON.stringify(invented)}`);
    // Discovery and an unknown method have distinguishable answers even on a
    // server with no tools capability. Swapping them must fail correlation.
    const intOne = peer.responsesFor(1)[0];
    const strOne = peer.responsesFor('1')[0];
    ctx.assert('BASE.RES.ID-MATCHES',
      Array.isArray(intOne?.result?.supportedVersions)
        && strOne?.error?.code === ERR.METHOD_NOT_FOUND && !('result' in strOne),
      'integer id 1 must carry discovery and string id "1" must carry Method not found');
  }),
});

test({
  id: 'CONC.NULL-ID-REJECTED',
  title: 'a request with id null is not treated as a valid request',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'Accepting id:null, which MCP forbids, producing responses no client can correlate.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.sendRaw('{"jsonrpc":"2.0","id":null,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}\n');
    peer.send(request('after-null', 'server/discover'));
    await peer.waitForId('after-null');
    const nullReplies = peer.messages.filter((m) => m && m.id === null && 'result' in m);
    // The spec forbids the CLIENT from sending id:null. It does not state the
    // server's obligation. A successful RESULT for id:null is the bad outcome,
    // because no client can match it; an error reply is fine, silence is fine.
    ctx.assert('BASE.REQ.ID-NOT-NULL', nullReplies.length === 0,
      'server returned a success result for a null id, which is uncorrelatable');
    ctx.variance('nullId.replyKind',
      peer.messages.some((m) => m && m.id === null && m.error) ? 'error'
        : nullReplies.length ? 'result' : 'none');
  }),
});

test({
  id: 'CONC.CANCEL-STOPS-RESPONSE',
  title: 'a request raced with cancellation receives at most one response',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake', timing: true,
  catches: 'A request raced with cancellation is answered twice; this does not establish that cancellation stopped in-progress work.',
  run: (ctx) => withServer(ctx, async (peer) => {
    if (!ctx.target.cancellationProbe) {
      ctx.note('cancel.startedWorkCoverage',
        'No held-work adapter is configured; this path measures only a completion/cancellation race.');
    }
    peer.send(request('cancelme', 'tools/list'));
    peer.send(notification('notifications/cancelled', { requestId: 'cancelme' }));
    // A later discovery answer establishes liveness after the cancellation.
    // Concurrent dispatch may still leave the earlier request in progress.
    peer.send(request('barrier', 'server/discover'));
    await peer.waitForId('barrier');
    await peer.quiesce(300);
    const replies = peer.responsesFor('cancelme');
    ctx.assert('CANCEL.NO-FURTHER-MESSAGES', replies.length <= 1,
      `cancelled request produced ${replies.length} responses`);
    // Both 0 and 1 are legal: the spec permits ignoring a cancellation that
    // arrives after completion.
    ctx.variance('cancel.responseCount', replies.length);
    if (ctx.target.cancellationProbe) {
      await probeStartedCancellation(ctx, peer, ctx.target.cancellationProbe);
    }
  }),
});

test({
  id: 'CONC.SERVER-CANCELLED-ONLY-FOR-SUBSCRIPTIONS',
  title: 'the server never sends notifications/cancelled outside a subscription teardown',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'fake',
  catches: 'A server reusing notifications/cancelled as a generic abort signal, which the 2026-07-28 spec forbids.',
  run: (ctx) => withServer(ctx, async (peer) => {
    const requests = [
      [1, 'server/discover', {}],
      [2, 'tools/list', {}],
      [3, 'prompts/list', {}],
      ['c1', 'tools/call', { name: '__nope__', arguments: {} }],
    ];
    for (const [id, method, params] of requests) {
      peer.send(request(id, method, params));
      try {
        await peer.waitForId(id, 6000);
      } catch (error) {
        ctx.assert('BASE.RES.ID-MATCHES', false,
          `${method} did not answer id ${JSON.stringify(id)}: ${error.message}`);
      }
      const replies = peer.responsesFor(id);
      ctx.assert('BASE.RES.ID-MATCHES', replies.length === 1,
        `${method} answered id ${JSON.stringify(id)} ${replies.length} times`);
      for (const reply of replies) {
        if ('error' in reply) {
          ctx.assert('BASE.ERR.SHAPE',
            typeof reply.error?.message === 'string' && !('result' in reply),
            `${method} returned a malformed error: ${JSON.stringify(reply)}`);
          ctx.assert('BASE.ERR.CODE-INTEGER', Number.isInteger(reply.error?.code),
            `${method} error code=${JSON.stringify(reply.error?.code)}`);
        }
      }
    }
    const cancels = peer.messages.filter((m) => m && m.method === 'notifications/cancelled');
    ctx.assert('CANCEL.SERVER-ONLY-SUBSCRIPTIONS', cancels.length === 0,
      `server sent notifications/cancelled with no subscription open: ${JSON.stringify(cancels)}`);
  }),
});

// SUBSCRIPTIONS ARE OPTIONAL, SO THIS CLAUSE IS CONDITIONAL — AND A CONDITIONAL CLAUSE STILL HAS A
// CONTRAPOSITIVE TO ASSERT.
//
// The clause used to answer "this server offers no subscriptions" with a SKIP, and under
// MCP_NO_SKIPS=1 that is a FAILURE naming a surface nobody touched. That report was wrong about the
// subject and wrong about itself. `2026-07-28` makes subscriptions optional and the pinned suite's
// required scenario set contains no subscription scenario, so a server that declares no
// `listChanged` on any capability is VACUOUSLY SATISFYING SUB.ACK-FIRST — there is no subscription
// for an acknowledgement to be late for.
//
// But "vacuously satisfied" is a CLAIM, and it is falsifiable. A server that declares no
// subscriptions must actually not have any:
//
//   1. `subscriptions/listen` MUST be answered, and answered as a method this server does not
//      implement: a well-formed `-32601` naming the request's own id. A server that hangs, or that
//      answers a RESULT, has a subscription surface it did not declare — which is worse than
//      declaring one, because no client will ever look for it.
//   2. NOTHING may arrive on the notification channel afterwards. A `notifications/…` frame from a
//      server that just said it has no subscriptions is the exact defect SUB.ACK-FIRST exists to
//      catch, arriving with no acknowledgement at all rather than merely before one.
//
// So the test now has TWO branches and no skip, and both are real assertions. The control takes the
// declaring branch (it declares `tools.listChanged`) and busbar takes the contrapositive branch, so
// one run of the two legs exercises both halves. Nothing was weakened: every assertion below the
// declaring branch is byte-identical to what it was.
test({
  id: 'CONC.SUBSCRIPTION-ACK-FIRST',
  title: 'subscriptions/listen acknowledges before any notification, or the server has no subscriptions at all',
  role: 'server', area: 'concurrency', tier: 'pr', peer: 'real', timing: true,
  catches: 'A subscription stream that emits events before the acknowledgement, so clients cannot correlate the first events — or an UNDECLARED subscription surface, which no client will ever look for.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(1, 'server/discover'));
    const disc = await peer.waitForId(1);
    const caps = (disc.result && disc.result.capabilities) || {};
    const supportsListChanged = Object.values(caps).some((c) => c && c.listChanged);
    ctx.variance('subscriptions.declaresListChanged', supportsListChanged);
    if (!supportsListChanged) {
      // THE CONTRAPOSITIVE. Not a skip: an assertion that the declaration was true.
      peer.send(request(50, 'subscriptions/listen', {
        notifications: { toolsListChanged: true },
      }));
      let res = null;
      try { res = await peer.waitForId(50, 8000); } catch { /* asserted below */ }
      ctx.assert('BASE.ERR.SHAPE', res !== null,
        'the server declares no listChanged capability and then did not answer '
        + 'subscriptions/listen at all: an undeclared surface that also hangs');
      if (res) {
        ctx.assert('BASE.ERR.SHAPE', Boolean(res.error),
          `the server declares no listChanged capability but answered subscriptions/listen with a `
          + `RESULT: ${JSON.stringify(res.result)}`);
        if (res.error) {
          ctx.assert('BASE.ERR.SHAPE', res.error.code === ERR.METHOD_NOT_FOUND,
            `code=${res.error.code} expected ${ERR.METHOD_NOT_FOUND} (Method not found)`);
          ctx.assert('BASE.ERR.CODE-INTEGER', Number.isInteger(res.error.code));
          ctx.assert('BASE.ERR.SHAPE', typeof res.error.message === 'string',
            `message=${JSON.stringify(res.error.message)}`);
          ctx.assert('BASE.ERR.ID-MATCHES', res.id === 50, `id=${JSON.stringify(res.id)}`);
        }
      }
      // AND NO SUBSCRIPTION EVER OPENED. `quiesce` first, because a notification that arrives after
      // the error response is exactly the frame this half is looking for.
      await peer.quiesce(500);
      const stray = peer.messages.filter(
        (m) => m && typeof m.method === 'string' && m.method.startsWith('notifications/'),
      );
      ctx.assert('SUB.ACK-FIRST', stray.length === 0,
        `a server declaring no listChanged capability sent subscription-channel notifications with `
        + `no acknowledgement to correlate them to: ${JSON.stringify(stray)}`);
      ctx.variance('subscriptions.listenMethodNotFound', Boolean(res && res.error
        && res.error.code === ERR.METHOD_NOT_FOUND));
      return;
    }

    peer.send(request(50, 'subscriptions/listen', {
      notifications: { toolsListChanged: true },
    }));

    let ack = null;
    try {
      ack = await peer.waitFor(
        (m) => m && (m.method === 'notifications/subscriptions/acknowledged'
          || (m.id === 50 && ('result' in m || 'error' in m))),
        'subscription acknowledgement or terminal response', 8000, 50,
      );
    } catch (error) {
      // The server may legally answer subscriptions/listen with an error if it
      // does not support the requested filter.
      const err = peer.responsesFor(50)[0];
      ctx.variance('subscriptions.listenRejected', Boolean(err && err.error));
      if (err && err.error) ctx.skip(`server rejected subscriptions/listen: ${err.error.code}`);
      throw new Error('no acknowledgement and no error response to subscriptions/listen', { cause: error });
    }

    // An explicit rejection is legal. A success result terminating the listen
    // request before any acknowledgement is an observed protocol violation;
    // silence still follows the existing ERROR path above.
    if (ack.id === 50 && ('result' in ack || 'error' in ack)) {
      ctx.variance('subscriptions.listenRejected', Boolean(ack.error));
      if (ack.error) ctx.skip(`server rejected subscriptions/listen: ${ack.error.code}`);
      if (ack.result?.resultType === 'input_required') {
        ctx.assert('PAT.MRTR.ONLY-SUPPORTED-METHODS', false,
          'subscriptions/listen returned InputRequiredResult, which is not permitted on this method');
        return;
      }
      ctx.assert('SUB.ACK-FIRST', false,
        `subscriptions/listen returned a success result before acknowledging subscription 50; result keys=${JSON.stringify(Object.keys(ack.result || {}))}`);
      return;
    }

    const SUB_KEY = 'io.modelcontextprotocol/subscriptionId';
    ctx.assert('SUB.ACK-FIRST',
      Boolean(ack.params && ack.params._meta && ack.params._meta[SUB_KEY] !== undefined),
      `acknowledgement lacks ${SUB_KEY}: ${JSON.stringify(ack.params)}`);
    ctx.assert('SUB.ACK-FIRST',
      ack.params._meta[SUB_KEY] === 50,
      `subscriptionId=${ack.params._meta[SUB_KEY]} expected the listen request id 50`);

    // Every notification arriving before the ack on this subscription is a
    // violation. Notifications for OTHER subscriptions may interleave.
    const ackIndex = peer.messages.indexOf(ack);
    const earlyForThisSub = peer.messages.slice(0, ackIndex).filter(
      (m) => m && m.method && m.method.startsWith('notifications/')
        && m.params && m.params._meta && m.params._meta[SUB_KEY] === 50,
    );
    ctx.assert('SUB.ACK-FIRST', earlyForThisSub.length === 0,
      `notifications preceded the acknowledgement: ${JSON.stringify(earlyForThisSub)}`);

    await peer.quiesce(300);
    const onStream = peer.messages.filter(
      (m) => m && m.method && m.method.startsWith('notifications/')
        && m.method !== 'notifications/subscriptions/acknowledged',
    );
    for (const n of onStream) {
      ctx.assert('SUB.ID-ON-EVERY-NOTIFICATION',
        Boolean(n.params && n.params._meta && n.params._meta[SUB_KEY] !== undefined),
        `notification ${n.method} lacks ${SUB_KEY}`);
    }
    ctx.variance('subscriptions.acknowledgedFilter',
      ack.params && ack.params.notifications ? Object.keys(ack.params.notifications).sort() : null);
  }),
});

test({
  id: 'CONC.SUBSCRIPTION-NO-UNREQUESTED-TYPES',
  title: 'observed subscription notifications use requested types',
  role: 'server', area: 'concurrency', tier: 'prerelease', peer: 'real', timing: true,
  catches: 'Unrequested notification types observed while a tools-list subscription is open; no catalog-change stimulus is available on this target.',
  run: (ctx) => withServer(ctx, async (peer) => {
    peer.send(request(60, 'subscriptions/listen', {
      notifications: { toolsListChanged: true },
    }));
    try {
      await peer.waitFor((m) => m && m.method === 'notifications/subscriptions/acknowledged'
        && m.params?._meta?.[SUBSCRIPTION_ID_KEY] === 60,
        'ack', 8000);
    } catch {
      if (ctx.target.subscriptionProbe) {
        throw new Error('the event-publisher probe could not open its tools-only subscription');
      }
      ctx.skip('server did not acknowledge a subscriptions/listen request');
    }
    if (ctx.target.subscriptionProbe) {
      await probePublishedSubscription(ctx, peer, ctx.target.subscriptionProbe);
      return;
    }
    ctx.note('subscriptions.publishedEventCoverage',
      'No event publisher is configured; this path observes only naturally occurring notifications.');
    await peer.quiesce(600);
    const allowed = new Set([
      'notifications/subscriptions/acknowledged',
      'notifications/tools/list_changed',
      'notifications/message',
      'notifications/progress',
    ]);
    const unrequested = peer.messages
      .filter((m) => m && m.method && m.method.startsWith('notifications/'))
      .filter((m) => !allowed.has(m.method));
    ctx.assert('SUB.NO-UNREQUESTED-TYPES', unrequested.length === 0,
      `unrequested notification types: ${JSON.stringify(unrequested.map((m) => m.method))}`);
    // Progress/logging for other in-flight requests can share stdio. They are
    // not exempt when explicitly stamped onto this tools-only subscription.
    assertRequestedSubscriptionTypes(ctx, peer.messages, 60);
  }),
});
