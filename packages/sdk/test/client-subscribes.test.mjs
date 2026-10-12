import test from 'node:test';
import assert from 'node:assert/strict';
import { Hooks, ContentManager } from 'agenthooksprotocol/client';

const capabilities = {
  toolBefore: {intercept: {deny: true}},
  toolAfter: {observe: true},
  sessionEnd: {observe: true},
};
const subscription = (events, mode = 'intercept', extras = {}) => ({
  events, mode, content: { default: 'metadata' },
  ...(mode === 'intercept' ? { timeoutMs: 1000, failurePolicy: 'fail-open' } : {}),
  ...extras,
});
function client(subscriptions, options = {}) {
  return new Hooks({ protocolVersion: 'draft', hooks: subscriptions.length ? [{
    id: 'interest.backend',
    transport: { type: 'stdio', command: 'must-not-start-subscription-lookup', lifecycle: 'per_event' },
    subscriptions,
  }] : [] }, { source: 'urn:test:interest', capabilities, ...options });
}

for (const [name, subscriptions, event, expected] of [
  ['no subscribers', [], 'tool.before', false],
  ['unrelated selectors', [subscription(['session.end'], 'observe')], 'tool.before', false],
  ['exact intercept', [subscription(['tool.before'])], 'tool.before', true],
  ['exact observation', [subscription(['tool.after'], 'observe')], 'tool.after', true],
  ['family wildcard', [subscription(['tool.*'])], 'tool.before', true],
  ['family observation', [subscription(['tool.*'], 'observe')], 'tool.after', true],
  ['global wildcard', [subscription(['*'])], 'tool.before', true],
  ['host-mode ineligible intercept', [subscription(['tool.*'])], 'tool.after', false],
  ['host-mode ineligible observation', [subscription(['tool.*'], 'observe')], 'tool.before', false],
  ['unknown event', [subscription(['*'])], 'future.event', false],
  ['unconfigured catalogue event', [subscription(['*'])], 'session.start', false],
  ['filtered match is conservative', [subscription(['tool.before'], 'intercept', { filters: { paths: ['other'], toolKinds: ['other'] } })], 'tool.before', true],
]) {
  test(`subscribes: ${name}`, async () => {
    const hooks = client(subscriptions);
    try {
      // No initialization await or occurrence input is needed for static interest.
      assert.equal(hooks.subscribes(event), expected);
      if (subscriptions.length === 0) {
        // Canonical registration requires a backend; an empty configuration has
        // no validated interest and retains its asynchronous configuration error.
        await assert.rejects(hooks.initialized, { name: "ConfigurationError" });
      } else await hooks.initialized;
      assert.equal(hooks.subscribes(event), expected);
    } finally { await hooks.close(); }
  });
}

test('subscribes performs no preparation, transport, authentication, or mutation', async () => {
  let preparation = 0, network = 0, credentials = 0;
  const original = ContentManager.prototype.prepare;
  ContentManager.prototype.prepare = function () { preparation++; throw Error('preparation forbidden'); };
  const hooks = client([subscription(['*'], 'observe')], {
    fetch: async () => { network++; throw Error('network forbidden'); },
    auth: { credential: async () => { credentials++; throw Error('auth forbidden'); } },
  });
  try {
    for (let index = 0; index < 3; index++) {
      assert.equal(hooks.subscribes('tool.after'), true);
      assert.equal(hooks.subscribes('tool.before'), false);
      assert.equal(hooks.subscribes('future.event'), false);
    }
    assert.deepEqual([preparation, network, credentials], [0, 0, 0]);
    assert.equal(hooks.subscribes('tool.after'), true);
  } finally { ContentManager.prototype.prepare = original; await hooks.close(); }
});

test('invalid configuration is not partially exposed as subscription interest', async () => {
  const hooks = new Hooks({ protocolVersion: 'draft', hooks: [] }, { source: '', capabilities });
  assert.equal(hooks.subscribes('future.event'), false);
  await assert.rejects(hooks.initialized, { name: 'ConfigurationError' });
  await hooks.close();
});
