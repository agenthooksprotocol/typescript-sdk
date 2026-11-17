import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { auth, AuthError } from 'agenthooksprotocol/client';
import { classifyAuthError } from '../dist/src/client/auth.js';

const context = { backendId: 'backend', purpose: 'event', url: 'https://receiver.example/events',
  authentication: { type: 'bearer', tokenRef: 'secret' } };
const vectors = JSON.parse(readFileSync(new URL('../testdata/sdk-auth-lifecycle.json', import.meta.url), 'utf8'));
const recoveries = Object.fromEntries(vectors.recovery.map(({ code, recovery }) => [code, recovery]));

for (const [code, recovery] of Object.entries(recoveries)) {
  test(`foreign provider ${code} is structurally classified and redacted`, async () => {
    const foreign = vm.runInNewContext(`Object.assign(new Error('SECRET'), { code: ${JSON.stringify(code)}, recovery: 'forged', cause: new Error('SECRET') })`);
    for (const phase of ['credential', 'challenge']) {
      const provider = { credential() { if (phase === 'credential') throw foreign; return { type: 'bearer', token: 'token' }; },
        challenge() { throw foreign; } };
      const composed = auth.compose({ bearer: provider });
      const credential = phase === 'challenge' ? await composed.credential(context) : undefined;
      await assert.rejects(phase === 'credential' ? composed.credential(context)
        : composed.challenge({ ...context, credential, response: new Response(null, { status: 401 }) }), error => {
        assert.ok(error instanceof AuthError);
        assert.equal(error.code, code);
        assert.equal(error.recovery, recovery);
        assert.equal(error.cause, undefined);
        assert.doesNotMatch(String(error), /SECRET/);
        return true;
      });
    }
  });
}

test('hostile error accessors and unallowlisted codes fail closed', () => {
  for (const error of [{ code: '__proto__' }, { code: 'access_token' }, Object.create(null, { code: { get() { throw new Error('SECRET'); } } }), Object.create(new Error(), { name: { get() { throw new Error('SECRET'); } } })]) {
    assert.equal(classifyAuthError(error).code, 'provider_failed');
  }
});

test('only the caller signal keeps native cancellation identity; provider aborts are operational', () => {
  for (const name of ['AbortError', 'TimeoutError']) {
    const reason = new DOMException('cancelled', name);
    assert.equal(classifyAuthError(reason).code, 'provider_failed');
    const controller = new AbortController();
    controller.abort(reason);
    assert.throws(() => classifyAuthError(new Error('provider'), 'provider_failed', controller.signal), error => error === reason);
  }
});

test('unbound preemptive credentials are optional but never fall back to another identity', async () => {
  let calls = 0;
  const composed = auth.compose({ discover: { credential() { calls++; return calls === 1 ? undefined : { type: 'bearer', token: 'cached' }; }, challenge() {} },
    bearer: { credential() { assert.fail('must not switch identity'); }, challenge() {} } });
  const { authentication: _, ...unbound } = context;
  assert.equal(await composed.credential(unbound), undefined);
  assert.equal((await composed.credential(unbound)).token, 'cached');
  const broken = auth.compose({ discover: { credential() { throw { code: 'credential_unavailable' }; }, challenge() {} } });
  await assert.rejects(broken.credential(unbound), { code: 'credential_unavailable' });
});
