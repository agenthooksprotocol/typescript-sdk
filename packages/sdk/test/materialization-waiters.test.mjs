import test from 'node:test';
import assert from 'node:assert/strict';
import { Attachment } from 'agenthooksprotocol/client';

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return { promise, resolve, reject };
}

test('overlapping reads join one pending materialization and return immutable snapshots', async (t) => {
  const source = deferred();
  let opens = 0, disposes = 0;
  const attachment = Attachment.lazy(() => { opens++; return source.promise; }, () => { disposes++; });
  t.after(() => attachment.close());

  const first = attachment.read();
  const second = attachment.read();
  assert.equal(opens, 1);
  assert.equal(disposes, 0);
  const bytes = new Uint8Array([1, 2, 3]);
  source.resolve(bytes);
  const [a, b] = await Promise.all([first, second]);
  assert.deepEqual(a, bytes);
  assert.deepEqual(b, bytes);
  assert.notStrictEqual(a, b);
  bytes.fill(9);
  a.fill(0);
  assert.deepEqual(b, new Uint8Array([1, 2, 3]));
  assert.deepEqual(await attachment.read(), new Uint8Array([1, 2, 3]));
  assert.equal(opens, 1);
  assert.equal(disposes, 1);
  await attachment.close();
  assert.equal(disposes, 1);
});

test('overlapping reads join one pending failure and cache the same error', async (t) => {
  const source = deferred();
  const failure = new Error('source failed');
  let opens = 0, disposes = 0;
  const attachment = Attachment.lazy(() => { opens++; return source.promise; }, () => { disposes++; });
  t.after(() => attachment.close());

  const first = assert.rejects(attachment.read(), error => error === failure);
  const second = assert.rejects(attachment.read(), error => error === failure);
  assert.equal(opens, 1);
  assert.equal(disposes, 0);
  source.reject(failure);
  await Promise.all([first, second]);
  await assert.rejects(attachment.read(), error => error === failure);
  assert.equal(opens, 1);
  assert.equal(disposes, 1);
  await attachment.close();
  assert.equal(disposes, 1);
});

for (const outcome of ['success', 'error']) {
  test(`cancelling the first waiter preserves the remaining waiter and source ${outcome}`, async (t) => {
    const source = deferred();
    const controller = new AbortController();
    const cancellation = new Error('first waiter cancelled');
    const failure = new Error('source failed after cancellation');
    let opens = 0, disposes = 0, sourceSignal;
    const attachment = Attachment.lazy(signal => {
      opens++;
      sourceSignal = signal;
      return source.promise;
    }, () => { disposes++; });
    t.after(() => attachment.close());

    const first = assert.rejects(attachment.read(controller.signal), error => error === cancellation);
    const remaining = attachment.read();
    const remainingFailure = outcome === 'error'
      ? assert.rejects(remaining, error => error === failure) : undefined;
    assert.equal(opens, 1);
    controller.abort(cancellation);
    await first;
    assert.equal(sourceSignal.aborted, false);
    assert.equal(disposes, 0, 'a cancelled waiter must not retire the pending source');

    // A new waiter must still join the original materialization after cancellation.
    const later = attachment.read();
    const laterFailure = outcome === 'error'
      ? assert.rejects(later, error => error === failure) : undefined;
    assert.equal(opens, 1);
    if (outcome === 'success') {
      source.resolve(new Uint8Array([4, 5]));
      const [a, b] = await Promise.all([remaining, later]);
      assert.deepEqual(a, new Uint8Array([4, 5]));
      a.fill(0);
      assert.deepEqual(b, new Uint8Array([4, 5]));
      assert.deepEqual(await attachment.read(), new Uint8Array([4, 5]));
    } else {
      source.reject(failure);
      await Promise.all([remainingFailure, laterFailure]);
      await assert.rejects(attachment.read(), error => error === failure);
    }
    assert.equal(sourceSignal.aborted, false);
    assert.equal(opens, 1);
    assert.equal(disposes, 1);
    await attachment.close();
    assert.equal(disposes, 1);
  });
}

test('last-owner close cancels ongoing materialization and awaits exactly one disposal', async (t) => {
  const source = deferred();
  const disposal = deferred();
  let sourceSignal, aborts = 0, opens = 0, disposes = 0;
  const attachment = Attachment.lazy(signal => {
    opens++;
    sourceSignal = signal;
    signal.addEventListener('abort', () => { aborts++; }, { once: true });
    // Deliberately ignore cancellation: close must still bound the read wait.
    return source.promise;
  }, () => { disposes++; return disposal.promise; });
  t.after(async () => { disposal.resolve(); await attachment.close(); });

  const first = assert.rejects(attachment.read(), /Attachment closed/);
  const second = assert.rejects(attachment.read(), /Attachment closed/);
  assert.equal(opens, 1);
  assert.equal(disposes, 0);
  const closing = attachment.close();
  assert.strictEqual(attachment.close(), closing);
  assert.equal(sourceSignal.aborted, true);
  assert.equal(aborts, 1);
  let closed = false;
  void closing.then(() => { closed = true; });
  await Promise.resolve();
  assert.equal(disposes, 1);
  assert.equal(closed, false, 'close must await asynchronous disposal');
  disposal.resolve();
  await Promise.all([closing, first, second]);
  assert.equal(closed, true);
  source.resolve(new Uint8Array([7]));
  await assert.rejects(attachment.read(), /Attachment closed/);
  await attachment.close();
  assert.equal(opens, 1);
  assert.equal(aborts, 1);
  assert.equal(disposes, 1);
});
