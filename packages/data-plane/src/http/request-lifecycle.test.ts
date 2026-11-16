import test from 'node:test';
import assert from 'node:assert/strict';
import { HttpRequestLifecycle } from './request-lifecycle.js';

test('tracks active requests', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();

  assert.ok(release);
  assert.equal(lifecycle.activeCount, 1);

  release();

  assert.equal(lifecycle.activeCount, 0);

  console.log('PASS: active request tracking');
});

test('rejects new requests after draining starts', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();
  assert.ok(release);

  lifecycle.startDraining();

  assert.equal(lifecycle.isDraining, true);
  assert.equal(lifecycle.tryAcquire(), null);
  assert.equal(lifecycle.activeCount, 1);

  release();

  console.log('PASS: new requests rejected during drain');
});

test('release is idempotent', () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();
  assert.ok(release);

  release();
  release();

  assert.equal(lifecycle.activeCount, 0);

  console.log('PASS: idempotent release');
});

test('waitForIdle resolves after active requests finish', async () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();
  assert.ok(release);

  const waiting = lifecycle.waitForIdle(1_000);

  release();

  assert.equal(await waiting, true);

  console.log('PASS: wait for active requests');
});

test('waitForIdle returns false when timeout expires', async () => {
  const lifecycle = new HttpRequestLifecycle();

  const release = lifecycle.tryAcquire();
  assert.ok(release);

  assert.equal(await lifecycle.waitForIdle(10), false);

  release();

  console.log('PASS: drain timeout');
});

test('rejects invalid timeout values', async () => {
  const lifecycle = new HttpRequestLifecycle();

  for (const timeout of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    await assert.rejects(
      lifecycle.waitForIdle(timeout),
      /timeoutMs must be a non-negative safe integer/i,
    );
  }

  console.log('PASS: invalid timeout validation');
});