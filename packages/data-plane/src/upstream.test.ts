import test from 'node:test';
import assert from 'node:assert/strict';
import { executeUpstreamOrSandbox } from './upstream.js';

const originalFetch = globalThis.fetch;

function mockResponse(provider: string): Response {
  if (provider === 'anthropic') {
    return new Response(JSON.stringify({
      content: [{ type: 'text', text: 'test response' }],
      usage: { input_tokens: 10, output_tokens: 5 },
    }), { status: 200 });
  }

  if (provider === 'gemini') {
    return new Response(JSON.stringify({
      candidates: [{
        content: { parts: [{ text: 'test response' }] },
      }],
      usageMetadata: {
        promptTokenCount: 10,
        candidatesTokenCount: 5,
      },
    }), { status: 200 });
  }

  return new Response(JSON.stringify({
    choices: [{
      message: { content: 'test response' },
    }],
    usage: { prompt_tokens: 10, completion_tokens: 5 },
  }), { status: 200 });
}

function requestParams(provider = 'openai') {
  return {
    provider,
    decryptedApiKey: 'test-live-provider-key',
    modelRouted: 'test-model',
    sanitizedMessages: [{ role: 'user', content: 'hello' }],
  };
}

test('forwards cancellation signal to all live provider requests', async () => {
  const receivedSignals: AbortSignal[] = [];

  globalThis.fetch = (async (input, init) => {
    assert.equal(init?.redirect, 'error');
    const signal = init?.signal;

    assert.ok(signal instanceof AbortSignal);
    receivedSignals.push(signal);

    const url = String(input);
    const provider = url.includes('anthropic')
      ? 'anthropic'
      : url.includes('googleapis')
        ? 'gemini'
        : 'openai';

    return mockResponse(provider);
  }) as typeof fetch;

  try {
    for (const provider of ['anthropic', 'gemini', 'google', 'openai', 'groq']) {
      await executeUpstreamOrSandbox(requestParams(provider));
    }

    assert.equal(receivedSignals.length, 5);
    assert.ok(receivedSignals.every((signal) => !signal.aborted));

    console.log('PASS: provider cancellation signals forwarded');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('aborts a live provider request when its timeout expires', async () => {
  globalThis.fetch = ((_input, init) => {
    return new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal as AbortSignal;

      signal.addEventListener(
        'abort',
        () => reject(signal.reason),
        { once: true },
      );
    });
  }) as typeof fetch;

  try {
    await assert.rejects(
      executeUpstreamOrSandbox({
        ...requestParams(),
        timeoutMs: 10,
      }),
      (error: unknown) =>
        error instanceof Error && error.name === 'TimeoutError',
    );

    console.log('PASS: upstream timeout aborts request');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('aborts a live provider request when caller cancels', async () => {
  const controller = new AbortController();

  globalThis.fetch = ((_input, init) => {
    return new Promise<Response>((_resolve, reject) => {
      const signal = init?.signal as AbortSignal;

      signal.addEventListener(
        'abort',
        () => reject(signal.reason),
        { once: true },
      );
    });
  }) as typeof fetch;

  try {
    const pending = executeUpstreamOrSandbox({
      ...requestParams(),
      signal: controller.signal,
      timeoutMs: 5_000,
    });

    controller.abort(new Error('Test cancellation'));

    await assert.rejects(
      pending,
      /Test cancellation/,
    );

    console.log('PASS: caller cancellation aborts request');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('rejects invalid live upstream timeout values', async () => {
  globalThis.fetch = originalFetch;

  for (const timeoutMs of [0, -1, 1.5, Number.NaN, 2_147_483_648]) {
    await assert.rejects(
      executeUpstreamOrSandbox({
        ...requestParams(),
        timeoutMs,
      }),
      /timeout must be a positive supported integer/i,
    );
  }

  console.log('PASS: invalid timeout values rejected');
});

test('rejects a caller signal that was already aborted', async () => {
  const controller = new AbortController();
  controller.abort();

  await assert.rejects(
    executeUpstreamOrSandbox({
      ...requestParams(),
      signal: controller.signal,
    }),
    /request was cancelled/i,
  );

  console.log('PASS: pre-aborted request rejected');
});

test('sandbox execution remains local and does not call fetch', async () => {
  let fetchCalls = 0;

  globalThis.fetch = (async () => {
    fetchCalls++;
    throw new Error('Sandbox must not call fetch');
  }) as typeof fetch;

  try {
    const result = await executeUpstreamOrSandbox({
      ...requestParams(),
      decryptedApiKey: 'mock-test-key',
    });

    assert.equal(result.executionMode, 'LOCAL_SANDBOX_SIMULATOR');
    assert.equal(fetchCalls, 0);

    console.log('PASS: sandbox remains local');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

// SEC-009: unsupported provider identifiers must fail closed.
test('rejects unsupported providers without making an outbound request', async () => {
  let fetchCalls = 0;

  globalThis.fetch = (async () => {
    fetchCalls++;
    throw new Error('Unsupported provider must not call fetch');
  }) as typeof fetch;

  try {
    await assert.rejects(
      executeUpstreamOrSandbox(requestParams('unsupported-provider')),
      /Unsupported upstream provider/i,
    );

    assert.equal(fetchCalls, 0);
    console.log('PASS: unsupported provider rejected before fetch');
  } finally {
    globalThis.fetch = originalFetch;
  }
});
