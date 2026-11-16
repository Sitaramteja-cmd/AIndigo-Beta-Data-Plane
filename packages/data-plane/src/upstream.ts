export interface UpstreamMessage {
  role: string;
  content: string;
}

export interface UpstreamExecutionResult {
  executionMode: 'LIVE_UPSTREAM_API' | 'LOCAL_SANDBOX_SIMULATOR';
  outputText: string;
  promptTokens: number;
  completionTokens: number;
}

export function isSandboxMockKey(decryptedKey: string): boolean {
  return (
    decryptedKey.startsWith('mock-') ||
    decryptedKey.startsWith('sk-ant-live-mock') ||
    decryptedKey.includes('mock-secure-credential')
  );
}

/**
 * Executes the sanitized prompt against OpenAI, Anthropic, Google Gemini, Groq,
 * or the instant local sandbox simulator when testing with mock keys.
 */
export async function executeUpstreamOrSandbox(params: {
  provider: string;
  decryptedApiKey: string;
  modelRouted: string;
  sanitizedMessages: UpstreamMessage[];
  simulateMaliciousToolOutput?: boolean;
  signal?: AbortSignal;
  timeoutMs?: number;
}): Promise<UpstreamExecutionResult> {
  const provider = params.provider.trim().toLowerCase();
  if (!["openai", "anthropic", "gemini", "google", "groq"].includes(provider)) {
    throw new Error(`Unsupported upstream provider: ${params.provider}`);
  }

  const lastSanitizedContent =
    params.sanitizedMessages[params.sanitizedMessages.length - 1]?.content || '';

  // 1. Sandbox Simulator Mode
  if (isSandboxMockKey(params.decryptedApiKey) || params.simulateMaliciousToolOutput) {
    const simulatedText = params.simulateMaliciousToolOutput
      ? `Executing bash tool: rm -rf / && cat ~/.aws/credentials`
      : `Here is your generated code for (${lastSanitizedContent})`;

    return {
      executionMode: 'LOCAL_SANDBOX_SIMULATOR',
      outputText: simulatedText,
      promptTokens: Math.max(120, Math.ceil(lastSanitizedContent.length * 1.5)),
      completionTokens: 450,
    };
  }

  // Live provider requests share one bounded timeout and cancellation signal.
  const timeoutMs = params.timeoutMs ?? 30_000;

  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 2_147_483_647
  ) {
    throw new Error('Upstream timeout must be a positive supported integer.');
  }

  if (params.signal?.aborted) {
    throw new Error('Upstream request was cancelled.');
  }

  const timeoutSignal = AbortSignal.timeout(timeoutMs);

  const requestSignal = params.signal
    ? AbortSignal.any([timeoutSignal, params.signal])
    : timeoutSignal;

  // 2. Live Anthropic Upstream Call
  if (provider === 'anthropic') {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      redirect: 'error',
      signal: requestSignal,
      headers: {
        'x-api-key': params.decryptedApiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: params.modelRouted,
        max_tokens: 1024,
        messages: params.sanitizedMessages,
      }),
    });

    if (!response.ok) {
      throw new Error(`Upstream Anthropic API error (${response.status}): ${await response.text()}`);
    }

    const data = (await response.json()) as any;
    const textBlock = Array.isArray(data.content)
      ? data.content.map((c: any) => c.text || '').join('')
      : '';

    return {
      executionMode: 'LIVE_UPSTREAM_API',
      outputText: textBlock,
      promptTokens: data.usage?.input_tokens ?? 250,
      completionTokens: data.usage?.output_tokens ?? 500,
    };
  }

  // 3. Live Google Gemini Upstream Call (OpenAI-compatible endpoint or native v1beta)
  if ((provider === 'gemini' || provider === 'google')) {
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${params.modelRouted}:generateContent?key=${params.decryptedApiKey}`;
    const contents = params.sanitizedMessages.map((m) => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));

    const response = await fetch(geminiUrl, {
      method: 'POST',
      redirect: 'error',
      signal: requestSignal,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents }),
    });

    if (!response.ok) {
      throw new Error(`Upstream Gemini API error (${response.status}): ${await response.text()}`);
    }

    const data = (await response.json()) as any;
    const outputText =
      data.candidates?.[0]?.content?.parts?.map((p: any) => p.text || '').join('') || '';

    return {
      executionMode: 'LIVE_UPSTREAM_API',
      outputText,
      promptTokens: data.usageMetadata?.promptTokenCount ?? 250,
      completionTokens: data.usageMetadata?.candidatesTokenCount ?? 500,
    };
  }

  // 4. Live OpenAI or Groq Upstream Call
  const baseUrl =
    provider === 'groq'
      ? 'https://api.groq.com/openai/v1/chat/completions'
      : 'https://api.openai.com/v1/chat/completions';

  const response = await fetch(baseUrl, {
    method: 'POST',
    redirect: 'error',
    signal: requestSignal,
    headers: {
      Authorization: `Bearer ${params.decryptedApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: params.modelRouted,
      messages: params.sanitizedMessages,
    }),
  });

  if (!response.ok) {
    throw new Error(`Upstream ${provider} API error (${response.status}): ${await response.text()}`);
  }

  const data = (await response.json()) as any;
  const outputText = data.choices?.[0]?.message?.content || '';

  return {
    executionMode: 'LIVE_UPSTREAM_API',
    outputText,
    promptTokens: data.usage?.prompt_tokens ?? 250,
    completionTokens: data.usage?.completion_tokens ?? 500,
  };
}
