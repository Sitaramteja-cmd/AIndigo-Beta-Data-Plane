import crypto from "node:crypto";
import { performance } from "node:perf_hooks";
import type { VirtualKeyVault, AuthorizeResult } from "../vault/virtual-key-vault.js";
import { scanAndRedactWithChecksums } from "../dlp/checksum-engine.js";
import type { SafeExactMatchCache, CacheMessage, CacheOptions } from "../cache/exact-cache.js";
import type { FinOpsGovernor } from "../governor/finops-governor.js";

export class UpstreamError extends Error {
  public readonly status: number;
  public readonly retryAfter?: string;
  constructor(status: number, message: string, retryAfter?: string) {
    super(message);
    this.name = "UpstreamError";
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

export interface PipelineRequest {
  bearerToken: string;
  system?: string | Array<Record<string, unknown>>;
  messages: CacheMessage[];
  model: string;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  seed?: number;
  stop?: string | string[];
  response_format?: unknown;
  stream?: boolean;
  bypass_cache?: boolean;
  tools?: Array<Record<string, unknown>>;
  tool_choice?: unknown;
  user?: string;
  noDownshift?: boolean;
  timeoutMs?: number;
}

export interface UpstreamResult {
  responseText: string;
  promptTokens: number;
  completionTokens: number;
  finishReason: string;
}

export interface PipelineResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  tokensUsed: { prompt: number; completion: number };
  costUsd: number;
  cacheStatus: "HIT" | "MISS" | "BYPASS";
  dlpDetectedCategories: string[];
}

function getModelPricing(model: string): { inputPricePerMillion: number; outputPricePerMillion: number } {
  const m = model.toLowerCase();
  if (m.includes("mini") || m.includes("haiku") || m.includes("flash")) {
    return { inputPricePerMillion: 0.15, outputPricePerMillion: 0.60 };
  }
  if (m.includes("gpt-4o") || m.includes("claude-3-5-sonnet") || m.includes("pro")) {
    return { inputPricePerMillion: 2.50, outputPricePerMillion: 10.00 };
  }
  if (m.includes("gpt-3.5") || m.includes("embedding")) {
    return { inputPricePerMillion: 0.50, outputPricePerMillion: 1.50 };
  }
  return { inputPricePerMillion: 1.00, outputPricePerMillion: 3.00 };
}

const SKIP_KEYS = new Set(["role", "type", "id", "tool_call_id", "model", "name"]);

function deepScanAndRedact(key: string, val: unknown, detectedCategories: Set<string>): unknown {
  if (typeof val === "string") {
    if (SKIP_KEYS.has(key) || val.startsWith("data:")) {
      return val;
    }
    const scan = scanAndRedactWithChecksums(val);
    scan.detectedCategories.forEach((c) => detectedCategories.add(c));
    return scan.redactedText;
  }
  if (Array.isArray(val)) {
    return val.map((item) => deepScanAndRedact(key, item, detectedCategories));
  }
  if (val !== null && typeof val === "object") {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (k === "arguments" && typeof v === "string") {
        try {
          const parsedArgs = JSON.parse(v);
          const redactedArgs = deepScanAndRedact(k, parsedArgs, detectedCategories);
          result[k] = JSON.stringify(redactedArgs);
          continue;
        } catch {}
      }
      result[k] = deepScanAndRedact(k, v, detectedCategories);
    }
    return result;
  }
  return val;
}

function mapVaultReasonToStatusCode(reason?: string): number {
  switch (reason) {
    case "INVALID_KEY":
    case "REVOKED_KEY":
    case "EXPIRED_KEY":
      return 401;
    case "MODEL_NOT_ALLOWED":
      return 403;
    case "BUDGET_EXCEEDED":
      return 402;
    case "BAD_REQUEST_AMOUNT":
      return 400;
    case "VAULT_DECRYPT_ERROR":
    case "VAULT_INTERNAL_ERROR":
    default:
      return 500;
  }
}

export async function processChatCompletion(
  vault: VirtualKeyVault,
  cache: SafeExactMatchCache,
  governor: FinOpsGovernor | undefined,
  req: PipelineRequest,
  upstreamExecutor: (decryptedKey: string, effectiveModel: string, scrubbedReq: PipelineRequest, signal: AbortSignal) => Promise<UpstreamResult>
): Promise<PipelineResponse> {
  if (req.stream) {
    return {
      statusCode: 400,
      headers: { "X-Aindigo-Error": "STREAMING_NOT_SUPPORTED_IN_V1" },
      body: JSON.stringify({ error: { message: "Streaming is reserved for SSE pipeline.", type: "aindigo_policy_violation" } }),
      tokensUsed: { prompt: 0, completion: 0 },
      costUsd: 0,
      cacheStatus: "BYPASS",
      dlpDetectedCategories: [],
    };
  }

  // 1. Peek Key Metadata for FinOps Governor Evaluation
  const keyMeta = vault.peekKey(req.bearerToken);
  let effectiveModel = req.model;
  let downshifted = false;
  let downshiftReason: string | undefined;

  if (keyMeta && governor && !req.noDownshift) {
    const evalResult = governor.evaluate(keyMeta, req.model);
    if (evalResult.downshifted) {
      effectiveModel = evalResult.effectiveModel;
      downshifted = true;
      downshiftReason = evalResult.reason;
    }
  }

  const pricing = getModelPricing(effectiveModel);

  const payloadJson = JSON.stringify({ system: req.system, messages: req.messages, tools: req.tools });
  const estimatedInputTokens = Math.max(20, Math.ceil(payloadJson.length / 3));
  const effectiveMaxTokens = req.max_tokens ?? 4096;

  const estimatedCostUsd = Number((
    (estimatedInputTokens / 1_000_000) * pricing.inputPricePerMillion +
    (effectiveMaxTokens / 1_000_000) * pricing.outputPricePerMillion
  ).toFixed(6));

  // 2. Authorize & Reserve Budget with Effective Model
  const auth: AuthorizeResult = vault.authorize({
    rawVirtualKey: req.bearerToken,
    requestedModel: req.model,
    downshiftedModel: effectiveModel,
    estimatedCostUsd,
  });

  if (!auth.valid || !auth.reservation_id || !auth.getProviderKey) {
    const statusCode = mapVaultReasonToStatusCode(auth.reason);
    return {
      statusCode,
      headers: { "X-Aindigo-Error": auth.reason ?? "UNAUTHORIZED" },
      body: JSON.stringify({ error: { message: `Request authorization failed: ${auth.reason}`, type: "aindigo_policy_violation" } }),
      tokensUsed: { prompt: 0, completion: 0 },
      costUsd: 0,
      cacheStatus: "BYPASS",
      dlpDetectedCategories: [],
    };
  }

  const reservationId = auth.reservation_id;
  let settledCostUsd = 0;
  let promptTokens = 0;
  let completionTokens = 0;
  let cacheStatus: "HIT" | "MISS" | "BYPASS" = "BYPASS";
  let upstreamSucceeded = false;
  let reconciled = false;
  const allDetectedCategories = new Set<string>();

  const controller = new AbortController();
  const timeoutMs = req.timeoutMs ?? 30000;
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    let dlpWasModified = false;
    const scrubbedSystem = req.system ? deepScanAndRedact("system", req.system, allDetectedCategories) : undefined;
    const scrubbedMessages = req.messages.map((m) => deepScanAndRedact("message", m, allDetectedCategories) as CacheMessage);
    const scrubbedTools = req.tools ? (deepScanAndRedact("tools", req.tools, allDetectedCategories) as Array<Record<string, unknown>>) : undefined;
    const scrubbedResponseFormat = req.response_format ? deepScanAndRedact("response_format", req.response_format, allDetectedCategories) : undefined;
    const scrubbedStop = req.stop ? deepScanAndRedact("stop", req.stop, allDetectedCategories) : undefined;

    if (allDetectedCategories.size > 0) {
      dlpWasModified = true;
    }

    const { bearerToken: _omit, ...safeReq } = req;
    const scrubbedReqPipeline: PipelineRequest = {
      ...safeReq,
      max_tokens: effectiveMaxTokens,
      system: scrubbedSystem as any,
      messages: scrubbedMessages,
      tools: scrubbedTools,
      response_format: scrubbedResponseFormat,
      stop: scrubbedStop as any,
    };

    const cacheMessages: CacheMessage[] = scrubbedSystem
      ? [{ role: "__system__", content: scrubbedSystem }, ...scrubbedMessages]
      : scrubbedMessages;

    const cacheOpts: CacheOptions = {
      org_id: auth.org_id!,
      virtual_key_id: auth.record_id!,
      model: effectiveModel,
      provider: auth.provider,
      temperature: req.temperature,
      max_tokens: effectiveMaxTokens,
      top_p: req.top_p,
      seed: req.seed,
      stop: scrubbedStop as any,
      response_format: scrubbedResponseFormat,
      has_tools: Boolean(req.tools && req.tools.length > 0),
      bypass_header: req.bypass_cache,
    };

    const cacheCheck = cache.get(cacheMessages, dlpWasModified, cacheOpts);
    cacheStatus = cacheCheck.cacheHeader;

    let responseText = "";
    let finishReason = "stop";

    if (cacheCheck.hit && cacheCheck.entry) {
      responseText = cacheCheck.entry.response_text;
      promptTokens = cacheCheck.entry.prompt_tokens;
      completionTokens = cacheCheck.entry.completion_tokens;
      settledCostUsd = 0;
      upstreamSucceeded = true;
    } else {
      const tStart = performance.now();
      const upstreamResult = await upstreamExecutor(
        auth.getProviderKey(),
        effectiveModel,
        scrubbedReqPipeline,
        controller.signal
      );
      const durationMs = performance.now() - tStart;

      responseText = upstreamResult.responseText;
      promptTokens = upstreamResult.promptTokens;
      completionTokens = upstreamResult.completionTokens;
      finishReason = (upstreamResult.finishReason || "stop").toLowerCase();
      upstreamSucceeded = true;

      const pCost = (promptTokens / 1_000_000) * pricing.inputPricePerMillion;
      const cCost = (completionTokens / 1_000_000) * pricing.outputPricePerMillion;
      settledCostUsd = Number((pCost + cCost).toFixed(6));

      if (finishReason === "stop" || finishReason === "end_turn") {
        cache.set(
          cacheMessages,
          dlpWasModified,
          cacheOpts,
          responseText,
          promptTokens,
          completionTokens,
          settledCostUsd,
          Math.round(durationMs)
        );
      }
    }

    clearTimeout(timer);

    const receiptId = `rcpt_${crypto.createHash("sha256").update(reservationId + settledCostUsd + effectiveModel).digest("hex").slice(0, 16)}`;
    vault.reconcileSpend(reservationId, settledCostUsd, receiptId);
    reconciled = true;

    const responseHeaders: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Aindigo-Cache": cacheStatus,
      "X-Aindigo-Key-Prefix": auth.key_prefix!,
      "X-Aindigo-Receipt-Id": receiptId,
      "X-Aindigo-DLP": Array.from(allDetectedCategories).join(",") || "NONE",
    };

    if (downshifted) {
      responseHeaders["X-Aindigo-Downshifted"] = `${req.model}->${effectiveModel}`;
      if (downshiftReason) {
        responseHeaders["X-Aindigo-Downshift-Reason"] = downshiftReason;
      }
    }

    return {
      statusCode: 200,
      headers: responseHeaders,
      body: JSON.stringify({
        id: `chatcmpl-${crypto.randomBytes(6).toString("hex")}`,
        object: "chat.completion",
        model: effectiveModel,
        choices: [{ message: { role: "assistant", content: responseText }, finish_reason: finishReason }],
        usage: { prompt_tokens: promptTokens, completion_tokens: completionTokens, total_tokens: promptTokens + completionTokens },
      }),
      tokensUsed: { prompt: promptTokens, completion: completionTokens },
      costUsd: settledCostUsd,
      cacheStatus,
      dlpDetectedCategories: Array.from(allDetectedCategories),
    };
  } catch (err: any) {
    clearTimeout(timer);

    let statusCode = 502;
    let errType = "UPSTREAM_GATEWAY_ERROR";
    let errMsg = "Upstream provider call failed.";

    if (err instanceof UpstreamError) {
      statusCode = err.status;
      errType = statusCode === 429 ? "RATE_LIMIT_EXCEEDED" : "UPSTREAM_CLIENT_ERROR";
      errMsg = err.message;
    } else if (controller.signal.aborted) {
      statusCode = 504;
      errType = "GATEWAY_TIMEOUT";
      errMsg = "Upstream request timed out.";
    }

    return {
      statusCode,
      headers: { "X-Aindigo-Error": errType },
      body: JSON.stringify({ error: { message: errMsg, type: "aindigo_gateway_error" } }),
      tokensUsed: { prompt: 0, completion: 0 },
      costUsd: 0,
      cacheStatus: "BYPASS",
      dlpDetectedCategories: Array.from(allDetectedCategories),
    };
  } finally {
    if (!reconciled) {
      const finalCost = upstreamSucceeded ? settledCostUsd : 0;
      vault.reconcileSpend(reservationId, finalCost, null);
    }
  }
}