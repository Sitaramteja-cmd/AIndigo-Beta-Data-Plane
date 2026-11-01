import { strict as assert } from "node:assert";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { VirtualKeyVault } from "../vault/virtual-key-vault.js";
import { SafeExactMatchCache } from "../cache/exact-cache.js";
import { processChatCompletion, PipelineRequest, UpstreamError } from "./request-pipeline.js";

async function runPipelineTests() {
  console.log("================================================================");
  console.log(" 🚀 AIndigo Tier 3 — Hardened Pipeline Test Suite");
  console.log("================================================================");

  const tmpDbPath = path.join(os.tmpdir(), `aindigo-pipeline-hardened-${Date.now()}.sqlite`);
  const masterKey = crypto.randomBytes(32).toString("hex");

  try {
    const vault = new VirtualKeyVault(masterKey, tmpDbPath, 1);
    const cache = new SafeExactMatchCache();

    const { rawVirtualKey, metadata } = vault.createVirtualKey({
      org_id: "org_enterprise",
      name: "Pipeline Hardened Key",
      provider: "openai",
      allowed_models: ["gpt-4o", "gpt-4o-mini"],
      raw_provider_key: "sk-proj-upstream-secret-999",
      budget_limit_usd: 1.00,
      budget_period: "monthly",
    });

    let upstreamCalls = 0;
    const mockExecutor = async (_key: string, model: string, req: PipelineRequest) => {
      upstreamCalls++;
      assert.equal((req as any).bearerToken, undefined, "bearerToken must never be passed to executor");
      return {
        responseText: `Model ${model} processed prompt successfully.`,
        promptTokens: 100,
        completionTokens: 100,
        finishReason: "STOP",
      };
    };

    // 1. Streaming Rejection Test (HTTP 400)
    const streamReq: PipelineRequest = {
      bearerToken: rawVirtualKey,
      messages: [{ role: "user", content: "Hi" }],
      model: "gpt-4o",
      stream: true,
      estimatedInputTokens: 10,
    };
    const resStream = await processChatCompletion(vault, cache, streamReq, mockExecutor);
    assert.equal(resStream.statusCode, 400);
    console.log("✅ 1. Streaming Request Rejection Verified.");

    // 2. Request with Sensitive Data (Triggers DLP Mutation -> Cache Bypass)
    const sensitiveReq: PipelineRequest = {
      bearerToken: rawVirtualKey,
      system: "You are helpful. My card is 4000 0000 0000 0002.",
      messages: [
        { role: "user", content: "Look up user with PAN ABCDE1234F" }
      ],
      model: "gpt-4o-mini",
      temperature: 0,
      estimatedInputTokens: 50,
    };

    const res1 = await processChatCompletion(vault, cache, sensitiveReq, mockExecutor);
    assert.equal(res1.statusCode, 200);
    assert.equal(res1.cacheStatus, "BYPASS");
    assert.equal(upstreamCalls, 1);
    console.log("✅ 2. DLP Mutation Cache Bypass Verified.");

    // 3. Clean Request (Cache MISS -> HIT)
    const cleanReq: PipelineRequest = {
      bearerToken: rawVirtualKey,
      system: "You are a calculator.",
      messages: [
        { role: "user", content: "What is 10 + 10?" }
      ],
      model: "gpt-4o-mini",
      temperature: 0,
      estimatedInputTokens: 20,
    };

    const resCleanMiss = await processChatCompletion(vault, cache, cleanReq, mockExecutor);
    assert.equal(resCleanMiss.statusCode, 200);
    assert.equal(resCleanMiss.cacheStatus, "MISS");
    assert.equal(upstreamCalls, 2);

    const resCleanHit = await processChatCompletion(vault, cache, cleanReq, mockExecutor);
    assert.equal(resCleanHit.statusCode, 200);
    assert.equal(resCleanHit.cacheStatus, "HIT");
    assert.equal(upstreamCalls, 2);
    console.log("✅ 3. Clean Request Cache MISS -> HIT Workflow Verified ($0.00 Spend).");

    // 4. Typed Upstream Error Mapping (429 Rate Limit) - Use unique request to avoid cache hit
    const errorReq: PipelineRequest = {
      bearerToken: rawVirtualKey,
      system: "You are error prone.",
      messages: [{ role: "user", content: "Trigger rate limit please." }],
      model: "gpt-4o-mini",
      temperature: 0,
      estimatedInputTokens: 20,
    };
    const rateLimitExecutor = async () => { throw new UpstreamError(429, "Rate limit hit"); };
    const res429 = await processChatCompletion(vault, cache, errorReq, rateLimitExecutor);
    assert.equal(res429.statusCode, 429);
    assert.equal(res429.headers["X-Aindigo-Error"], "RATE_LIMIT_EXCEEDED");
    console.log("✅ 4. Typed Upstream Error Mapping (429) Verified.");

    vault.close();
  } finally {
    for (const suffix of ["", "-wal", "-shm"]) {
      const p = `${tmpDbPath}${suffix}`;
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch {}
      }
    }
  }

  console.log("================================================================");
  console.log(" 🎉 Tier 3 Module 3.1 Hardened Pipeline Tests PASSED");
  console.log("================================================================");
}

runPipelineTests();