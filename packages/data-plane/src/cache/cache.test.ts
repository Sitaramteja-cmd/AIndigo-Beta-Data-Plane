import { strict as assert } from "node:assert";
import { SafeExactMatchCache, CacheMessage, CacheOptions } from "./exact-cache.js";

function runCacheTests() {
  console.log("================================================================");
  console.log(" ⚡ AIndigo Tier 2 — Hardened Enterprise Cache Test Suite");
  console.log("================================================================");

  const cache = new SafeExactMatchCache(5, 1024 * 1024, 64 * 1024, 60000);

  const messages: CacheMessage[] = [
    { role: "user", content: "Tell me a random story." }
  ];

  const explicitZeroTemp: CacheOptions = { org_id: "org_1", virtual_key_id: "vk_alice", model: "gemini-2.5-flash", temperature: 0 };
  const omittedTemp: CacheOptions = { org_id: "org_1", virtual_key_id: "vk_alice", model: "gemini-2.5-flash" };

  const r1 = cache.get(messages, false, explicitZeroTemp);
  assert.equal(r1.cacheHeader, "MISS");
  cache.set(messages, false, explicitZeroTemp, "Deterministic story...", 10, 20, 0.0001, 200);
  
  const r2 = cache.get(messages, false, explicitZeroTemp);
  assert.equal(r2.hit, true, "Explicit temperature: 0 must be cacheable");
  console.log("✅ 1. Explicit Temperature 0 Caching Verified.");

  const r3 = cache.get(messages, false, omittedTemp);
  assert.equal(r3.cacheHeader, "BYPASS", "Omitted temperature must bypass cache");
  console.log("✅ 2. Omitted Temperature Stochastic Bypass Verified.");

  console.log("================================================================");
  console.log(" 🎉 Tier 2 Module 2.3 Temperature Eligibility Tests PASSED");
  console.log("================================================================");
}

runCacheTests();