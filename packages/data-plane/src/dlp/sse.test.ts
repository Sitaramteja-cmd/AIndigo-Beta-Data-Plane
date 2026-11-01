import { test } from "node:test";
import assert from "node:assert/strict";
import { SseSlidingWindowDlpTransform, LedgerSettlementReport } from "./sse-sliding-window.js";

const RULE = { name: "OPENAI", pattern: /sk-proj-[A-Za-z0-9_]{30,50}/g, replacement: "[REDACTED]" };

/** Concatenates the text content the CLIENT would see, parsing each SSE frame. */
function clientText(frames: string[]): string {
  let text = "";
  for (const f of frames.join("").split("\n\n")) {
    if (!f.startsWith("data: ") || f.trim() === "data: [DONE]") continue;
    try {
      text += JSON.parse(f.slice(6))?.choices?.[0]?.delta?.content ?? "";
    } catch {}
  }
  return text;
}

test("secret split across three chunks never reaches the client", async () => {
  let report: LedgerSettlementReport | null = null;
  const s = new SseSlidingWindowDlpTransform({ holdbackSize: 80, outboundRules: [RULE], onSettle: (r) => { report = r; } });
  const out: string[] = [];
  s.on("data", (c) => out.push(c.toString("utf8")));
  s.write(`data: {"choices":[{"delta":{"content":"key sk-proj-CANARY_"}}]}\n\n`);
  s.write(`data: {"choices":[{"delta":{"content":"SPLIT_SECRET_99887766"}}]}\n\n`);
  s.write(`data: {"choices":[{"delta":{"content":"554433221100 then a long normal tail of response text to flush the window fully"}}]}\n\n`);
  s.write(`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":42,"completion_tokens":35}}\n\n`);
  s.end(`data: [DONE]\n\n`);
  await new Promise((r) => s.on("end", r));
  const text = clientText(out);
  assert.ok(!text.includes("CANARY"), "secret body leaked");
  assert.ok(!text.includes("sk-proj"), "secret prefix leaked");
  assert.ok(text.includes("[REDACTED]"), "marker missing");
  assert.equal(report!.status, "SETTLED");
  assert.equal(report!.promptTokens, 42);
  assert.equal(report!.completionTokens, 35);
  assert.equal(report!.redactionsApplied, 1);
});

test("placeholder rehydrates across TCP fragmentation", async () => {
  const s = new SseSlidingWindowDlpTransform({ holdbackSize: 80, rehydrationMap: new Map([["{{AINDIGO_VAULT_AWS_001}}", "AKIA_LOCAL_RESTORED"]]) });
  const out: string[] = [];
  s.on("data", (c) => out.push(c.toString("utf8")));
  s.write(`data: {"choices":[{"delta":{"content":"export K={{AINDIGO_"}}]}\n\n`);
  s.write(`data: {"choi`);
  s.write(`ces":[{"delta":{"content":"VAULT_AWS_001}} in .env"}}]}\n\n`);
  s.end(`data: [DONE]\n\n`);
  await new Promise((r) => s.on("end", r));
  const text = clientText(out);
  assert.ok(text.includes("AKIA_LOCAL_RESTORED"));
  assert.ok(!text.includes("{{AINDIGO"));
});

test("placeholder is never cut in half at a window boundary", async () => {
  const s = new SseSlidingWindowDlpTransform({ holdbackSize: 64, rehydrationMap: new Map([["{{AINDIGO_X_1}}", "REAL"]]) });
  const out: string[] = [];
  s.on("data", (c) => out.push(c.toString("utf8")));
  const pad = "a".repeat(40);
  s.write(`data: {"choices":[{"delta":{"content":"${pad}{{AINDIGO_X_1}} end"}}]}\n\n`);
  s.end(`data: [DONE]\n\n`);
  await new Promise((r) => s.on("end", r));
  const text = clientText(out);
  assert.equal(text, `${pad}REAL end`);
});

test("dropped upstream settles ABORTED_PARTIAL with tokens > 0", async () => {
  let report: LedgerSettlementReport | null = null;
  const s = new SseSlidingWindowDlpTransform({ holdbackSize: 64, onSettle: (r) => { report = r; } });
  s.on("error", () => {});
  s.on("data", () => {});
  s.write(`data: {"choices":[{"delta":{"content":"${"Partial response text. ".repeat(10)}"}}]}\n\n`);
  s.destroy(new Error("UPSTREAM_SOCKET_HANGUP"));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(report!.status, "ABORTED_PARTIAL");
  assert.ok(report!.completionTokens > 0);
});

test("upstream ending WITHOUT [DONE] is not reported as SETTLED", async () => {
  let report: LedgerSettlementReport | null = null;
  const s = new SseSlidingWindowDlpTransform({ holdbackSize: 64, onSettle: (r) => { report = r; } });
  s.on("data", () => {});
  s.end(`data: {"choices":[{"delta":{"content":"hi"}}]}\n\n`);
  await new Promise((r) => s.on("end", r));
  assert.equal(report!.status, "ABORTED_PARTIAL");
});

test("restored developer key is not redacted by an outbound rule on later chunks", async () => {
  const s = new SseSlidingWindowDlpTransform({
    holdbackSize: 80,
    outboundRules: [RULE],
    rehydrationMap: new Map([["{{K}}", "sk-proj-LOCALDEVKEY_0123456789abcdefghij"]]),
  });
  const out: string[] = [];
  s.on("data", (c) => out.push(c.toString("utf8")));
  s.write(`data: {"choices":[{"delta":{"content":"key={{K}} "}}]}\n\n`);
  s.write(`data: {"choices":[{"delta":{"content":"more text here to push the window forward past eighty characters total yes"}}]}\n\n`);
  s.end(`data: [DONE]\n\n`);
  await new Promise((r) => s.on("end", r));
  assert.ok(clientText(out).includes("sk-proj-LOCALDEVKEY"));
});

test("single-pass rehydration prevents prefix collision and cross-placeholder mutation", async () => {
  const s = new SseSlidingWindowDlpTransform({
    holdbackSize: 64,
    rehydrationMap: new Map([
      ["AKIA_VAULT_1", "VAL_ONE_WITH_AKIA_VAULT_2_INSIDE"],
      ["AKIA_VAULT_10", "VAL_TEN"],
      ["AKIA_VAULT_2", "SHOULD_NOT_REPLACE_INSIDE_VAL_ONE"],
    ]),
  });
  const out: string[] = [];
  s.on("data", (c) => out.push(c.toString("utf8")));
  s.write(`data: {"choices":[{"delta":{"content":"a=AKIA_VAULT_10 b=AKIA_VAULT_1"}}]}\n\n`);
  s.end(`data: [DONE]\n\n`);
  await new Promise((r) => s.on("end", r));
  assert.equal(clientText(out), "a=VAL_TEN b=VAL_ONE_WITH_AKIA_VAULT_2_INSIDE");
});