import { Transform, TransformCallback } from "node:stream";

export interface LedgerSettlementReport {
  status: "SETTLED" | "ABORTED_PARTIAL";
  promptTokens: number;
  completionTokens: number;
  redactionsApplied: number;
  rehydrationsApplied: number;
}

export interface OutboundDlpRule {
  name: string;
  pattern: RegExp;
  replacement: string;
}

export interface SseSlidingWindowOptions {
  /** Trailing characters held back. Must exceed the longest secret or placeholder. Minimum 64. */
  holdbackSize?: number;
  /** placeholder -> developer's own value. Applied only to text that is already past the holdback. */
  rehydrationMap?: Map<string, string>;
  outboundRules?: OutboundDlpRule[];
  onSettle?: (report: LedgerSettlementReport) => void;
}

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Invariants
 *  - `raw` holds ONLY outbound-scanned text that has not yet been emitted. It never contains rehydrated values,
 *    so each character is scanned exactly once per pass and restored values are never re-redacted.
 *  - Rehydration is applied in a single longest-match-first pass only to the text being emitted, never to the held tail.
 *  - A cut point never falls inside a (partial) placeholder, so a placeholder is always emitted whole.
 *  - Settlement is exactly once. SETTLED only when upstream sent [DONE]; any other end is ABORTED_PARTIAL.
 */
export class SseSlidingWindowDlpTransform extends Transform {
  private readonly holdbackSize: number;
  private readonly rehydrationMap: Map<string, string>;
  private readonly rehydrationRegex: RegExp | null;
  private readonly outboundRules: OutboundDlpRule[];
  private readonly onSettle?: (report: LedgerSettlementReport) => void;
  private readonly rules: Array<{ re: RegExp; replacement: string }>;

  private rawLineBuffer = "";
  private raw = "";
  private template: Record<string, any> | null = null;

  private promptTokens = 0;
  private completionTokens = 0;
  private deltaCharsSeen = 0;
  private redactionsApplied = 0;
  private rehydrationsApplied = 0;
  private sawDone = false;
  private settled = false;

  constructor(options: SseSlidingWindowOptions = {}) {
    super();
    this.holdbackSize = Math.max(options.holdbackSize ?? 128, 64);
    this.rehydrationMap = options.rehydrationMap ?? new Map();
    this.outboundRules = options.outboundRules ?? [];
    this.onSettle = options.onSettle;

    // Sort placeholders by descending length so prefix-overlapping tokens ({{K_10}} vs {{K_1}}) never collide
    const sortedPlaceholders = Array.from(this.rehydrationMap.keys())
      .filter((k) => k.length > 0)
      .sort((a, b) => b.length - a.length);

    this.rehydrationRegex =
      sortedPlaceholders.length > 0
        ? new RegExp(sortedPlaceholders.map(escapeRegExp).join("|"), "g")
        : null;

    this.rules = this.outboundRules.map((r) => ({
      re: new RegExp(r.pattern.source, r.pattern.flags.includes("g") ? r.pattern.flags : r.pattern.flags + "g"),
      replacement: r.replacement,
    }));
  }

  /** Idempotent: replacement markers do not match rules, so rescanning is harmless. */
  private scanOutbound(text: string): string {
    let out = text;
    for (const rule of this.rules) {
      out = out.replace(rule.re, () => {
        this.redactionsApplied++;
        return rule.replacement;
      });
    }
    return out;
  }

  /** Single-pass rehydration prevents prefix collisions and cross-placeholder double-replacement. */
  private rehydrate(text: string): string {
    if (!this.rehydrationRegex) return text;
    return text.replace(this.rehydrationRegex, (matched) => {
      const restored = this.rehydrationMap.get(matched);
      if (restored !== undefined) {
        this.rehydrationsApplied++;
        return restored;
      }
      return matched;
    });
  }

  /** Moves the cut earlier if it would split a placeholder. */
  private safeCut(text: string, cut: number): number {
    let result = cut;
    for (const placeholder of this.rehydrationMap.keys()) {
      for (let k = Math.min(placeholder.length - 1, cut); k >= 1; k--) {
        if (text.slice(cut - k, cut) === placeholder.slice(0, k)) {
          result = Math.min(result, cut - k);
          break;
        }
      }
    }
    return Math.max(0, result);
  }

  private frame(content: string): string {
    const base = this.template
      ? structuredClone(this.template)
      : { object: "chat.completion.chunk", choices: [{ index: 0, delta: {} }] };
    base.choices[0].delta = { content };
    base.choices[0].finish_reason = null;
    return `data: ${JSON.stringify(base)}\n\n`;
  }

  /** Adds a delta to the window and returns the frames that are now safe to emit. */
  private ingestContent(delta: string): string[] {
    this.deltaCharsSeen += delta.length;
    this.raw = this.scanOutbound(this.raw + delta);
    if (this.raw.length <= this.holdbackSize) return [];

    const cut = this.safeCut(this.raw, this.raw.length - this.holdbackSize);
    if (cut <= 0) return [];
    const emit = this.rehydrate(this.raw.slice(0, cut));
    this.raw = this.raw.slice(cut);
    return emit.length > 0 ? [this.frame(emit)] : [];
  }

  /** Emits everything still held. Called on finish_reason, [DONE] and end of stream. */
  private drainRaw(): string[] {
    if (this.raw.length === 0) return [];
    const emit = this.rehydrate(this.scanOutbound(this.raw));
    this.raw = "";
    return emit.length > 0 ? [this.frame(emit)] : [];
  }

  private handleSseEventBlock(block: string): string[] {
    const out: string[] = [];
    for (const line of block.split(/\r?\n/)) {
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();

      if (payload === "[DONE]") {
        out.push(...this.drainRaw());
        this.sawDone = true;
        out.push("data: [DONE]\n\n");
        continue;
      }

      let parsed: Record<string, any>;
      try {
        parsed = JSON.parse(payload);
      } catch {
        out.push(`data: ${payload}\n\n`);
        continue;
      }

      if (parsed.usage && typeof parsed.usage === "object") {
        if (typeof parsed.usage.prompt_tokens === "number") this.promptTokens = parsed.usage.prompt_tokens;
        if (typeof parsed.usage.completion_tokens === "number") this.completionTokens = parsed.usage.completion_tokens;
      }

      const choice = parsed?.choices?.[0];
      const delta = choice?.delta?.content;

      if (typeof delta === "string" && delta.length > 0) {
        this.template = parsed;
        out.push(...this.ingestContent(delta));
        if (choice?.finish_reason) {
          out.push(...this.drainRaw());
          const finishCopy = structuredClone(parsed);
          if (finishCopy?.choices?.[0]?.delta) {
            delete finishCopy.choices[0].delta.content;
          }
          out.push(`data: ${JSON.stringify(finishCopy)}\n\n`);
        }
      } else {
        if (choice?.finish_reason) out.push(...this.drainRaw());
        out.push(`data: ${JSON.stringify(parsed)}\n\n`);
      }
    }
    return out;
  }

  public override _transform(chunk: Buffer | string, _enc: BufferEncoding, callback: TransformCallback): void {
    try {
      this.rawLineBuffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      const parts = this.rawLineBuffer.split(/\r?\n\r?\n/);
      this.rawLineBuffer = parts.pop() ?? "";
      for (const block of parts) {
        if (block.trim().length === 0) continue;
        for (const f of this.handleSseEventBlock(block)) this.push(f);
      }
      callback();
    } catch (err: any) {
      callback(err);
    }
  }

  public override _flush(callback: TransformCallback): void {
    try {
      if (this.rawLineBuffer.trim().length > 0) {
        for (const f of this.handleSseEventBlock(this.rawLineBuffer)) this.push(f);
        this.rawLineBuffer = "";
      }
      for (const f of this.drainRaw()) this.push(f);
      this.finalize(this.sawDone ? "SETTLED" : "ABORTED_PARTIAL");
      callback();
    } catch (err: any) {
      callback(err);
    }
  }

  public override _destroy(error: Error | null, callback: (error: Error | null) => void): void {
    this.finalize("ABORTED_PARTIAL");
    callback(error);
  }

  private finalize(status: "SETTLED" | "ABORTED_PARTIAL"): void {
    if (this.settled) return;
    this.settled = true;
    const completionTokens =
      this.completionTokens > 0 ? this.completionTokens : Math.max(1, Math.ceil(this.deltaCharsSeen / 4));
    this.onSettle?.({
      status,
      promptTokens: this.promptTokens,
      completionTokens,
      redactionsApplied: this.redactionsApplied,
      rehydrationsApplied: this.rehydrationsApplied,
    });
  }
}