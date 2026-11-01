import crypto from "node:crypto";

export type CacheMessage = Record<string, unknown>;

export interface CacheOptions {
  org_id: string;
  virtual_key_id: string;
  model: string;
  provider?: string;
  temperature?: number;
  max_tokens?: number;
  top_p?: number;
  seed?: number;
  stop?: string | string[];
  response_format?: unknown;
  stream?: boolean;
  has_tools?: boolean;
  bypass_header?: boolean;
}

export interface CacheEntry {
  response_text: string;
  prompt_tokens: number;
  completion_tokens: number;
  cost_usd: number;
  latency_saved_ms: number;
  byte_size: number;
  cached_at: number;
}

export interface FinOpsStats {
  total_requests: number;
  cache_hits: number;
  cache_misses: number;
  dlp_bypasses: number;
  ineligible_bypasses: number;
  header_bypasses: number;
  tokens_saved: number;
  usd_saved: number;
  latency_saved_ms: number;
  hit_rate: number;
}

function sortObjectKeys(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(sortObjectKeys);
  }
  const sortedKeys = Object.keys(obj as object).sort();
  const result: Record<string, unknown> = {};
  for (const key of sortedKeys) {
    const val = (obj as Record<string, unknown>)[key];
    if (val !== undefined) {
      result[key] = sortObjectKeys(val);
    }
  }
  return result;
}

export class SafeExactMatchCache {
  private store: Map<string, CacheEntry> = new Map();
  private maxEntries: number;
  private maxTotalBytes: number;
  private maxEntryBytes: number;
  private ttlMs: number;
  private currentTotalBytes: number = 0;

  private stats: FinOpsStats = {
    total_requests: 0,
    cache_hits: 0,
    cache_misses: 0,
    dlp_bypasses: 0,
    ineligible_bypasses: 0,
    header_bypasses: 0,
    tokens_saved: 0,
    usd_saved: 0,
    latency_saved_ms: 0,
    hit_rate: 0,
  };

  constructor(
    maxEntries: number = 5000,
    maxTotalBytes: number = 50 * 1024 * 1024,
    maxEntryBytes: number = 256 * 1024,
    ttlMs: number = 24 * 60 * 60 * 1000
  ) {
    this.maxEntries = maxEntries;
    this.maxTotalBytes = maxTotalBytes;
    this.maxEntryBytes = maxEntryBytes;
    this.ttlMs = ttlMs;
  }

  private buildCacheKey(messages: CacheMessage[], opts: CacheOptions): string {
    const payload = {
      org_id: opts.org_id,
      virtual_key_id: opts.virtual_key_id,
      model: opts.model,
      provider: opts.provider ?? "default",
      temperature: opts.temperature ?? null,
      max_tokens: opts.max_tokens ?? null,
      top_p: opts.top_p ?? null,
      seed: opts.seed ?? null,
      stop: opts.stop ?? null,
      response_format: opts.response_format ?? null,
      stream: opts.stream ?? false,
      messages: messages,
    };

    const canonicalObj = sortObjectKeys(payload);
    const canonicalString = JSON.stringify(canonicalObj);
    return crypto.createHash("sha256").update(canonicalString).digest("hex");
  }

  private updateHitRate() {
    const totalDecided = this.stats.cache_hits + this.stats.cache_misses;
    this.stats.hit_rate = totalDecided > 0 ? Number((this.stats.cache_hits / totalDecided).toFixed(4)) : 0;
  }

  public get(
    messages: CacheMessage[],
    dlpWasModified: boolean,
    opts: CacheOptions
  ): { hit: boolean; entry?: CacheEntry; cacheHeader: "HIT" | "MISS" | "BYPASS" } {
    this.stats.total_requests++;

    if (opts.bypass_header) {
      this.stats.header_bypasses++;
      this.updateHitRate();
      return { hit: false, cacheHeader: "BYPASS" };
    }

    if (dlpWasModified) {
      this.stats.dlp_bypasses++;
      this.updateHitRate();
      return { hit: false, cacheHeader: "BYPASS" };
    }

    const isEligible = (opts.temperature === 0 || opts.seed !== undefined) && !opts.has_tools;
    if (!isEligible) {
      this.stats.ineligible_bypasses++;
      this.updateHitRate();
      return { hit: false, cacheHeader: "BYPASS" };
    }

    const key = this.buildCacheKey(messages, opts);
    const entry = this.store.get(key);

    if (!entry) {
      this.stats.cache_misses++;
      this.updateHitRate();
      return { hit: false, cacheHeader: "MISS" };
    }

    if (Date.now() - entry.cached_at > this.ttlMs) {
      this.store.delete(key);
      this.currentTotalBytes -= entry.byte_size;
      this.stats.cache_misses++;
      this.updateHitRate();
      return { hit: false, cacheHeader: "MISS" };
    }

    this.store.delete(key);
    this.store.set(key, entry);

    this.stats.cache_hits++;
    this.stats.tokens_saved += (entry.prompt_tokens + entry.completion_tokens);
    this.stats.usd_saved += entry.cost_usd;
    this.stats.latency_saved_ms += entry.latency_saved_ms;
    this.updateHitRate();

    return { hit: true, entry, cacheHeader: "HIT" };
  }

  public set(
    messages: CacheMessage[],
    dlpWasModified: boolean,
    opts: CacheOptions,
    response_text: string,
    prompt_tokens: number,
    completion_tokens: number,
    cost_usd: number,
    latency_saved_ms: number
  ): boolean {
    const isEligible = (opts.temperature === 0 || opts.seed !== undefined) && !opts.has_tools;
    if (dlpWasModified || !isEligible || opts.bypass_header) {
      return false;
    }

    const byte_size = Buffer.byteLength(response_text, "utf8");
    if (byte_size > this.maxEntryBytes) {
      return false;
    }

    const key = this.buildCacheKey(messages, opts);

    if (this.store.has(key)) {
      const existing = this.store.get(key)!;
      this.currentTotalBytes -= existing.byte_size;
      this.store.delete(key);
    }

    while (
      (this.store.size >= this.maxEntries || this.currentTotalBytes + byte_size > this.maxTotalBytes) &&
      this.store.size > 0
    ) {
      const oldestKey = this.store.keys().next().value;
      if (oldestKey !== undefined) {
        const oldestEntry = this.store.get(oldestKey)!;
        this.currentTotalBytes -= oldestEntry.byte_size;
        this.store.delete(oldestKey);
      } else {
        break;
      }
    }

    const entry: CacheEntry = {
      response_text,
      prompt_tokens,
      completion_tokens,
      cost_usd,
      latency_saved_ms,
      byte_size,
      cached_at: Date.now(),
    };

    this.store.set(key, entry);
    this.currentTotalBytes += byte_size;
    return true;
  }

  public flush(): void {
    this.store.clear();
    this.currentTotalBytes = 0;
  }

  public getFinOpsStats(): FinOpsStats {
    return { ...this.stats };
  }
}