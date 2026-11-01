import crypto from "node:crypto";

export const AUDIT_DOMAIN_SEPARATOR = "AINDIGO_AUDIT_V1";

/**
 * Fully recursive canonical JSON serializer.
 * - Sorts keys at every object level recursively.
 * - Preserves array order.
 * - Rejects undefined, functions, symbols, BigInt, non-finite numbers, cyclic objects, and unsupported object types.
 */
export function canonicalJsonStringify(val: unknown, seen = new Set<unknown>()): string {
  if (val === null || val === undefined) {
    if (val === undefined) {
      throw new Error("CANONICAL_JSON_ERROR: undefined values are not supported.");
    }
    return "null";
  }

  const t = typeof val;
  if (t === "boolean" || t === "string") {
    return JSON.stringify(val);
  }

  if (t === "number") {
    if (!Number.isFinite(val)) {
      throw new Error("CANONICAL_JSON_ERROR: non-finite numbers (NaN, Infinity) are not supported.");
    }
    return JSON.stringify(val);
  }

  if (t === "bigint" || t === "symbol" || t === "function") {
    throw new Error(`CANONICAL_JSON_ERROR: type '${t}' is not supported.`);
  }

  if (typeof val === "object") {
    if (
      val instanceof Date ||
      val instanceof Map ||
      val instanceof Set ||
      val instanceof RegExp ||
      val instanceof Error
    ) {
      throw new Error(`CANONICAL_JSON_ERROR: unsupported object type '${val.constructor.name}'.`);
    }

    if (seen.has(val)) {
      throw new Error("CANONICAL_JSON_ERROR: cyclic object detected.");
    }
    seen.add(val);

    try {
      if (Array.isArray(val)) {
        const items = val.map((item) => canonicalJsonStringify(item, seen));
        return "[" + items.join(",") + "]";
      }

      const proto = Object.getPrototypeOf(val);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error("CANONICAL_JSON_ERROR: only plain objects and arrays are supported.");
      }

      const keys = Object.keys(val as Record<string, unknown>).sort();
      const pairs: string[] = [];
      for (const k of keys) {
        const v = (val as Record<string, unknown>)[k];
        if (v === undefined) {
          throw new Error("CANONICAL_JSON_ERROR: undefined values are not supported.");
        }
        pairs.push(JSON.stringify(k) + ":" + canonicalJsonStringify(v, seen));
      }
      return "{" + pairs.join(",") + "}";
    } finally {
      seen.delete(val);
    }
  }

  throw new Error(`CANONICAL_JSON_ERROR: unsupported type '${t}'.`);
}

export interface AuditHashInputParams {
  id: string;
  timestamp: number;
  eventType: string;
  orgId: string;
  virtualKeyId: string;
  payload: Record<string, unknown> | string; // Can accept raw object or canonical string
  prevHash: string;
}

/**
 * Exact shared canonical hash input builder used by both edge proxies and the control plane aggregator.
 */
export function computeCanonicalRecordHash(params: AuditHashInputParams): { canonicalPayload: string; hashInput: string; hash: string } {
  const canonicalPayload = typeof params.payload === "string" ? params.payload : canonicalJsonStringify(params.payload);

  const hashInput = [
    AUDIT_DOMAIN_SEPARATOR,
    params.id,
    String(params.timestamp),
    params.eventType,
    params.orgId,
    params.virtualKeyId,
    canonicalPayload,
    params.prevHash,
  ].join("|");

  const hash = crypto.createHash("sha256").update(hashInput, "utf8").digest("hex");
  return { canonicalPayload, hashInput, hash };
}