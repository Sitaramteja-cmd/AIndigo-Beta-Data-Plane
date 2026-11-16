import { Buffer } from "node:buffer";

export const MAX_POLICY_PAYLOAD_BYTES = 65536;
export const MAX_CANONICAL_DEPTH = 32;

export function canonicalizePolicyPayload(
  payload: unknown,
  maxBytes: number = MAX_POLICY_PAYLOAD_BYTES
): string {
  if (
    typeof maxBytes !== "number" ||
    !Number.isSafeInteger(maxBytes) ||
    maxBytes <= 0
  ) {
    throw new Error("CANONICALIZATION_ERROR: Invalid maxBytes limit");
  }

  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new Error(
      "CANONICALIZATION_ERROR: Root policy payload must be a plain object"
    );
  }

  const activeAncestors = new Set<object>();

  function normalize(value: unknown, depth: number): unknown {
    if (depth > MAX_CANONICAL_DEPTH) {
      throw new Error(
        "CANONICALIZATION_ERROR: Maximum nesting depth exceeded"
      );
    }

    if (
      value === null ||
      typeof value === "boolean" ||
      typeof value === "string"
    ) {
      return value;
    }

    if (typeof value === "number") {
      if (!Number.isFinite(value)) {
        throw new Error(
          "CANONICALIZATION_ERROR: Non-finite numbers are not allowed"
        );
      }

      return Object.is(value, -0) ? 0 : value;
    }

    if (typeof value !== "object") {
      throw new Error(
        `CANONICALIZATION_ERROR: Unsupported value type "${typeof value}"`
      );
    }

    if (activeAncestors.has(value)) {
      throw new Error(
        "CANONICALIZATION_ERROR: Circular reference detected"
      );
    }

    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new Error(
        "CANONICALIZATION_ERROR: Symbol properties are not allowed"
      );
    }

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new Error(
          "CANONICALIZATION_ERROR: Non-plain Array prototype not allowed"
        );
      }

      const ownNames = Object.getOwnPropertyNames(value);

      if (ownNames.length !== value.length + 1) {
        throw new Error(
          "CANONICALIZATION_ERROR: Sparse arrays or custom array properties are not allowed"
        );
      }

      activeAncestors.add(value);

      try {
        const normalizedArr: unknown[] = new Array(value.length);

        // Prevent inherited toJSON methods from affecting serialization.
        Object.setPrototypeOf(normalizedArr, null);

        for (let i = 0; i < value.length; i++) {
          const idxKey = String(i);
          const desc = Object.getOwnPropertyDescriptor(value, idxKey);

          if (
            !desc ||
            !desc.enumerable ||
            !Object.prototype.hasOwnProperty.call(desc, "value")
          ) {
            throw new Error(
              "CANONICALIZATION_ERROR: Invalid, sparse, or accessor array element"
            );
          }

          if (typeof desc.value === "undefined") {
            throw new Error(
              "CANONICALIZATION_ERROR: Undefined array elements are not allowed"
            );
          }

          normalizedArr[i] = normalize(desc.value, depth + 1);
        }

        return normalizedArr;
      } finally {
        activeAncestors.delete(value);
      }
    }

    const proto = Object.getPrototypeOf(value);

    if (proto !== Object.prototype && proto !== null) {
      throw new Error(
        "CANONICALIZATION_ERROR: Non-plain object not allowed"
      );
    }

    activeAncestors.add(value);

    try {
      const ownKeys = Object.getOwnPropertyNames(value).sort();
      const sortedObj: Record<string, unknown> = Object.create(null);

      for (const key of ownKeys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);

        if (
          !descriptor ||
          !Object.prototype.hasOwnProperty.call(descriptor, "value")
        ) {
          throw new Error(
            `CANONICALIZATION_ERROR: Accessor properties are not allowed ("${key}")`
          );
        }

        if (!descriptor.enumerable) {
          throw new Error(
            `CANONICALIZATION_ERROR: Non-enumerable properties are not allowed ("${key}")`
          );
        }

        const propVal = descriptor.value;

        if (typeof propVal === "undefined") {
          throw new Error(
            `CANONICALIZATION_ERROR: Undefined property "${key}" is not allowed`
          );
        }

        Object.defineProperty(sortedObj, key, {
          value: normalize(propVal, depth + 1),
          enumerable: true,
          configurable: true,
          writable: true,
        });
      }

      return sortedObj;
    } finally {
      activeAncestors.delete(value);
    }
  }

  const normalizedRoot = normalize(payload, 0);
  const jsonString = JSON.stringify(normalizedRoot);

  if (typeof jsonString !== "string") {
    throw new Error(
      "CANONICALIZATION_ERROR: JSON serialization failed"
    );
  }

  const utf8ByteLength = Buffer.byteLength(jsonString, "utf8");

  if (utf8ByteLength > maxBytes) {
    throw new Error(
      `CANONICALIZATION_ERROR: Serialized payload (${utf8ByteLength} bytes) exceeds maximum (${maxBytes} bytes)`
    );
  }

  return jsonString;
}