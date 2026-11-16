import test from "node:test";
import assert from "node:assert/strict";
import {
  canonicalizePolicyPayload,
  MAX_CANONICAL_DEPTH,
} from "./policy-canonical-json.js";

test("Step 3E.2.2 Hardened Canonical JSON Serializer Suite (12 Scenarios)", async (t) => {
  await t.test("1. Identical output regardless of object property insertion order", () => {
    const objA = {
      z: 1,
      a: { y: true, b: "hello" },
      m: [3, 2, 1],
    };
    const objB = {
      m: [3, 2, 1],
      a: { b: "hello", y: true },
      z: 1,
    };

    const canonA = canonicalizePolicyPayload(objA);
    const canonB = canonicalizePolicyPayload(objB);

    assert.equal(canonA, canonB);
    assert.equal(canonA, '{"a":{"b":"hello","y":true},"m":[3,2,1],"z":1}');
  });

  await t.test("2. Correct preservation of array order", () => {
    const payload = { items: ["z", "a", "m", 10, 2] };
    assert.equal(
      canonicalizePolicyPayload(payload),
      '{"items":["z","a","m",10,2]}'
    );
  });

  await t.test("3. Shared non-circular DAG object and array references accepted", () => {
    const sharedLeaf = { enabled: true, provider: "openai" };
    const sharedArray = ["gpt-4o", "claude-3-7-sonnet"];
    const payload = {
      first: sharedLeaf,
      second: sharedLeaf,
      modelsA: sharedArray,
      modelsB: sharedArray,
    };

    const result = canonicalizePolicyPayload(payload);
    assert.equal(
      result,
      '{"first":{"enabled":true,"provider":"openai"},"modelsA":["gpt-4o","claude-3-7-sonnet"],"modelsB":["gpt-4o","claude-3-7-sonnet"],"second":{"enabled":true,"provider":"openai"}}'
    );
  });

  await t.test("4. Circular object and array references rejected", () => {
    const cyclicObj: Record<string, unknown> = { a: 1 };
    cyclicObj.self = cyclicObj;
    assert.throws(
      () => canonicalizePolicyPayload(cyclicObj),
      /Circular reference detected/
    );

    const cyclicArr: unknown[] = [];
    cyclicArr.push(cyclicArr);
    assert.throws(
      () => canonicalizePolicyPayload({ arr: cyclicArr }),
      /Circular reference detected/
    );
  });

  await t.test("5. BigInt, undefined, functions, and symbols rejected", () => {
    assert.throws(
      () => canonicalizePolicyPayload({ count: 10n }),
      /Unsupported value type "bigint"/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ missing: undefined }),
      /Undefined property "missing" is not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ list: [1, undefined, 3] }),
      /Undefined array elements are not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ fn: () => {} }),
      /Unsupported value type "function"/
    );

    const symObj: Record<string | symbol, unknown> = { a: 1 };
    symObj[Symbol("secret")] = "hidden";
    assert.throws(
      () => canonicalizePolicyPayload(symObj),
      /Symbol properties are not allowed/
    );
  });

  await t.test("6. NaN, Infinity, and -Infinity rejected", () => {
    assert.throws(
      () => canonicalizePolicyPayload({ v: Number.NaN }),
      /Non-finite numbers are not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ v: Number.POSITIVE_INFINITY }),
      /Non-finite numbers are not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ v: Number.NEGATIVE_INFINITY }),
      /Non-finite numbers are not allowed/
    );
  });

  await t.test("7. Negative zero normalized to positive zero", () => {
    const result = canonicalizePolicyPayload({ zero: -0, nested: [-0] });
    assert.equal(result, '{"nested":[0],"zero":0}');
  });

  await t.test("8. Non-plain objects and sparse/modified arrays rejected", () => {
    assert.throws(
      () => canonicalizePolicyPayload({ date: new Date() }),
      /Non-plain object not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ map: new Map() }),
      /Non-plain object not allowed/
    );
    assert.throws(
      () => canonicalizePolicyPayload({ buf: Buffer.from("abc") }),
      /Non-plain object not allowed/
    );

    // Sparse array check
    const sparse: unknown[] = [];
    sparse[0] = "a";
    sparse[2] = "c";
    assert.throws(
      () => canonicalizePolicyPayload({ arr: sparse }),
      /Sparse arrays or custom array properties are not allowed/
    );

    // Array with attached custom property check
    const customPropArr: unknown[] = ["a", "b"];
    (customPropArr as unknown as Record<string, unknown>).extra = "injected";
    assert.throws(
      () => canonicalizePolicyPayload({ arr: customPropArr }),
      /Sparse arrays or custom array properties are not allowed/
    );
  });

  await t.test("9. UTF-8 multi-byte limit strictly enforced", () => {
    // 25 emoji characters = 100 UTF-8 bytes (4 bytes each), though .length is 50 UTF-16 units
    const payload = { data: "🔒".repeat(25) };
    assert.throws(
      () => canonicalizePolicyPayload(payload, 80),
      /exceeds maximum \(80 bytes\)/
    );
    assert.doesNotThrow(() => canonicalizePolicyPayload(payload, 120));
  });

  await t.test("10. Excessive nesting depth rejected", () => {
    let deep: Record<string, unknown> = { leaf: "ok" };
    for (let i = 0; i < MAX_CANONICAL_DEPTH + 1; i++) {
      deep = { child: deep };
    }
    assert.throws(
      () => canonicalizePolicyPayload(deep),
      /Maximum nesting depth exceeded/
    );
  });

  await t.test("11. Getter properties rejected without executing getter code", () => {
    let getterExecuted = false;
    const malicious = {
      safe: "ok",
    };
    Object.defineProperty(malicious, "trap", {
      enumerable: true,
      get() {
        getterExecuted = true;
        return "compromised";
      },
    });

    assert.throws(
      () => canonicalizePolicyPayload(malicious),
      /Accessor properties are not allowed \("trap"\)/
    );
    assert.equal(getterExecuted, false, "Getter must never be executed!");
  });

  await t.test("12. __proto__ property handled safely without prototype mutation", () => {
    const raw = JSON.parse('{"b":1,"__proto__":{"admin":true},"a":2}');
    const canonical = canonicalizePolicyPayload(raw);
    assert.equal(canonical, '{"__proto__":{"admin":true},"a":2,"b":1}');
    assert.equal(({} as Record<string, unknown>).admin, undefined);
  });
});