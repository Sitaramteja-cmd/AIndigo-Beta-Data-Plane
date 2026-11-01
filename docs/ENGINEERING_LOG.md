# AIndigo v2.0 Enterprise — Engineering & Architecture Log

## [Module 0.2] Standalone Ed25519 Asymmetric Node Identity & Offline Verifier
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise` (Isolated from `main` beta)
- **Node Identity Generated:** `node_e7adede03740be62`
- **Files Created:**
  - `packages/data-plane/src/crypto/node-identity.ts`
  - `packages/cli/verify.ts`
- **What Changed & Why:**
  - Introduced native Node.js `ed25519` asymmetric keypair generation per Data Plane node stored in `.keys/` (gitignored).
  - Replaces shared-secret HMAC receipt signing with asymmetric Ed25519 signatures over canonicalized SHA-256 receipt hashes so the Cloud Control Plane can verify receipts without ever holding the node's signing key.
  - Added `packages/cli/verify.ts` to verify receipt chains offline using only `node_ed25519_public.pem` and detect payload tampering or chain gaps.
- **Verification Command:** `npx tsx packages/cli/verify.ts --selftest`

## [Module 0.3] Strict Egress Allowlist Guard & Canary Leakage CI Test
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (All 4 verification checks green)
- **Files Created:**
  - `packages/data-plane/src/egress/egress-guard.ts`
  - `packages/cli/canary-test.ts`
- **What Changed & Why:**
  - Enforced a 16-key schema allowlist and forbidden secret regex checks on all outbound control plane payloads.
  - Verified local `egress-audit.jsonl` auditing guarantees zero leakage of sensitive customer prompts.
- **Verification Command:** `npm run canary`

## [Module 1.1] PostgreSQL Schema & Tenant Isolation (Control Plane)
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Files Created:**
  - `packages/control-plane/src/db/schema.ts`
  - `packages/control-plane/src/db/tenant-isolation.test.ts`
- **What Changed & Why:**
  - Established normalized Drizzle ORM schema for PostgreSQL (`orgs`, `nodes`, `virtual_keys`, `receipts`) keyed by `org_id`.
  - Implemented and verified tenant scoping middleware ensuring strict data isolation between enterprise organizations.
- **Verification Command:** `npx tsx packages/control-plane/src/db/tenant-isolation.test.ts`

## [Module 1.2] Production Auth & Security (Argon2id Hashing)
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Files Created:**
  - `packages/control-plane/src/auth/password.ts`
  - `packages/control-plane/src/auth/auth.test.ts`
- **What Changed & Why:**
  - Implemented Argon2id password hashing and verification module for secure enterprise user authentication.
  - Verified unique salt generation, correct password validation, and incorrect password rejection.
- **Verification Command:** `npx tsx packages/control-plane/src/auth/auth.test.ts`

## [Module 1.3] Signed Policy Bundles & Offline License Verification
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Files Created:**
  - `packages/control-plane/src/licensing/bundle-signer.ts`
  - `packages/control-plane/src/licensing/licensing.test.ts`
- **What Changed & Why:**
  - Implemented Ed25519-signed policy bundle generation and offline verification for decentralized enterprise nodes.
  - Verified tamper detection for unauthorized plan limit changes and expiration checks.
- **Verification Command:** `npx tsx packages/control-plane/src/licensing/licensing.test.ts`

## [Module 1.4] SQLite Telemetry Outbox & Resilient Batch Sync
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Files Created:**
  - `packages/data-plane/src/sync/outbox.ts`
  - `packages/data-plane/src/sync/outbox.test.ts`
- **What Changed & Why:**
  - Implemented the local Outbox pattern for decentralized Data Plane telemetry with batched queueing, exponential backoff retries, and failure handling.
- **Verification Command:** `npx tsx packages/data-plane/src/sync/outbox.test.ts`

## [Module 2.1] Streaming (SSE) Sliding-Window DLP Transform
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified split-chunk secret interception)
- **Files Created:**
  - `packages/data-plane/src/proxy/sse-transform.ts`
  - `packages/data-plane/src/proxy/sse.test.ts`
- **What Changed & Why:**
  - Built custom Node.js `TransformStream` with trailing lookbehind buffer to intercept and redact secrets split across Server-Sent Event (SSE) chunk boundaries for IDE assistants.
- **Verification Command:** `npx tsx packages/data-plane/src/proxy/sse.test.ts`

## [Module 2.2] Mathematical Checksum DLP Engine & False-Positive Prevention
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified Luhn algorithm, PAN structural checks, and false-positive order ID filtering)
- **Files Created:**
  - `packages/data-plane/src/dlp/checksum-engine.ts`
  - `packages/data-plane/src/dlp/checksum.test.ts`
- **What Changed & Why:**
  - Implemented mathematical checksum validation to eliminate false positives on random 16-digit serial numbers or transaction IDs while catching genuine credit cards and sensitive PAN records.
- **Verification Command:** `npx tsx packages/data-plane/src/dlp/checksum.test.ts`
