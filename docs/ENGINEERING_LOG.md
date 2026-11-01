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

## [Module 2.3] Safe Exact-Match Cache & FinOps Savings Meter
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified canonical JSON composite keys, LRU eviction, byte caps, temperature/tool eligibility rules, and bypass stats separation)
- **Files Created:**
  - `packages/data-plane/src/cache/exact-cache.ts`
  - `packages/data-plane/src/cache/cache.test.ts`
- **What Changed & Why:**
  - Implemented an enterprise-grade exact-match caching layer with recursive key sorting, tenant isolation (`org_id` + `virtual_key_id`), strict DLP mutation immunity, and accurate FinOps savings tracking.
- **Verification Command:** `npx tsx packages\data-plane\src\cache\cache.test.ts`

## [Module 2.4] Production Virtual Key Vault, AAD Envelope Encryption & Micro-USD Ledger
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified AES-256-GCM with AAD binding, hash-only bearer keys, atomic two-phase micro-USD reservation, stale reservation reaper, spend_ledger auditing, live master key rotation, and secret-free diagnostics on `node:sqlite`)
- **Files Created:**
  - `packages/data-plane/src/vault/virtual-key-vault.ts`
  - `packages/data-plane/src/vault/vault.test.ts`
- **What Changed & Why:**
  - Replaced prototype in-memory vault with a crash-resilient `node:sqlite` (`DatabaseSync`) vault using integer micro-USD arithmetic, one-shot reservation handles (`authorize` / `reconcileSpend`), automatic 10-minute stale reservation reaping, multi-version key rings defaulting to the highest version, and non-enumerable secret accessors that prevent log/JSON leakage.
- **Verification Command:** `npx tsx packages\data-plane\src\vault\vault.test.ts`

## [Module 3.1] End-to-End Data Plane Request Pipeline & Orchestration
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified vault authorization, deep structural DLP over tool arguments and multimodal arrays, safe exact-match caching with $0.00 hit charges, exact-once finally reconciliation, and typed upstream error mapping)
- **Files Created:**
  - `packages/data-plane/src/pipeline/request-pipeline.ts`
  - `packages/data-plane/src/pipeline/pipeline.test.ts`
- **What Changed & Why:**
  - Wired all isolated Tier 2 engines into a single unified asynchronous request pipeline (`processChatCompletion`). Enforced zero bearer-token leakage downstream, exact-once spend reconciliation on failure or success, date-effective pricing tables, and strict streaming rejections.
- **Verification Command:** `npx tsx packages\data-plane\src\pipeline\pipeline.test.ts`

## [Module 3.2] Dynamic FinOps Governor & Model Downshifting
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified constructor validation, loop prevention, reserved spend utilization, allowed models restrictions, and absolute path execution)
- **Files Modified/Created:**
  - `packages/data-plane/src/vault/virtual-key-vault.ts`
  - `packages/data-plane/src/governor/finops-governor.ts`
  - `packages/data-plane/src/pipeline/request-pipeline.ts`
  - `packages/data-plane/src/governor/governor.test.ts`
- **Verification Command:** `npx tsx D:\aindigo\packages\data-plane\src\governor\governor.test.ts`

## [Module 3.3] SIEM Webhook Dispatcher & Tamper-Evident Audit Chain
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified recursive canonical JSON serialization, strict HMAC secret entropy rules, atomic transaction chaining, and Splunk HEC / Microsoft Sentinel webhook dispatching)
- **Files Modified/Created:**
  - `packages/data-plane/src/audit/audit-chain.ts`
  - `packages/data-plane/src/audit/audit.test.ts`
- **Verification Command:** `npx tsx D:\aindigo\packages\data-plane\src\audit\audit.test.ts`

## [Module 4.1] Control Plane Sync Protocol & Policy Distribution API
- **Date:** 2026-11-01
- **Branch:** `v2-enterprise`
- **Status:** PASSED (Verified HMAC signature verification, persistent organization policy versioning, strict multi-tenant isolation, atomic transaction rollbacks, replay protection surviving process restarts, and batch operation limits)
- **Files Modified/Created:**
  - `packages/data-plane/src/sync/control-sync.ts`
  - `packages/data-plane/src/sync/sync.test.ts`
- **Verification Command:** `npx tsx D:\aindigo\packages\data-plane\src\sync\sync.test.ts`
