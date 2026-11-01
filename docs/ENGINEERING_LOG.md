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
