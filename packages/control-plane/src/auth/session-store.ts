import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";

import {
  createSessionToken,
  hashSessionToken,
  verifySessionToken,
  getSessionExpiry,
} from "./session.js";

export interface SessionTenant {
  tenant_id: string;
  org_name: string | null;
  email: string | null;
  subscription_tier: string | null;
  monthly_request_limit: number | null;
}

export interface CreatedSession {
  token: string;
  sessionId: string;
  expiresAt: number;
}

export function initializeSessionStore(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id TEXT PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER,
      FOREIGN KEY (tenant_id)
        REFERENCES tenants(tenant_id)
        ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_user_sessions_tenant
      ON user_sessions(tenant_id);

    CREATE INDEX IF NOT EXISTS idx_user_sessions_expiry
      ON user_sessions(expires_at);
  `);
}

export function createUserSession(
  db: DatabaseSync,
  tenantId: string,
  now: number = Date.now(),
): CreatedSession {
  if (typeof tenantId !== "string" || !tenantId.trim()) {
    throw new Error("A valid tenant ID is required.");
  }

  if (!Number.isSafeInteger(now) || now <= 0) {
    throw new Error("A valid session creation timestamp is required.");
  }

  const tenant = db.prepare(`
    SELECT tenant_id FROM tenants WHERE tenant_id = ?
  `).get(tenantId) as { tenant_id: string } | undefined;

  if (!tenant) {
    throw new Error("Cannot create a session for an unknown tenant.");
  }

  const token = createSessionToken();
  const sessionId = randomUUID();
  const expiresAt = getSessionExpiry(new Date(now)).getTime();

  db.prepare(`
    INSERT INTO user_sessions (
      session_id, tenant_id, token_hash, created_at, expires_at
    ) VALUES (?, ?, ?, ?, ?)
  `).run(sessionId, tenantId, hashSessionToken(token), now, expiresAt);

  return { token, sessionId, expiresAt };
}

export function resolveUserSession(
  db: DatabaseSync,
  token: string,
  now: number = Date.now(),
): SessionTenant | null {
  if (
    typeof token !== "string" ||
    !token.startsWith("aindigo_sess_") ||
    !Number.isSafeInteger(now) ||
    now <= 0
  ) {
    return null;
  }

  const tokenHash = hashSessionToken(token);

  const session = db.prepare(`
    SELECT
      s.token_hash,
      t.tenant_id,
      t.org_name,
      t.email,
      t.subscription_tier,
      t.monthly_request_limit
    FROM user_sessions s
    INNER JOIN tenants t ON t.tenant_id = s.tenant_id
    WHERE s.token_hash = ?
      AND s.revoked_at IS NULL
      AND s.expires_at > ?
    LIMIT 1
  `).get(tokenHash, now) as
    | (SessionTenant & { token_hash: string })
    | undefined;

  if (!session || !verifySessionToken(token, session.token_hash)) {
    return null;
  }

  const { token_hash: _tokenHash, ...safeTenant } = session;
  return safeTenant;
}

export function revokeUserSession(
  db: DatabaseSync,
  token: string,
  now: number = Date.now(),
): boolean {
  if (
    typeof token !== "string" ||
    !token.startsWith("aindigo_sess_") ||
    !Number.isSafeInteger(now) ||
    now <= 0
  ) {
    return false;
  }

  const result = db.prepare(`
    UPDATE user_sessions
    SET revoked_at = ?
    WHERE token_hash = ?
      AND revoked_at IS NULL
  `).run(now, hashSessionToken(token));

  return Number(result.changes) === 1;
}
