import 'dotenv/config';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { URL } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { HttpRequestLifecycle } from './http/request-lifecycle.js';
import { InMemoryRateLimiter, type RateLimitEndpoint } from './http/rate-limiter.js';
import { createGracefulShutdown } from './http/shutdown-orchestrator.js';
import {
  hashPassword as hashPasswordArgon2,
  verifyPassword,
} from './auth/password.js';
import {
  initializeSessionStore,
  createUserSession,
  resolveUserSession,
  revokeUserSession,
} from './auth/session-store.js';
import {
  initializeNodeEnrollmentStore,
  createEnrollmentCode,
  revokeEnrollmentCode,
  createEnrollmentChallenge,
  completeNodeEnrollment,
  resolveEnrollmentCodeTenant,
  resolveEnrollmentChallengeTenant,
  getRegisteredNode,
  consumeNodeStatusNonce,
  updateRegisteredNodeLastSeen,
  revokeRegisteredNode,
} from './enrollment/node-enrollment-store.js';
import {
  loadControlPlaneSigningKeyFromEnvironment,
} from './crypto/control-plane-signing-config.js';
import {
  verifyNodeStatusRequest,
  signNodeStatusResponse,
} from './crypto/node-status.js';

// Load and validate the signing identity before database initialization.
const controlPlaneSigningKey = loadControlPlaneSigningKeyFromEnvironment(process.env);

// Outbound SIEM delivery remains disabled until SSRF and secret-storage controls are implemented.
const SIEM_OUTBOUND_DELIVERY_ENABLED = false;

const dbPath = process.env.CONTROL_PLANE_DB_PATH
  ? path.resolve(process.env.CONTROL_PLANE_DB_PATH)
  : path.resolve(process.cwd(), 'control-plane-saas.sqlite');

const db = new DatabaseSync(dbPath);

db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA synchronous = NORMAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS tenants (
    tenant_id TEXT PRIMARY KEY,
    org_name TEXT,
    email TEXT UNIQUE,
    password_hash TEXT,
    subscription_tier TEXT DEFAULT 'COMMUNITY',
    monthly_request_limit INTEGER DEFAULT 10000,
    cluster_sync_token TEXT,
    siem_webhook_url TEXT DEFAULT '',
    siem_auth_header TEXT DEFAULT '',
    siem_format TEXT DEFAULT 'json',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS synced_receipts (
    receipt_id TEXT PRIMARY KEY,
    tenant_id TEXT,
    department TEXT,
    model_requested TEXT,
    model_routed TEXT,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    cost_usd REAL,
    finops_saved_usd REAL,
    dlp_flags TEXT,
    prompt_sha256 TEXT,
    previous_receipt_hash TEXT,
    receipt_hmac TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_webhook_url TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_auth_header TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_format TEXT DEFAULT 'json'`); } catch {}
try {
  db.exec(`ALTER TABLE synced_receipts ADD COLUMN prompt_sha256 TEXT DEFAULT ''`);
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);

  if (!message.includes('duplicate column name')) {
    throw error;
  }
}

// Initialize persistent browser sessions after tenant schema is available.
initializeSessionStore(db);
initializeNodeEnrollmentStore(db);

function legacyHashPassword(pw: string): string {
  return crypto.createHash('sha256').update(pw + '_aindigo_salt').digest('hex');
}

function formatReceiptAsCEF(r: any): string {
  const flags = r.dlp_flags || '[]';
  const severity = flags !== '[]' ? 8 : 3;
  return `CEF:0|AIndigo|AISecurityGateway|1.00.00|DLP_GOVERNANCE|Governed AI Agent Turn|${severity}|receiptId=${r.receipt_id} tenant=${r.tenant_id} dept=${r.department} modelRequested=${r.model_requested} modelRouted=${r.model_routed} costUsd=${r.cost_usd} dlpFlags=${flags} merkleHmac=${r.receipt_hmac} rt=${r.timestamp}`;
}

async function forwardToCustomerSiem(tenant: any, receipts: any[]) {
  if (!tenant || !tenant.siem_webhook_url) return;
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (tenant.siem_auth_header) {
      headers['Authorization'] = tenant.siem_auth_header;
    }
    const payload = tenant.siem_format === 'cef'
      ? { events: receipts.map(formatReceiptAsCEF) }
      : { source: 'aindigo-control-plane', version: 'v1.00.00-beta', tenantId: tenant.tenant_id, events: receipts };

    await fetch(tenant.siem_webhook_url, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error('[SIEM Push Warning] Could not reach webhook:', (err as Error).message);
  }
}

function resolvePortalHtmlPath(): string {
  const candidates = [
    path.resolve(process.cwd(), 'packages/control-plane/src/portal.html'),
    path.resolve(process.cwd(), 'src/portal.html'),
    path.resolve(process.cwd(), 'portal.html')
  ];

  const existingPath = candidates.find((candidate) =>
    fs.existsSync(candidate) && fs.statSync(candidate).isFile()
  );

  if (!existingPath) {
    throw new Error(
      `portal.html not found. Checked: ${candidates.join(', ')}`
    );
  }

  return existingPath;
}

class RequestBodyError extends Error {
  constructor(
    message: string,
    public readonly statusCode: 400 | 413
  ) {
    super(message);
    this.name = 'RequestBodyError';
  }
}

function readJsonBody(
  req: http.IncomingMessage,
  maxBytes = 1_048_576
): Promise<any> {
  return new Promise((resolve, reject) => {
    const contentLength = req.headers['content-length'];

    if (contentLength !== undefined) {
      const declaredLength = Number(contentLength);

      if (
        !Number.isSafeInteger(declaredLength) ||
        declaredLength < 0
      ) {
        reject(new RequestBodyError('Invalid Content-Length', 400));
        req.resume();
        return;
      }

      if (declaredLength > maxBytes) {
        reject(new RequestBodyError('Request body too large', 413));
        req.resume();
        return;
      }
    }

    const chunks: Buffer[] = [];
    let receivedBytes = 0;
    let settled = false;

    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      chunks.length = 0;
      reject(error);
    };

    req.on('data', (chunk: Buffer | string) => {
      if (settled) return;

      const buffer = Buffer.isBuffer(chunk)
        ? chunk
        : Buffer.from(chunk);

      receivedBytes += buffer.length;

      if (receivedBytes > maxBytes) {
        fail(new RequestBodyError('Request body too large', 413));
        return;
      }

      chunks.push(buffer);
    });

    req.on('end', () => {
      if (settled) return;

      if (receivedBytes === 0) {
        fail(new RequestBodyError('Request body is required', 400));
        return;
      }

      try {
        const body = Buffer.concat(chunks).toString('utf8');
        const parsed = JSON.parse(body);

        if (
          parsed === null ||
          typeof parsed !== 'object' ||
          Array.isArray(parsed)
        ) {
          fail(new RequestBodyError('JSON body must be an object', 400));
          return;
        }

        settled = true;
        resolve(parsed);
      } catch {
        fail(new RequestBodyError('Malformed JSON body', 400));
      }
    });

    req.on('aborted', () => {
      fail(new RequestBodyError('Request body was interrupted', 400));
    });

    req.on('error', () => {
      fail(new RequestBodyError('Unable to read request body', 400));
    });
  });
}

function sendJson(res: http.ServerResponse, status: number, data: any) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
  });
  res.end(JSON.stringify(data));
}

const authRateLimiter = new InMemoryRateLimiter();

function checkAuthRateLimit(
  req: http.IncomingMessage,
  endpoint: RateLimitEndpoint
): number | null {
  return authRateLimiter.check(
    endpoint,
    req.socket.remoteAddress || 'unknown',
  );
}
function sendRateLimitResponse(
  res: http.ServerResponse,
  retryAfterSeconds: number
) {
  res.writeHead(429, {
    'Content-Type': 'application/json; charset=utf-8',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Retry-After': String(retryAfterSeconds)
  });

  res.end(JSON.stringify({
    error: 'Too many requests. Please try again later.',
    retryAfterSeconds
  }));
}
function getBrowserSessionTenant(req: http.IncomingMessage) {
  const authorization = req.headers.authorization || '';
  const token = authorization.startsWith('Bearer ')
    ? authorization.slice(7).trim()
    : '';

  return token ? resolveUserSession(db, token) : null;
}

const requestLifecycle = new HttpRequestLifecycle();

const server = http.createServer(async (req, res) => {
  const releaseRequest = requestLifecycle.tryAcquire();

  if (!releaseRequest) {
    res.writeHead(503, {
      'Content-Type': 'application/json',
      'Connection': 'close',
      'Retry-After': '5',
    });

    res.end(JSON.stringify({
      error: 'SERVER_DRAINING',
    }));

    return;
  }
  try {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || '127.0.0.1:3000'}`);
  const pathname = parsedUrl.pathname;

  // Browser session introspection
  if (req.method === 'GET' && pathname === '/api/v1/auth/session') {
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    return sendJson(res, 200, { authenticated: true, tenant });
  }

  // Revoke the current browser session
  if (req.method === 'POST' && pathname === '/api/v1/auth/logout') {
    const authorization = req.headers.authorization || '';
    const token = authorization.startsWith('Bearer ')
      ? authorization.slice(7).trim()
      : '';

    if (!token || !revokeUserSession(db, token)) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    return sendJson(res, 200, { status: 'logged_out' });
  }

  // --------------------------------------------------
  // Secure Data Plane Node Enrollment API
  // --------------------------------------------------

  // Data Plane node status check: authenticated by its registered Ed25519 key.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/status'
  ) {
    const ipRetryAfter = checkAuthRateLimit(req, 'node-status-ip');

    if (ipRetryAfter !== null) {
      return sendRateLimitResponse(res, ipRetryAfter);
    }

    let body: any;

    try {
      body = await readJsonBody(req, 16_384);
    } catch (error) {
      if (error instanceof RequestBodyError) {
        return sendJson(res, error.statusCode, {
          error: error.message,
        });
      }
      throw error;
    }

    if (
      !body.payload ||
      typeof body.payload.nodeId !== 'string' ||
      typeof body.payload.tenantId !== 'string'
    ) {
      return sendJson(res, 400, {
        error: 'Invalid node-status request',
      });
    }

    const node = getRegisteredNode(
      db,
      body.payload.tenantId,
      body.payload.nodeId,
    );

    if (!node) {
      return sendJson(res, 404, {
        error: 'Registered node not found',
      });
    }

    const nowMs = Date.now();
    const verifiedPayload = verifyNodeStatusRequest(
      body,
      node,
      nowMs,
    );

    if (!verifiedPayload) {
      return sendJson(res, 401, {
        error: 'Invalid or expired node-status authentication',
      });
    }

    // Apply the node-specific limit only after cryptographic authentication.
    const nodeRetryAfter = authRateLimiter.check(
      'node-status-node',
      node.node_id,
    );

    if (nodeRetryAfter !== null) {
      return sendRateLimitResponse(res, nodeRetryAfter);
    }

    if (!controlPlaneSigningKey) {
      return sendJson(res, 503, {
        error: 'Node status signing service is unavailable',
      });
    }

    try {
      const signedResponse = signNodeStatusResponse({
        schemaVersion: '1.0',
        nodeId: node.node_id,
        tenantId: node.tenant_id,
        leaseId: node.lease_id!,
        requestNonce: verifiedPayload.nonce,
        status: node.status,
        checkedAt: new Date(nowMs).toISOString(),
        keyId: controlPlaneSigningKey.keyId,
      }, controlPlaneSigningKey);

      // Persist replay protection only after successful verification and signing.
      const nonceConsumed = consumeNodeStatusNonce(
        db,
        node.node_id,
        verifiedPayload.nonce,
        nowMs,
      );

      if (!nonceConsumed) {
        return sendJson(res, 409, {
          error: 'Node-status request replay detected',
        });
      }

      const lastSeenUpdated = updateRegisteredNodeLastSeen(
        db,
        node.tenant_id,
        node.node_id,
        nowMs,
      );

      if (!lastSeenUpdated) {
        return sendJson(res, 409, {
          error: 'Registered node state changed during status check',
        });
      }

      return sendJson(res, 200, signedResponse);
    } catch (error) {
      console.error('[node-status] Status request failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to process node-status request',
      });
    }
  }
  // Create a short-lived enrollment code for the authenticated tenant.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/enrollment-codes'
  ) {
    const retryAfter = checkAuthRateLimit(req, 'enrollment-code-create');
    if (retryAfter !== null) {
      return sendRateLimitResponse(res, retryAfter);
    }
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    try {
      const body = await readJsonBody(req);
      const result = createEnrollmentCode(db, tenant.tenant_id, body);

      // Plaintext enrollment code is returned only once.
      return sendJson(res, 201, {
        enrollmentCode: result.enrollmentCode,
        expiresAt: result.expiresAt,
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'ZodError') {
        return sendJson(res, 400, {
          error: 'Invalid enrollment-code request',
        });
      }

      console.error('[node-enrollment] Code creation failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to create enrollment code',
      });
    }
  }

  // Revoke an unused enrollment code belonging to the authenticated tenant.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/enrollment-codes/revoke'
  ) {
    const retryAfter = checkAuthRateLimit(req, 'enrollment-code-revoke');
    if (retryAfter !== null) {
      return sendRateLimitResponse(res, retryAfter);
    }
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    try {
      const body = await readJsonBody(req);

      if (
        !body ||
        typeof body.enrollmentCode !== 'string'
      ) {
        return sendJson(res, 400, {
          error: 'Invalid enrollment-code request',
        });
      }

      const revoked = revokeEnrollmentCode(
        db,
        tenant.tenant_id,
        body.enrollmentCode
      );

      if (!revoked) {
        return sendJson(res, 404, {
          error: 'Enrollment code not found or no longer active',
        });
      }

      return sendJson(res, 200, {
        revoked: true,
      });
    } catch (error) {
      if (error instanceof Error && error.name === 'ZodError') {
        return sendJson(res, 400, {
          error: 'Invalid enrollment-code request',
        });
      }

      console.error('[node-enrollment] Code revocation failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to revoke enrollment code',
      });
    }
  }

  // Revoke a registered Data Plane node belonging to the authenticated tenant.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/revoke'
  ) {
    const retryAfter = checkAuthRateLimit(req, 'node-revoke');

    if (retryAfter !== null) {
      return sendRateLimitResponse(res, retryAfter);
    }

    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    try {
      const body = await readJsonBody(req);

      if (
        !body ||
        typeof body.nodeId !== 'string' ||
        !body.nodeId.trim() ||
        body.nodeId.trim().length > 256
      ) {
        return sendJson(res, 400, {
          error: 'Invalid node-revocation request',
        });
      }

      const nodeId = body.nodeId.trim();
      const node = getRegisteredNode(db, tenant.tenant_id, nodeId);

      if (!node) {
        return sendJson(res, 404, {
          error: 'Registered node not found',
        });
      }

      if (node.status !== 'ACTIVE') {
        return sendJson(res, 409, {
          error: 'Node is already revoked or inactive',
        });
      }

      const revokedAt = Date.now();
      const revoked = revokeRegisteredNode(
        db,
        tenant.tenant_id,
        nodeId,
        revokedAt,
      );

      if (!revoked) {
        return sendJson(res, 409, {
          error: 'Node state changed; refresh and retry if required',
        });
      }

      return sendJson(res, 200, {
        revoked: true,
        nodeId,
        revokedAt,
      });
    } catch (error) {
      console.error('[node-enrollment] Registered-node revocation failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to revoke registered node',
      });
    }
  }
  // Data Plane proves possession of an active enrollment code.
  // Tenant identity is resolved from the stored code hash.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/enrollment/challenge'
  ) {
    const retryAfter = checkAuthRateLimit(req, 'enrollment-challenge');
    if (retryAfter !== null) {
      return sendRateLimitResponse(res, retryAfter);
    }
    let body: any;

    try {
      body = await readJsonBody(req);
    } catch (error) {
      throw error;
    }

    let tenantId: string | null;

    try {
      tenantId = resolveEnrollmentCodeTenant(
        db,
        body.enrollmentCode
      );
    } catch {
      return sendJson(res, 400, {
        error: 'Invalid or expired enrollment code',
      });
    }

    if (!tenantId) {
      return sendJson(res, 400, {
        error: 'Invalid or expired enrollment code',
      });
    }

    try {
      const challenge = createEnrollmentChallenge(
        db,
        tenantId,
        body
      );

      return sendJson(res, 200, challenge);
    } catch (error) {
      const message = error instanceof Error ? error.message : '';

      if (message.includes('already registered')) {
        return sendJson(res, 409, {
          error: 'Node is already registered',
        });
      }

      if (
        message.startsWith('NODE_ENROLLMENT_ERROR:') ||
        (error instanceof Error && error.name === 'ZodError')
      ) {
        return sendJson(res, 400, {
          error: 'Node enrollment challenge could not be created',
        });
      }

      console.error('[node-enrollment] Challenge creation failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to create enrollment challenge',
      });
    }
  }

  // Data Plane submits its signed proof.
  // Tenant identity is resolved from the stored challenge.
  if (
    req.method === 'POST' &&
    pathname === '/api/v1/nodes/enrollment/proof'
  ) {
    const retryAfter = checkAuthRateLimit(req, 'enrollment-proof');
    if (retryAfter !== null) {
      return sendRateLimitResponse(res, retryAfter);
    }
    const body = await readJsonBody(req);

    let tenantId: string | null;

    try {
      tenantId = resolveEnrollmentChallengeTenant(
        db,
        body.challengeId
      );
    } catch {
      return sendJson(res, 400, {
        error: 'Invalid enrollment challenge',
      });
    }

    if (!tenantId) {
      return sendJson(res, 400, {
        error: 'Invalid, expired, or already consumed enrollment challenge',
      });
    }

    // Never issue an unsigned lease.
    if (!controlPlaneSigningKey) {
      return sendJson(res, 503, {
        error: 'Node enrollment signing service is unavailable',
      });
    }

    try {
      const result = completeNodeEnrollment(
        db,
        tenantId,
        body,
        controlPlaneSigningKey
      );

      return sendJson(res, 200, {
        nodeId: result.nodeId,
        tenantId: result.tenantId,
        publicKeyFingerprint: result.publicKeyFingerprint,
        label: result.label,
        enrolledAt: result.enrolledAt,
        signedLease: result.signedLease,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : '';

      if (message.includes('UNIQUE constraint failed')) {
        return sendJson(res, 409, {
          error: 'Node registration conflict',
        });
      }

      if (
        message.startsWith('NODE_ENROLLMENT_ERROR:') ||
        (error instanceof Error && error.name === 'ZodError')
      ) {
        return sendJson(res, 400, {
          error: 'Node enrollment proof is invalid or expired',
        });
      }

      console.error('[node-enrollment] Proof verification failed:', error);

      return sendJson(res, 500, {
        error: 'Unable to complete node enrollment',
      });
    }
  }

  // Serve Portal UI
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    const htmlPath = resolvePortalHtmlPath();
    if (fs.existsSync(htmlPath)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(fs.readFileSync(htmlPath, 'utf8'));
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('portal.html not found at ' + htmlPath);
  }

// Register Account
if (req.method === 'POST' && pathname === '/api/v1/auth/register') {
  const retryAfter = checkAuthRateLimit(req, 'register');
  if (retryAfter !== null) {
    return sendRateLimitResponse(res, retryAfter);
  }
  const { orgName, email, password } = await readJsonBody(req);

  if (
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    !password
  ) {
    return sendJson(res, 400, {
      error: 'Email and password required'
    });
  }

  let passwordHash: string;

  try {
    passwordHash = await hashPasswordArgon2(password);
  } catch {
    return sendJson(res, 400, {
      error: 'Password must be at least 8 characters long.'
    });
  }

  const existing = db.prepare(
    `SELECT * FROM tenants WHERE email = ?`
  ).get(email.trim());

  if (existing) {
    return sendJson(res, 400, {
      error: 'Account already exists with this email. Please Log In.'
    });
  }

  const tenantId = 'org_' + crypto.randomBytes(4).toString('hex');
  const syncToken = 'aindigo_cst_' + crypto.randomBytes(16).toString('hex');

  db.prepare(`
    INSERT INTO tenants (
      tenant_id,
      org_name,
      email,
      password_hash,
      subscription_tier,
      monthly_request_limit,
      cluster_sync_token
    )
    VALUES (?, ?, ?, ?, 'COMMUNITY', 10000, ?)
  `).run(
    tenantId,
    orgName || email.trim(),
    email.trim(),
    passwordHash,
    syncToken
  );

  const tenant = db.prepare(`
  SELECT tenant_id, org_name, email, subscription_tier,
         monthly_request_limit
  FROM tenants
  WHERE tenant_id = ?
`).get(tenantId);

  const browserSession = createUserSession(db, tenantId);

  return sendJson(res, 200, {
    token: syncToken,
    sessionToken: browserSession.token,
    sessionExpiresAt: browserSession.expiresAt,
    tenant
  });
}

  // Login Account
if (req.method === 'POST' && pathname === '/api/v1/auth/login') {
  const retryAfter = checkAuthRateLimit(req, 'login');
  if (retryAfter !== null) {
    return sendRateLimitResponse(res, retryAfter);
  }
  const { email, password } = await readJsonBody(req);

  if (
    typeof email !== 'string' ||
    !email.trim() ||
    typeof password !== 'string' ||
    !password
  ) {
    return sendJson(res, 401, {
      error: 'Invalid email or password'
    });
  }

  const tenant: any = db.prepare(`
  SELECT
    tenant_id,
    org_name,
    email,
    password_hash,
    subscription_tier,
    monthly_request_limit,
    cluster_sync_token
  FROM tenants
  WHERE email = ?
`).get(email.trim());

  if (!tenant || typeof tenant.password_hash !== 'string') {
    return sendJson(res, 401, {
      error: 'Invalid email or password'
    });
  }

  let passwordValid = false;
  const storedHash = tenant.password_hash;

  try {
    if (storedHash.startsWith('$argon2id$')) {
      // Verify modern Argon2id password
      passwordValid = await verifyPassword(storedHash, password);
    } else if (/^[a-f0-9]{64}$/i.test(storedHash)) {
      // Verify legacy SHA-256 password
      const expectedHash = legacyHashPassword(password);

      const expectedBuffer = Buffer.from(expectedHash, 'hex');
      const storedBuffer = Buffer.from(storedHash, 'hex');

      passwordValid =
        expectedBuffer.length === storedBuffer.length &&
        crypto.timingSafeEqual(expectedBuffer, storedBuffer);

      // Upgrade legacy password hash after successful verification
      if (passwordValid) {
        const upgradedHash = await hashPasswordArgon2(password);

        db.prepare(`
          UPDATE tenants
          SET password_hash = ?
          WHERE tenant_id = ?
            AND password_hash = ?
        `).run(
          upgradedHash,
          tenant.tenant_id,
          storedHash
        );
      }
    }
  } catch {
    passwordValid = false;
  }

  if (!passwordValid) {
    return sendJson(res, 401, {
      error: 'Invalid email or password'
    });
  }

  const safeTenant = {
  tenant_id: tenant.tenant_id,
  org_name: tenant.org_name,
  email: tenant.email,
  subscription_tier: tenant.subscription_tier,
  monthly_request_limit: tenant.monthly_request_limit,

};

const browserSession = createUserSession(db, tenant.tenant_id);

return sendJson(res, 200, {
  token: tenant.cluster_sync_token,
  sessionToken: browserSession.token,
  sessionExpiresAt: browserSession.expiresAt,
  tenant: safeTenant
});
}

    // Telemetry Sync from Data Plane
  if (req.method === 'POST' && pathname === '/api/v1/telemetry/sync') {
    const syncSecret = (req.headers['x-cluster-sync-secret'] as string) || '';
    const { receipts } = await readJsonBody(req, 2_097_152);

    if (!Array.isArray(receipts) || receipts.length < 1 || receipts.length > 500) {
      return sendJson(res, 400, {
        error: 'Invalid receipts batch. Expected between 1 and 500 receipts.'
      });
    }

    const tenant: any = syncSecret
      ? db.prepare(
          `SELECT * FROM tenants WHERE cluster_sync_token = ?`
        ).get(syncSecret)
      : null;

    if (!tenant || typeof tenant.cluster_sync_token !== 'string') {
      return sendJson(res, 401, {
        error: 'Unauthorized: Invalid cluster sync credentials'
      });
    }

    const validatedReceipts: any[] = [];

    // Validate and cryptographically verify the entire batch before writing.
    for (const r of receipts) {
      if (!r || typeof r !== 'object' || Array.isArray(r)) {
        return sendJson(res, 400, { error: 'Invalid receipt object' });
      }

      const requiredStrings = [
        'receipt_id',
        'department',
        'model_requested',
        'model_routed',
        'prompt_sha256',
        'previous_receipt_hash',
        'receipt_hmac',
        'timestamp'
      ];

      for (const field of requiredStrings) {
        if (typeof r[field] !== 'string' || !r[field].trim()) {
          return sendJson(res, 400, {
            error: `Invalid receipt field: ${field}`
          });
        }
      }

      if (r.tenant_id !== undefined && r.tenant_id !== tenant.tenant_id) {
        return sendJson(res, 400, {
          error: 'Receipt tenant does not match authenticated tenant'
        });
      }

      if (
        !/^[a-f0-9]{64}$/.test(r.prompt_sha256) ||
        !/^[a-f0-9]{64}$/.test(r.previous_receipt_hash) ||
        !/^[a-f0-9]{64}$/.test(r.receipt_hmac)
      ) {
        return sendJson(res, 400, {
          error: 'Invalid receipt hash format'
        });
      }

      if (
        !Number.isSafeInteger(r.prompt_tokens) ||
        r.prompt_tokens < 0 ||
        !Number.isSafeInteger(r.completion_tokens) ||
        r.completion_tokens < 0 ||
        typeof r.cost_usd !== 'number' ||
        !Number.isFinite(r.cost_usd) ||
        r.cost_usd < 0 ||
        typeof r.finops_saved_usd !== 'number' ||
        !Number.isFinite(r.finops_saved_usd) ||
        r.finops_saved_usd < 0
      ) {
        return sendJson(res, 400, {
          error: 'Invalid receipt usage or cost values'
        });
      }

      if (Number.isNaN(Date.parse(r.timestamp))) {
        return sendJson(res, 400, {
          error: 'Invalid receipt timestamp'
        });
      }

      let dlpFlags: string[];

      try {
        dlpFlags = typeof r.dlp_flags === 'string'
          ? JSON.parse(r.dlp_flags)
          : r.dlp_flags;
      } catch {
        return sendJson(res, 400, {
          error: 'Invalid receipt DLP flags'
        });
      }

      if (
        !Array.isArray(dlpFlags) ||
        !dlpFlags.every((flag: unknown) => typeof flag === 'string')
      ) {
        return sendJson(res, 400, {
          error: 'Receipt DLP flags must be an array of strings'
        });
      }

      const canonicalPayload = [
        r.previous_receipt_hash,
        r.receipt_id,
        tenant.tenant_id,
        r.department,
        r.model_requested,
        r.model_routed,
        r.prompt_tokens,
        r.completion_tokens,
        r.cost_usd.toFixed(6),
        r.finops_saved_usd.toFixed(6),
        dlpFlags.join(','),
        r.prompt_sha256,
      ].join('|');

      const expectedHmac = crypto
        .createHmac('sha256', tenant.cluster_sync_token)
        .update(canonicalPayload)
        .digest();

      const suppliedHmac = Buffer.from(r.receipt_hmac, 'hex');

      if (
        suppliedHmac.length !== expectedHmac.length ||
        !crypto.timingSafeEqual(suppliedHmac, expectedHmac)
      ) {
        return sendJson(res, 401, {
          error: 'Receipt integrity verification failed'
        });
      }

      validatedReceipts.push({
        receipt_id: r.receipt_id,
        tenant_id: tenant.tenant_id,
        department: r.department,
        model_requested: r.model_requested,
        model_routed: r.model_routed,
        prompt_tokens: r.prompt_tokens,
        completion_tokens: r.completion_tokens,
        cost_usd: r.cost_usd,
        finops_saved_usd: r.finops_saved_usd,
        dlp_flags: JSON.stringify(dlpFlags),
        prompt_sha256: r.prompt_sha256,
        previous_receipt_hash: r.previous_receipt_hash,
        receipt_hmac: r.receipt_hmac,
        timestamp: r.timestamp
      });
    }

    const insert = db.prepare(`
      INSERT OR IGNORE INTO synced_receipts (
        receipt_id, tenant_id, department, model_requested, model_routed,
        prompt_tokens, completion_tokens, cost_usd, finops_saved_usd,
        dlp_flags, prompt_sha256, previous_receipt_hash, receipt_hmac, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const findExisting = db.prepare(`
      SELECT tenant_id, receipt_hmac
      FROM synced_receipts
      WHERE receipt_id = ?
    `);

    const acceptedReceiptIds: string[] = [];
    const newlyInserted: any[] = [];

    db.exec('BEGIN IMMEDIATE');

    try {
      for (const r of validatedReceipts) {
        const info = insert.run(
          r.receipt_id,
          r.tenant_id,
          r.department,
          r.model_requested,
          r.model_routed,
          r.prompt_tokens,
          r.completion_tokens,
          r.cost_usd,
          r.finops_saved_usd,
          r.dlp_flags,
          r.prompt_sha256,
          r.previous_receipt_hash,
          r.receipt_hmac,
          r.timestamp
        );

        if (info.changes > 0) {
          acceptedReceiptIds.push(r.receipt_id);
          newlyInserted.push(r);
          continue;
        }

        // A duplicate is acknowledged only if it is the exact same
        // tenant receipt with the same verified HMAC.
        const existing: any = findExisting.get(r.receipt_id);

        if (
          existing &&
          existing.tenant_id === tenant.tenant_id &&
          existing.receipt_hmac === r.receipt_hmac
        ) {
          acceptedReceiptIds.push(r.receipt_id);
          continue;
        }

        throw new Error('Receipt ID collision or conflicting duplicate');
      }

      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');

      const message = error instanceof Error ? error.message : String(error);

      if (message.includes('Receipt ID collision')) {
        return sendJson(res, 409, {
          error: 'Receipt ID collision or conflicting duplicate'
        });
      }

      throw error;
    }

      if (SIEM_OUTBOUND_DELIVERY_ENABLED && newlyInserted.length > 0 && tenant.siem_webhook_url) {
        forwardToCustomerSiem(tenant, newlyInserted);
      }
    return sendJson(res, 200, {
      status: 'synced',
      count: acceptedReceiptIds.length,
      accepted_receipt_ids: acceptedReceiptIds
    });
  }

  // Dashboard Summary
  if (req.method === 'GET' && pathname === '/api/v1/dashboard/summary') {
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    const stats: any = db.prepare(`
      SELECT
        COUNT(*) as total_requests_governed,
        COALESCE(SUM(cost_usd), 0) as total_spend_usd,
        COALESCE(SUM(finops_saved_usd), 0) as total_finops_saved_usd,
        SUM(CASE WHEN dlp_flags != '[]' AND dlp_flags != '' THEN 1 ELSE 0 END) as prompts_with_secrets_vaulted
      FROM synced_receipts
WHERE tenant_id = ?
   `).get(tenant.tenant_id);

    const recentCryptographicReceipts = db.prepare(`
  SELECT *
  FROM synced_receipts
  WHERE tenant_id = ?
  ORDER BY timestamp DESC
  LIMIT 100
`).all(tenant.tenant_id);

    return sendJson(res, 200, {
      tenant,
      summary: {
        total_requests_governed: stats.total_requests_governed || 0,
        total_spend_usd: stats.total_spend_usd || 0,
        total_finops_saved_usd: stats.total_finops_saved_usd || 0,
        prompts_with_secrets_vaulted: stats.prompts_with_secrets_vaulted || 0
      },
      recentCryptographicReceipts
    });
  }

  // SIEM Pull API & UI File Export
  if (req.method === 'GET' && pathname === '/api/v1/siem/logs') {
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    const format = (parsedUrl.searchParams.get('format') || 'json').toLowerCase();
    const limit = Math.min(1000, parseInt(parsedUrl.searchParams.get('limit') || '200', 10));
    const filter = (parsedUrl.searchParams.get('filter') || 'all').toLowerCase();

       const conditions = ['tenant_id = ?'];
    const queryParams: any[] = [tenant.tenant_id];

    if (filter === 'dlp') {
      conditions.push(`dlp_flags != '[]' AND dlp_flags != ''`);
    }

    const query = `
      SELECT *
      FROM synced_receipts
      WHERE ${conditions.join(' AND ')}
      ORDER BY timestamp DESC
      LIMIT ?
    `;

    queryParams.push(limit);

    const rows: any[] = db.prepare(query).all(...queryParams);
    if (format === 'csv') {
      const header = 'receipt_id,timestamp,tenant_id,department,model_requested,model_routed,prompt_tokens,completion_tokens,cost_usd,finops_saved_usd,dlp_flags,receipt_hmac\n';
      const csvRows = rows.map(r =>
        `"${r.receipt_id}","${r.timestamp}","${r.tenant_id}","${r.department}","${r.model_requested}","${r.model_routed}",${r.prompt_tokens},${r.completion_tokens},${r.cost_usd},${r.finops_saved_usd},"${String(r.dlp_flags).replace(/"/g, '""')}","${r.receipt_hmac}"`
      ).join('\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="aindigo-siem-security-logs.csv"',
        'Access-Control-Allow-Origin': '*'
      });
      return res.end(header + csvRows);
    }

    if (format === 'cef') {
      const cefLines = rows.map(formatReceiptAsCEF).join('\n');
      res.writeHead(200, {
        'Content-Type': 'text/plain; charset=utf-8',
        'Content-Disposition': 'attachment; filename="aindigo-siem-security-logs.cef"',
        'Access-Control-Allow-Origin': '*'
      });
      return res.end(cefLines);
    }

    return sendJson(res, 200, {
      schema: 'aindigo.siem.telemetry.v1',
      exportedAt: new Date().toISOString(),
      totalEvents: rows.length,
      events: rows
    });
  }

  // SIEM Push Webhook Config
  if (req.method === 'POST' && pathname === '/api/v1/siem/config') {
    const tenant = getBrowserSessionTenant(req);

    if (!tenant) {
      return sendJson(res, 401, { error: 'Unauthorized' });
    }

    if (!SIEM_OUTBOUND_DELIVERY_ENABLED) {
      return sendJson(res, 503, {
        error: 'SIEM webhook configuration is temporarily unavailable',
        code: 'SIEM_DELIVERY_DISABLED'
      });
    }

    const { webhookUrl, authHeader: webhookAuthHeader, format } =
      await readJsonBody(req);

if (
  typeof webhookUrl !== 'string' ||
  !webhookUrl.trim() ||
  typeof webhookAuthHeader !== 'string'
) {
  return sendJson(res, 400, {
    error: 'Valid webhook URL and authentication header are required'
  });
}

if (!['json', 'cef'].includes((format || 'json').toLowerCase())) {
  return sendJson(res, 400, {
    error: 'Unsupported SIEM format'
  });
}

let parsedWebhookUrl: URL;

try {
  parsedWebhookUrl = new URL(webhookUrl);
} catch {
  return sendJson(res, 400, {
    error: 'Invalid webhook URL'
  });
}

if (!['https:', 'http:'].includes(parsedWebhookUrl.protocol)) {
  return sendJson(res, 400, {
    error: 'Only HTTP or HTTPS webhook URLs are supported'
  });
}

const selectedFormat = (format || 'json').toLowerCase();

db.prepare(`
  UPDATE tenants
  SET siem_webhook_url = ?,
      siem_auth_header = ?,
      siem_format = ?
  WHERE tenant_id = ?
`).run(
  parsedWebhookUrl.toString(),
  webhookAuthHeader,
  selectedFormat,
  tenant.tenant_id
);

return sendJson(res, 200, {
  status: 'saved',
  message: 'SIEM configuration saved successfully.',
  config: {
    configured: true,
    format: selectedFormat
  }
});
  }

// SIEM Test Push Dispatcher
if (req.method === 'POST' && pathname === '/api/v1/siem/test-push') {
  const tenant = getBrowserSessionTenant(req);

  if (!tenant) {
    return sendJson(res, 401, { error: 'Unauthorized' });
  }

  const { format } = await readJsonBody(req);

  const sampleEvent = {
    receipt_id: 'rcpt_siem_test_' + crypto.randomBytes(4).toString('hex'),
    tenant_id: tenant.tenant_id,
    department: 'secops_verification',
    model_requested: 'gemini-2.5-pro',
    model_routed: 'gemini-2.5-flash',
    prompt_tokens: 320,
    completion_tokens: 190,
    cost_usd: 0.00042,
    finops_saved_usd: 0.00185,
    dlp_flags: '["AWS_ACCESS_KEY","INTERNAL_CORP_HOST"]',
    previous_receipt_hash: 'GENESIS',
    receipt_hmac: '',
    timestamp: new Date().toISOString()
  };

  const formattedPayload = format === 'cef'
    ? { cef: formatReceiptAsCEF(sampleEvent) }
    : {
        schema: 'aindigo.siem.telemetry.v1',
        eventType: 'SIEM_PUSH_VERIFICATION',
        event: sampleEvent
      };

  return sendJson(res, 200, {
    status: 'simulated_siem_event',
    note: 'Verification payload generated. Remote delivery is not enabled by this test endpoint yet.',
    dispatchedPayload: formattedPayload
  });
}

// Compliance API route dispatcher
  if (handleComplianceApi(req, res, parsedUrl)) {
    return;
  }

  // Final fallback for unknown routes
  return sendJson(res, 404, {
    error: 'Not found: ' + pathname
  });
  } catch (error) {
    if (res.headersSent || res.writableEnded || res.destroyed) {
      return;
    }

    if (error instanceof RequestBodyError) {
      return sendJson(res, error.statusCode, {
        error: error.message
      });
    }

    console.error('Control Plane request failed:', error);

    return sendJson(res, 500, {
      error: 'Internal server error'
    });
  } finally {
    releaseRequest();
  }
});


const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const shutdown = createGracefulShutdown({
  server,
  requests: requestLifecycle,
  closeDatabase: () => db.close(),
});

function handleShutdown(signal: NodeJS.Signals): void {
  void shutdown(signal).then((outcome) => {
    if (outcome !== 'CLOSED') {
      console.error(
        `[shutdown] Control Plane shutdown completed with outcome: ${outcome}`,
      );

      process.exitCode = 1;
    }
  });
}

process.on('SIGINT', () => handleShutdown('SIGINT'));
process.on('SIGTERM', () => handleShutdown('SIGTERM'));
server.listen(PORT, '0.0.0.0', () => {
  if (controlPlaneSigningKey) {
    console.log('[security] Control Plane signing identity loaded: ' + controlPlaneSigningKey.keyId);
  }
  console.log(`☁️  [AIndigo Cloud Control Plane v1.00.00-beta] Active on http://127.0.0.1:${PORT}`);
});

// ==========================================
// ENTERPRISE COMPLIANCE AUDIT API HANDLERS
// ==========================================
function handleComplianceApi(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  parsedUrl: URL
): boolean {
  const pathname = parsedUrl.pathname;

  if (
    pathname !== '/api/compliance/summary' &&
    pathname !== '/api/compliance/export-report'
  ) {
    return false;
  }

  if (req.method !== 'GET') {
    sendJson(res, 405, { error: 'Method not allowed' });
    return true;
  }

  const tenant = getBrowserSessionTenant(req);

  if (!tenant) {
    sendJson(res, 401, { error: 'Unauthorized' });
    return true;
  }

  try {
    if (pathname === '/api/compliance/summary') {
      const stats: any = db.prepare(`
        SELECT
          COUNT(*) AS total_audits,
          COALESCE(SUM(
            CASE WHEN dlp_flags LIKE '%HIPAA%'
              OR dlp_flags LIKE '%US_SSN%'
              OR dlp_flags LIKE '%MEDICAL_RECORD_NUMBER%'
            THEN 1 ELSE 0 END
          ), 0) AS hipaa_events,
          COALESCE(SUM(
            CASE WHEN dlp_flags LIKE '%NIST%'
              OR dlp_flags LIKE '%API_KEY%'
            THEN 1 ELSE 0 END
          ), 0) AS nist_events,
          COALESCE(SUM(
            CASE WHEN dlp_flags != '[]' AND dlp_flags != ''
            THEN 1 ELSE 0 END
          ), 0) AS iso_events
        FROM synced_receipts
        WHERE tenant_id = ?
      `).get(tenant.tenant_id);

      const recentViolations = db.prepare(`
        SELECT
          receipt_id,
          department,
          model_routed,
          dlp_flags,
          timestamp
        FROM synced_receipts
        WHERE tenant_id = ?
          AND dlp_flags != '[]'
          AND dlp_flags != ''
        ORDER BY timestamp DESC
        LIMIT 25
      `).all(tenant.tenant_id);

     sendJson(res, 200, {
  status: 'SUCCESS',
  frameworksActive: [
    'HIPAA Security Rule (45 CFR § 164.312)',
    'NIST AI RMF 1.0 (SP 800-53)',
    'ISO/IEC 42001:2023 AI Management'
  ],
  statistics: stats,
  violations: recentViolations
});
return true;
    }

    if (pathname === '/api/compliance/export-report') {
      const allReceipts = db.prepare(`
        SELECT
          receipt_id,
          department,
          model_requested,
          model_routed,
          prompt_tokens,
          completion_tokens,
          cost_usd,
          finops_saved_usd,
          dlp_flags,
          previous_receipt_hash,
          timestamp
        FROM synced_receipts
        WHERE tenant_id = ?
        ORDER BY timestamp DESC
      `).all(tenant.tenant_id);

      sendJson(res, 200, {
  generatedAt: new Date().toISOString(),
  organization: tenant.org_name,
  frameworksValidated: [
    'HIPAA Security Rule - PHI Redaction & Zero Retention',
    'NIST AI RMF 1.0 - Cryptographic Audit Integrity',
    'ISO/IEC 42001 - Automated Policy Enforcement'
  ],
  totalAuditEntries: allReceipts.length,
  auditTrail: allReceipts
});
return true;
    }
  } catch (err) {
    console.error('Compliance API request failed:', err);
    sendJson(res, 500, { error: 'Compliance API request failed' });
    return true;
  }

  return false;
}
