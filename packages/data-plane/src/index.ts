import 'dotenv/config';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getOrCreateNodeIdentity } from './crypto/node-identity.js';
import {
  configureNodeLeaseRuntime,
  getNodeLeaseRuntimeStatus,
  assertNodeLeaseActive,
  verifyNodeLeaseRuntime,
} from './crypto/node-lease-runtime.js';
import type { Server as HttpServer } from 'node:http';
import { exec } from 'node:child_process';
import { Hono, type Context } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { LRUCache } from 'lru-cache';
import { hashVirtualKey, verifyKeyHashSafe, decryptSecret } from './crypto.js';
import {
  findVirtualKeyByHash,
  mintCustomVirtualKey,
  listActiveVirtualKeys,
  recordTurnSpendAndSavings,
  createAndQueueAuditReceipt,
  getNodeActivation,
  activateDataPlaneNode,
  incrementNodeRequestCounter,
  closeDataPlaneDatabase,
  VirtualKeyRow,
} from './db.js';
import {
  rehydrateFromVault,
  destroyVaultSession,
} from './dlp-vault.js';
import {
  prepareDlpRequest,
  type DlpMode,
} from './dlp/request-protection.js';
import {
  evaluateBudgetAndRouteModel,
  calculateTurnCostAndSavings,
} from './finops-governor.js';
import {
  inspectAgentOutputFirewall,
} from './stream-guard.js';
import {
  runControlPlaneSyncCycle,
  startBackgroundSyncLoop,
  stopBackgroundSyncLoop,
  waitForSyncIdle,
} from './sync-worker.js';
import { executeUpstreamOrSandbox } from './upstream.js';
import { HttpRequestLifecycle } from './http/request-lifecycle.js';
import { createGracefulShutdown } from './http/shutdown-orchestrator.js';

const VERSION = 'v1.00.00-beta';
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:3000';

const configuredNodeKeysDir = process.env.AINDIGO_NODE_KEYS_DIR?.trim();
const defaultNodeKeysDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../.keys',
);
const nodeKeysDir = configuredNodeKeysDir
  ? path.resolve(configuredNodeKeysDir)
  : defaultNodeKeysDir;

// Validate the persistent node identity before background sync or traffic.
const nodeIdentity = getOrCreateNodeIdentity(nodeKeysDir);

configureNodeLeaseRuntime(nodeIdentity);
const startupLeaseState = verifyNodeLeaseRuntime();

const app = new Hono();
const requestLifecycle = new HttpRequestLifecycle();
function safeActivationResponse(state: ReturnType<typeof getNodeActivation>) {
  return {
    is_activated: state.is_activated,
    tenant_id: state.tenant_id,
    org_name: state.org_name,
    subscription_tier: state.subscription_tier,
    monthly_request_limit: state.monthly_request_limit,
    requests_used_this_month: state.requests_used_this_month,
  };
}
app.use('/*', cors());
app.use('/*', async (c, next) => {
  c.header('Access-Control-Allow-Private-Network', 'true');
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
  return next();
});

// Track application requests so shutdown never closes SQLite
// while a handler is still using the database.
app.use('/*', async (c, next) => {
  // CORS preflight requests do not access application state.
  if (c.req.method === 'OPTIONS') {
    await next();
    return;
  }

  // Keep health checks available during draining without
  // touching SQLite after shutdown has started.
  if (c.req.path === '/health' && requestLifecycle.isDraining) {
    c.json({
      status: 'DRAINING',
      version: VERSION,
      plane: 'AIndigo Data Plane (Local Engine)',
      active_requests: requestLifecycle.activeCount,
      timestamp: new Date().toISOString(),
    }, 503);
    return;
  }

  const release = requestLifecycle.tryAcquire();

  if (!release) {
    c.json({
      error: {
        code: 'SERVER_DRAINING',
        message: 'The Data Plane is shutting down and is not accepting new requests.',
      },
    }, 503);
    return;
  }

  try {
    await next();
  } finally {
    release();
  }
});

// Protected Data Plane operations require a verified signed node lease.
// Health and onboarding remain available while the node is unenrolled.
app.use('/*', async (c, next) => {
  if (
    c.req.method === 'OPTIONS' ||
    c.req.path === '/' ||
    c.req.path === '/health' ||
    c.req.path === '/v1/node/pair'
  ) {
    await next();
    return;
  }

  try {
    assertNodeLeaseActive();
  } catch {
    return c.json({
      error: {
        code: 'NODE_AUTHORIZATION_REQUIRED',
        message: 'A valid signed node lease and a fresh authenticated ACTIVE Control Plane node status are required.',
      },
    }, 503);
  }

  return next();
});

const keyCache = new LRUCache<string, VirtualKeyRow>({
  max: 5000,
  ttl: 60 * 1000,
});

if (startupLeaseState.status === 'ONLINE') {
  startBackgroundSyncLoop(10_000);
  console.log('[security] Data Plane signed node lease verified.');
} else {
  console.warn('[security] Data Plane lease gate: ' + startupLeaseState.status + '; protected operations and sync remain disabled.');
}

function openBrowserToControlPlane(url: string) {
  if (process.env.NO_BROWSER_OPEN === 'true') return;
  const cmd =
    process.platform === 'win32'
      ? `start "" "${url}"`
      : process.platform === 'darwin'
      ? `open "${url}"`
      : `xdg-open "${url}"`;
  exec(cmd, () => {});
}

function authenticateRequest(
  authHeader: string | undefined,
  xApiKeyHeader?: string | undefined
): { keyRow: VirtualKeyRow; cacheHit: boolean } | null {
  const rawToken = xApiKeyHeader
    ? xApiKeyHeader.trim()
    : (authHeader || '').replace('Bearer ', '').trim();

  if (!rawToken) return null;

  const incomingHash = hashVirtualKey(rawToken);
  let keyRow = keyCache.get(incomingHash);
  let cacheHit = true;

  if (!keyRow) {
    cacheHit = false;
    keyRow = findVirtualKeyByHash(incomingHash);
    if (keyRow) {
      keyCache.set(incomingHash, keyRow);
    }
  }

  if (!keyRow || !verifyKeyHashSafe(incomingHash, keyRow.key_hash)) {
    return null;
  }

  return { keyRow, cacheHit };
}

app.get('/', (c) => c.redirect(`${CONTROL_PLANE_URL}/?pair_port=8080`));

app.get('/health', (c) => {
  const state = getNodeActivation();
  const leaseState = getNodeLeaseRuntimeStatus();

  return c.json({
    status: leaseState.status === 'ONLINE' ? 'ONLINE' : 'DEGRADED',
    lease_status: leaseState.status,
    version: VERSION,
    plane: 'AIndigo Data Plane (Local Engine)',
    activation: safeActivationResponse(state),
    timestamp: new Date().toISOString(),
  }, leaseState.status === 'ONLINE' ? 200 : 503);
});


app.post('/v1/node/pair', async (c) => {
  let body: {
    tenantId: string;
    orgName: string;
    subscriptionTier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
    clusterSyncSecret: string;
    monthlyRequestLimit: number;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'Invalid JSON request body.' }, 400);
  }

  if (
    !body.tenantId?.trim() ||
    !body.orgName?.trim() ||
    !body.clusterSyncSecret?.trim()
  ) {
    return c.json(
      { error: 'Tenant ID, organization name, and node credential are required.' },
      400
    );
  }

  try {
    const updated = activateDataPlaneNode({
      tenantId: body.tenantId,
      orgName: body.orgName,
      subscriptionTier: body.subscriptionTier || 'COMMUNITY',
      clusterSyncSecret: body.clusterSyncSecret,
      monthlyRequestLimit: body.monthlyRequestLimit || 10000,
    });

    keyCache.clear();
    void runControlPlaneSyncCycle();

    return c.json({
      status: 'NODE_PAIRED_AND_ACTIVATED',
      version: VERSION,
      activation: safeActivationResponse(updated),
    });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : 'Node activation failed.';

    return c.json({ error: message }, 409);
  }
});


// Universal Key Minting for ANY Upstream Provider API Key
app.post('/v1/keys/create', async (c) => {
  const nodeState = getNodeActivation();

  // Require an activated node before creating virtual keys.
  if (
    nodeState.is_activated !== 1 ||
    !nodeState.tenant_id ||
    nodeState.tenant_id === 'unpaired'
  ) {
    return c.json(
      {
        error: 'Data Plane node must be securely enrolled before key creation.',
      },
      403
    );
  }

  const body = await c.req.json<{
    department?: string;
    provider?: string;
    upstreamApiKey?: string;
    monthlyBudgetUsd?: number;
    dlpMode?: 'redact' | 'block' | 'audit';
  }>();

  if (!body.department || !body.upstreamApiKey) {
    return c.json(
      { error: 'Department and upstreamApiKey are required.' },
      400
    );
  }

  const provider = body.provider || 'anthropic';
  const dlpMode = body.dlpMode || 'redact';

  const minted = mintCustomVirtualKey({
    tenantId: nodeState.tenant_id,
    department: body.department.trim(),
    provider,
    upstreamApiKey: body.upstreamApiKey.trim(),
    monthlyBudgetUsd: Number(body.monthlyBudgetUsd) || 100.0,
    dlpMode,
  });

  return c.json({
    status: 'VIRTUAL_KEY_MINTED',
    version: VERSION,
    edition: nodeState.subscription_tier,
    message: 'Save this Virtual Key. Only its SHA-256 hash is stored at rest.',
    virtualKey: minted.virtualKey,
    keyPreview: minted.keyPreview,
    department: body.department.trim(),
    provider,
    monthlyBudgetUsd: Number(body.monthlyBudgetUsd) || 100.0,
    dlpMode,
    encryptionAtRest: 'AES-256-GCM',
  });
});


app.get('/v1/keys/list', (c) => {
  return c.json({
    activation: safeActivationResponse(getNodeActivation()),
    keys: listActiveVirtualKeys(),
  });
});

app.post('/v1/sync/flush-now', async (c) => {
  const report = await runControlPlaneSyncCycle();
  keyCache.clear();
  return c.json(report);
});

interface ChatMessage {
  role: string;
  content: string;
}

async function handleUnifiedProxyRequest(c: Context, protocol: 'openai' | 'anthropic') {
  const start = performance.now();
  const auth = authenticateRequest(c.req.header('Authorization'), c.req.header('x-api-key'));

  if (!auth) {
    return c.json(
      { error: { message: 'Invalid or revoked AIndigo Virtual Key', type: 'auth_error' } },
      401
    );
  }

  const nodeState = getNodeActivation();


  let body: {
    model?: string;
    messages?: ChatMessage[];
    stream?: boolean;
    simulateMaliciousToolOutput?: boolean;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: { message: 'Invalid JSON request body.' } }, 400);
  }

  const modelRequested =
    body.model || (protocol === 'anthropic' ? 'claude-3-7-sonnet' : 'gpt-4o');
  const messages = Array.isArray(body.messages) ? body.messages : [];

  if (messages.length === 0) {
    return c.json({ error: { message: 'messages cannot be empty' } }, 400);
  }

  if (
    messages.some(
      (msg) =>
        !msg ||
        typeof msg !== 'object' ||
        typeof msg.content !== 'string'
    )
  ) {
    return c.json(
      { error: { message: 'Every message must have string content.' } },
      400
    );
  }

  const budgetDecision = evaluateBudgetAndRouteModel(
    modelRequested,
    auth.keyRow.current_spend_usd,
    auth.keyRow.monthly_budget_usd
  );

  if (!budgetDecision.allowed) {
    return c.json(
      { error: { code: 'BUDGET_EXHAUSTED', message: 'Monthly budget cap reached.' } },
      429
    );
  }

  const dlpMode = auth.keyRow.dlp_mode;

  if (!['redact', 'block', 'audit'].includes(dlpMode)) {
    return c.json(
      { error: { code: 'INVALID_DLP_POLICY', message: 'Unsupported DLP policy.' } },
      403
    );
  }

  let dlpPreparation: ReturnType<typeof prepareDlpRequest>;

try {
  dlpPreparation = prepareDlpRequest(
    auth.keyRow.tenant_id,
    messages,
    dlpMode as DlpMode
  );
} catch (error) {
  if (
    error instanceof Error &&
    error.message.startsWith('DLP_PAYLOAD_TOO_LARGE:')
  ) {
    return c.json(
      {
        error: {
          code: 'DLP_PAYLOAD_TOO_LARGE',
          message: 'A message exceeds the maximum DLP scanning size.',
        },
      },
      413
    );
  }

  return c.json(
    {
      error: {
        code: 'DLP_SCAN_FAILED',
        message: 'The request could not be scanned by the DLP engine.',
      },
    },
    500
  );
}

const vaultSession = dlpPreparation.vaultSession;
const allFlaggedCategories = dlpPreparation.flaggedCategories;
const sanitizedMessages = dlpPreparation.providerMessages;

try {
  if (dlpPreparation.blocked) {
    return c.json(
      {
        error: {
          code: 'DLP_POLICY_BLOCKED',
          message: 'Request blocked by the configured DLP policy.',
        },
        aindigo_governance: {
          dlp_action: 'block',
          flagged_categories: allFlaggedCategories,
        },
      },
      403
    );
  }

  const quota = incrementNodeRequestCounter();

  if (!quota.allowed) {
    return c.json(
      {
        error: {
          code: 'COMMUNITY_QUOTA_EXCEEDED',
          message: `Monthly limit of ${quota.limit.toLocaleString()} requests reached.`,
        },
      },
      429
    );
  }
    const decryptedUpstreamKey = decryptSecret({
      ciphertext: auth.keyRow.encrypted_upstream_key,
      iv: auth.keyRow.key_iv,
      authTag: auth.keyRow.key_auth_tag,
    });


    const upstreamResult = await executeUpstreamOrSandbox({
      provider: auth.keyRow.provider,
      decryptedApiKey: decryptedUpstreamKey,
      modelRouted: budgetDecision.modelRouted,
      sanitizedMessages,
      simulateMaliciousToolOutput: body.simulateMaliciousToolOutput,
      signal: c.req.raw.signal,
    });

    const costMetrics = calculateTurnCostAndSavings(
      budgetDecision.modelRequested,
      budgetDecision.modelRouted,
      upstreamResult.promptTokens,
      upstreamResult.completionTokens
    );

    recordTurnSpendAndSavings(
      auth.keyRow.key_hash,
      costMetrics.actualCostUsd,
      costMetrics.finopsSavedUsd
    );

    const refreshed = findVirtualKeyByHash(auth.keyRow.key_hash);
    if (refreshed) {
      keyCache.set(auth.keyRow.key_hash, refreshed);
    }

    const auditReceipt = createAndQueueAuditReceipt({
      tenantId: auth.keyRow.tenant_id,
      department: auth.keyRow.department,
      modelRequested: budgetDecision.modelRequested,
      modelRouted: budgetDecision.modelRouted,
      promptTokens: upstreamResult.promptTokens,
      completionTokens: upstreamResult.completionTokens,
      costUsd: costMetrics.actualCostUsd,
      savedUsd: costMetrics.finopsSavedUsd,
      dlpFlags: allFlaggedCategories,
      rawPromptText: messages.map((m) => m.content).join('\n'),
    });

    void runControlPlaneSyncCycle();

    const overheadMs = Number((performance.now() - start).toFixed(3));

    const firewallCheck = inspectAgentOutputFirewall(upstreamResult.outputText);

    if (firewallCheck.blocked) {
      return c.json(
        {
          error: {
            code: 'AGENT_FIREWALL_INTERCEPTED',
            violation: firewallCheck.violationType,
          },
        },
        403
      );
    }

    const responseText =
      dlpMode === 'redact'
        ? rehydrateFromVault(upstreamResult.outputText, vaultSession)
        : upstreamResult.outputText;

    return c.json({
      id:
        protocol === 'openai'
          ? `chatcmpl-aindigo-${Date.now()}`
          : `msg_aindigo-${Date.now()}`,
      object: protocol === 'openai' ? 'chat.completion' : 'message',
      version: VERSION,
      edition: nodeState.subscription_tier,
      model: budgetDecision.modelRouted,
      aindigo_governance: {
        execution_mode: upstreamResult.executionMode,
        overhead_ms: overheadMs,
        dlp_action: dlpMode,
        flagged_categories: allFlaggedCategories,
        budget_downgraded: budgetDecision.budgetDowngraded,
        turn_cost_usd: costMetrics.actualCostUsd,
        saved_usd: costMetrics.finopsSavedUsd,
        cryptographic_receipt: {
          receipt_id: auditReceipt.receiptId,
          receipt_hmac: auditReceipt.receiptHmac,
        },
      },
      content: responseText,
    });
  } catch (err) {
    // Do not expose provider error bodies, credentials, or internal exception details.
    return c.json(
      { error: { code: 'UPSTREAM_OR_POLICY_ERROR', message: 'The request could not be completed.' } },
      502
    );
  } finally {
    destroyVaultSession(vaultSession.sessionId);
  }
}

app.post('/v1/chat/completions', (c) => handleUnifiedProxyRequest(c, 'openai'));
app.post('/v1/messages', (c) => handleUnifiedProxyRequest(c, 'anthropic'));

const port = Number(process.env.PORT) || 8080;
const host = process.env.HOST || '127.0.0.1';

const server = serve({ fetch: app.fetch, port, hostname: host }, (info) => {
  console.log(`Node identity: ${nodeIdentity.nodeId}`);
  const state = getNodeActivation();
  console.log(`\n======================================================`);
  console.log(`ÃƒÂ¢Ã…Â¡Ã‚Â¡ AIndigo Data Plane Engine ${VERSION} (Port ${info.port})`);
  if (!state.is_activated) {
    const onboardingUrl = `${CONTROL_PLANE_URL}/?pair_port=${info.port}`;
    console.log(`ÃƒÂ°Ã…Â¸Ã…â€™Ã‚Â Launching Cloud Control Plane in browser: ${onboardingUrl}`);
    openBrowserToControlPlane(onboardingUrl);
  }
  console.log(`======================================================\n`);
}) as HttpServer;
// ------------------------------------------------------------
// ------------------------------------------------------------
// Graceful Data Plane shutdown
// ------------------------------------------------------------

const shutdown = createGracefulShutdown(
  {
    server,
    requests: requestLifecycle,
    stopSync: stopBackgroundSyncLoop,
    waitForSyncIdle,
    closeDatabase: closeDataPlaneDatabase,
  },
  {
    gracePeriodMs: 30_000,
    recoveryPeriodMs: 15_000,
    serverCloseTimeoutMs: 5_000,
  },
);

function handleShutdown(signal: NodeJS.Signals): void {
  void shutdown(signal).then((outcome) => {
    if (outcome !== 'CLOSED') {
      process.exitCode = 1;
    }
  });
}

process.once('SIGINT', () => {
  handleShutdown('SIGINT');
});

process.once('SIGTERM', () => {
  handleShutdown('SIGTERM');
});
