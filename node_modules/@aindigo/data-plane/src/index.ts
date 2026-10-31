import 'dotenv/config';
import { exec } from 'node:child_process';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { serve } from '@hono/node-server';
import { LRUCache } from 'lru-cache';
import { hashVirtualKey, verifyKeyHashSafe, decryptSecret } from './crypto.js';
import {
  findVirtualKeyByHash,
  seedDevVirtualKey,
  mintCustomVirtualKey,
  listActiveVirtualKeys,
  recordTurnSpendAndSavings,
  setDepartmentSpendLevel,
  createAndQueueAuditReceipt,
  getNodeActivation,
  activateDataPlaneNode,
  incrementNodeRequestCounter,
  VirtualKeyRow,
} from './db.js';
import {
  createVaultSession,
  scrubAndVaultText,
  rehydrateFromVault,
  destroyVaultSession,
} from './dlp-vault.js';
import {
  checkAgentTrajectoryLoop,
  evaluateBudgetAndRouteModel,
  calculateTurnCostAndSavings,
} from './finops-governor.js';
import {
  createRehydratingSseStream,
  inspectAgentOutputFirewall,
} from './stream-guard.js';
import {
  runControlPlaneSyncCycle,
  startBackgroundSyncLoop,
} from './sync-worker.js';
import { executeUpstreamOrSandbox } from './upstream.js';

const VERSION = 'v1.00.00-beta';
const CONTROL_PLANE_URL = process.env.CONTROL_PLANE_URL || 'http://127.0.0.1:3000';

const app = new Hono();
app.use('/*', cors());
app.use('/*', async (c, next) => {
  c.header('Access-Control-Allow-Private-Network', 'true');
  c.header('Access-Control-Allow-Origin', '*');
  c.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  c.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
  if (c.req.method === 'OPTIONS') return c.text('', 204);
  await next();
});

const keyCache = new LRUCache<string, VirtualKeyRow>({
  max: 5000,
  ttl: 60 * 1000,
});

const DEV_VIRTUAL_KEY = 'vk-aindigo-dev-local-9999';
const MOCK_UPSTREAM_KEY = 'sk-ant-live-mock-secure-credential';
seedDevVirtualKey(DEV_VIRTUAL_KEY, MOCK_UPSTREAM_KEY);

startBackgroundSyncLoop(10_000);

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
  return c.json({
    status: 'ONLINE',
    version: VERSION,
    plane: 'AIndigo Data Plane (Local Engine)',
    activation: state,
    timestamp: new Date().toISOString(),
  });
});

app.post('/v1/node/pair', async (c) => {
  const body = await c.req.json<{
    tenantId: string;
    orgName: string;
    subscriptionTier: 'COMMUNITY' | 'SME_PRO' | 'ENTERPRISE';
    clusterSyncSecret: string;
    monthlyRequestLimit: number;
  }>();

  const updated = activateDataPlaneNode({
    tenantId: body.tenantId,
    orgName: body.orgName,
    subscriptionTier: body.subscriptionTier || 'COMMUNITY',
    clusterSyncSecret: body.clusterSyncSecret,
    monthlyRequestLimit: body.monthlyRequestLimit || 10000,
  });

  keyCache.clear();
  void runControlPlaneSyncCycle();

  return c.json({ status: 'NODE_PAIRED_AND_ACTIVATED', version: VERSION, activation: updated });
});

// Universal Key Minting for ANY Upstream Provider API Key
app.post('/v1/keys/create', async (c) => {
  const nodeState = getNodeActivation();
  const body = await c.req.json<{
    tenantId?: string;
    department?: string;
    provider?: string;
    upstreamApiKey?: string;
    monthlyBudgetUsd?: number;
    dlpMode?: 'redact' | 'block' | 'audit';
  }>();

  if (!body.department || !body.upstreamApiKey) {
    return c.json({ error: 'Department and upstreamApiKey are required.' }, 400);
  }

  const provider = body.provider || 'anthropic';
  const dlpMode = body.dlpMode || 'redact';

  const minted = mintCustomVirtualKey({
    tenantId: nodeState.tenant_id !== 'unpaired' ? nodeState.tenant_id : (body.tenantId || 'acme_corp'),
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
  return c.json({ activation: getNodeActivation(), keys: listActiveVirtualKeys() });
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

async function handleUnifiedProxyRequest(c: any, protocol: 'openai' | 'anthropic') {
  const start = performance.now();
  const auth = authenticateRequest(c.req.header('Authorization'), c.req.header('x-api-key'));
  if (!auth) {
    return c.json({ error: { message: 'Invalid or revoked AIndigo Virtual Key', type: 'auth_error' } }, 401);
  }

  const nodeState = getNodeActivation();
  const quota = incrementNodeRequestCounter();
  if (!quota.allowed) {
    return c.json({ error: { code: 'COMMUNITY_QUOTA_EXCEEDED', message: `Monthly limit of ${quota.limit.toLocaleString()} requests reached.` } }, 429);
  }

  const body = await c.req.json<{
    model?: string;
    messages?: ChatMessage[];
    stream?: boolean;
    simulateMaliciousToolOutput?: boolean;
  }>();

  const modelRequested = body.model || (protocol === 'anthropic' ? 'claude-3-7-sonnet' : 'gpt-4o');
  const messages = Array.isArray(body.messages) ? body.messages : [];
  if (messages.length === 0) return c.json({ error: { message: 'messages cannot be empty' } }, 400);

  // FinOps Budget & Smart Auto-Downgrade
  const budgetDecision = evaluateBudgetAndRouteModel(
    modelRequested,
    auth.keyRow.current_spend_usd,
    auth.keyRow.monthly_budget_usd
  );

  if (!budgetDecision.allowed) {
    return c.json({ error: { code: 'BUDGET_EXHAUSTED', message: `Monthly budget cap reached.` } }, 429);
  }

  // Scrub & Vault
  const vaultSession = createVaultSession(auth.keyRow.tenant_id);
  let allFlaggedCategories: string[] = [];

  const sanitizedMessages = messages.map((msg) => {
    const res = scrubAndVaultText(msg.content, vaultSession);
    allFlaggedCategories = res.flaggedCategories;
    return { ...msg, content: res.sanitizedText };
  });

  const decryptedUpstreamKey = decryptSecret({
    ciphertext: auth.keyRow.encrypted_upstream_key,
    iv: auth.keyRow.key_iv,
    authTag: auth.keyRow.key_auth_tag,
  });

  let upstreamResult;
  try {
    upstreamResult = await executeUpstreamOrSandbox({
      provider: auth.keyRow.provider,
      decryptedApiKey: decryptedUpstreamKey,
      modelRouted: budgetDecision.modelRouted,
      sanitizedMessages,
      simulateMaliciousToolOutput: body.simulateMaliciousToolOutput,
    });
  } catch (err: any) {
    destroyVaultSession(vaultSession.sessionId);
    return c.json({ error: { code: 'UPSTREAM_PROVIDER_ERROR', message: err?.message } }, 502);
  }

  const costMetrics = calculateTurnCostAndSavings(
    budgetDecision.modelRequested,
    budgetDecision.modelRouted,
    upstreamResult.promptTokens,
    upstreamResult.completionTokens
  );
  recordTurnSpendAndSavings(auth.keyRow.key_hash, costMetrics.actualCostUsd, costMetrics.finopsSavedUsd);
  const refreshed = findVirtualKeyByHash(auth.keyRow.key_hash);
  if (refreshed) keyCache.set(auth.keyRow.key_hash, refreshed);

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

  try {
    const firewallCheck = inspectAgentOutputFirewall(upstreamResult.outputText);
    if (firewallCheck.blocked) {
      return c.json({ error: { code: 'AGENT_FIREWALL_INTERCEPTED', violation: firewallCheck.violationType } }, 403);
    }

    const rehydratedText = rehydrateFromVault(upstreamResult.outputText, vaultSession);

    return c.json({
      id: protocol === 'openai' ? `chatcmpl-aindigo-${Date.now()}` : `msg_aindigo_${Date.now()}`,
      object: protocol === 'openai' ? 'chat.completion' : 'message',
      version: VERSION,
      edition: nodeState.subscription_tier,
      model: budgetDecision.modelRouted,
      aindigo_governance: {
        execution_mode: upstreamResult.executionMode,
        overhead_ms: overheadMs,
        flagged_categories: allFlaggedCategories,
        budget_downgraded: budgetDecision.budgetDowngraded,
        turn_cost_usd: costMetrics.actualCostUsd,
        saved_usd: costMetrics.finopsSavedUsd,
        cryptographic_receipt: {
          receipt_id: auditReceipt.receiptId,
          receipt_hmac: auditReceipt.receiptHmac,
        },
      },
      content: rehydratedText,
    });
  } finally {
    destroyVaultSession(vaultSession.sessionId);
  }
}

app.post('/v1/chat/completions', (c) => handleUnifiedProxyRequest(c, 'openai'));
app.post('/v1/messages', (c) => handleUnifiedProxyRequest(c, 'anthropic'));

const port = Number(process.env.PORT) || 8080;
const host = process.env.HOST || '127.0.0.1';

serve({ fetch: app.fetch, port, hostname: host }, (info) => {
  const state = getNodeActivation();
  console.log(`\n======================================================`);
  console.log(`⚡ AIndigo Data Plane Engine ${VERSION} (Port ${info.port})`);
  if (!state.is_activated) {
    const onboardingUrl = `${CONTROL_PLANE_URL}/?pair_port=${info.port}`;
    console.log(`🌐 Launching Cloud Control Plane in browser: ${onboardingUrl}`);
    openBrowserToControlPlane(onboardingUrl);
  }
  console.log(`======================================================\n`);
});

