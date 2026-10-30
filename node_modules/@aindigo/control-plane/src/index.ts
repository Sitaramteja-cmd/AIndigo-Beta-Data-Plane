import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { URL } from 'node:url';
import Database from 'better-sqlite3';

const dbPath = path.resolve(process.cwd(), 'control-plane-saas.sqlite');
const db = new Database(dbPath);

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
    previous_receipt_hash TEXT,
    receipt_hmac TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_webhook_url TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_auth_header TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE tenants ADD COLUMN siem_format TEXT DEFAULT 'json'`); } catch {}

const defaultSyncToken = 'aindigo-cluster-hmac-secret-key-2026-enterprise-verified';
const ensureDefault = db.prepare(`SELECT * FROM tenants WHERE tenant_id = 'acme_corp'`).get();
if (!ensureDefault) {
  db.prepare(`
    INSERT INTO tenants (tenant_id, org_name, email, password_hash, subscription_tier, monthly_request_limit, cluster_sync_token)
    VALUES ('acme_corp', 'Community Sandbox', 'admin@aindigo.local', 'sandbox', 'COMMUNITY', 10000, ?)
  `).run(defaultSyncToken);
}

function hashPassword(pw: string): string {
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
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

function readJsonBody(req: http.IncomingMessage): Promise<any> {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch { resolve({}); }
    });
    req.on('error', () => resolve({}));
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

const server = http.createServer(async (req, res) => {
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
    const { orgName, email, password, tier } = await readJsonBody(req);
    if (!email || !password) return sendJson(res, 400, { error: 'Email and password required' });

    const existing = db.prepare(`SELECT * FROM tenants WHERE email = ?`).get(email);
    if (existing) return sendJson(res, 400, { error: 'Account already exists with this email. Please Log In.' });

    const tenantId = 'org_' + crypto.randomBytes(4).toString('hex');
    const syncToken = 'aindigo_cst_' + crypto.randomBytes(16).toString('hex');
    db.prepare(`
      INSERT INTO tenants (tenant_id, org_name, email, password_hash, subscription_tier, monthly_request_limit, cluster_sync_token)
      VALUES (?, ?, ?, ?, ?, 10000, ?)
    `).run(tenantId, orgName || 'My Dev Workspace', email, hashPassword(password), tier || 'COMMUNITY', syncToken);

    const tenant = db.prepare(`SELECT tenant_id, org_name, email, subscription_tier, monthly_request_limit, cluster_sync_token, siem_webhook_url, siem_format FROM tenants WHERE tenant_id = ?`).get(tenantId);
    return sendJson(res, 200, { token: syncToken, tenant });
  }

  // Login Account
  if (req.method === 'POST' && pathname === '/api/v1/auth/login') {
    const { email, password } = await readJsonBody(req);
    const tenant: any = db.prepare(`SELECT * FROM tenants WHERE email = ? AND password_hash = ?`).get(email, hashPassword(password || ''));
    if (!tenant) return sendJson(res, 401, { error: 'Invalid email or password' });
    return sendJson(res, 200, { token: tenant.cluster_sync_token, tenant });
  }

  // Telemetry Sync from Data Plane
  if (req.method === 'POST' && pathname === '/api/v1/telemetry/sync') {
    const syncSecret = (req.headers['x-cluster-sync-secret'] as string) || '';
    const { receipts } = await readJsonBody(req);
    if (!Array.isArray(receipts)) return sendJson(res, 400, { error: 'Invalid receipts array' });

    let tenant: any = db.prepare(`SELECT * FROM tenants WHERE cluster_sync_token = ?`).get(syncSecret);
    if (!tenant) tenant = db.prepare(`SELECT * FROM tenants WHERE tenant_id = 'acme_corp'`).get();

    const insert = db.prepare(`
      INSERT OR IGNORE INTO synced_receipts (
        receipt_id, tenant_id, department, model_requested, model_routed,
        prompt_tokens, completion_tokens, cost_usd, finops_saved_usd,
        dlp_flags, previous_receipt_hash, receipt_hmac, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const newlyInserted: any[] = [];
    const tx = db.transaction((items: any[]) => {
      for (const r of items) {
        const info = insert.run(
          r.receipt_id,
          tenant.tenant_id,
          r.department || 'default',
          r.model_requested || 'unknown',
          r.model_routed || 'unknown',
          r.prompt_tokens || 0,
          r.completion_tokens || 0,
          r.cost_usd || 0,
          r.finops_saved_usd || 0,
          typeof r.dlp_flags === 'string' ? r.dlp_flags : JSON.stringify(r.dlp_flags || []),
          r.previous_receipt_hash || 'GENESIS',
          r.receipt_hmac || '',
          r.timestamp || new Date().toISOString()
        );
        if (info.changes > 0) newlyInserted.push(r);
      }
    });
    tx(receipts);

    if (newlyInserted.length > 0 && tenant.siem_webhook_url) {
      forwardToCustomerSiem(tenant, newlyInserted);
    }

    return sendJson(res, 200, { status: 'synced', count: receipts.length });
  }

  // Dashboard Summary
  if (req.method === 'GET' && pathname === '/api/v1/dashboard/summary') {
    const auth = ((req.headers['authorization'] as string) || '').replace('Bearer ', '').trim();
    let tenant: any = auth ? db.prepare(`SELECT * FROM tenants WHERE cluster_sync_token = ?`).get(auth) : null;
    if (!tenant) tenant = db.prepare(`SELECT * FROM tenants WHERE tenant_id = 'acme_corp'`).get();

    const stats: any = db.prepare(`
      SELECT
        COUNT(*) as total_requests_governed,
        COALESCE(SUM(cost_usd), 0) as total_spend_usd,
        COALESCE(SUM(finops_saved_usd), 0) as total_finops_saved_usd,
        SUM(CASE WHEN dlp_flags != '[]' AND dlp_flags != '' THEN 1 ELSE 0 END) as prompts_with_secrets_vaulted
      FROM synced_receipts
    `).get();

    const recentCryptographicReceipts = db.prepare(`
      SELECT * FROM synced_receipts ORDER BY timestamp DESC LIMIT 100
    `).all();

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
    const format = (parsedUrl.searchParams.get('format') || 'json').toLowerCase();
    const limit = Math.min(1000, parseInt(parsedUrl.searchParams.get('limit') || '200', 10));
    const filter = (parsedUrl.searchParams.get('filter') || 'all').toLowerCase();

    let query = `SELECT * FROM synced_receipts`;
    if (filter === 'dlp') {
      query += ` WHERE dlp_flags != '[]' AND dlp_flags != ''`;
    }
    query += ` ORDER BY timestamp DESC LIMIT ?`;
    const rows: any[] = db.prepare(query).all(limit);

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
    const auth = ((req.headers['authorization'] as string) || '').replace('Bearer ', '').trim();
    let tenant: any = auth ? db.prepare(`SELECT * FROM tenants WHERE cluster_sync_token = ?`).get(auth) : null;
    if (!tenant) tenant = db.prepare(`SELECT * FROM tenants WHERE tenant_id = 'acme_corp'`).get();

    const { webhookUrl, authHeader, format } = await readJsonBody(req);
    db.prepare(`
      UPDATE tenants SET siem_webhook_url = ?, siem_auth_header = ?, siem_format = ? WHERE tenant_id = ?
    `).run(webhookUrl || '', authHeader || '', format || 'json', tenant.tenant_id);

    return sendJson(res, 200, {
      status: 'saved',
      message: 'SIEM Push Webhook configuration saved. All new AI Agent receipts will stream automatically.',
      config: { webhookUrl, format: format || 'json' }
    });
  }

  // SIEM Test Push Dispatcher
  if (req.method === 'POST' && pathname === '/api/v1/siem/test-push') {
    const { webhookUrl, authHeader, format } = await readJsonBody(req);
    const sampleEvent = {
      receipt_id: 'rcpt_siem_test_' + crypto.randomBytes(4).toString('hex'),
      tenant_id: 'acme_corp',
      department: 'secops_verification',
      model_requested: 'gemini-2.5-pro',
      model_routed: 'gemini-2.5-flash',
      prompt_tokens: 320,
      completion_tokens: 190,
      cost_usd: 0.00042,
      finops_saved_usd: 0.00185,
      dlp_flags: '["AWS_ACCESS_KEY","INTERNAL_CORP_HOST"]',
      previous_receipt_hash: '0000000000000000',
      receipt_hmac: crypto.createHmac('sha256', defaultSyncToken).update('siem_verification').digest('hex'),
      timestamp: new Date().toISOString()
    };

    const formattedPayload = format === 'cef'
      ? { cef: formatReceiptAsCEF(sampleEvent) }
      : { schema: 'aindigo.siem.telemetry.v1', eventType: 'SIEM_PUSH_VERIFICATION', event: sampleEvent };

    if (webhookUrl && webhookUrl.startsWith('http')) {
      try {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' };
        if (authHeader) headers['Authorization'] = authHeader;
        const resp = await fetch(webhookUrl, { method: 'POST', headers, body: JSON.stringify(formattedPayload) });
        return sendJson(res, 200, {
          status: 'pushed_to_remote_siem',
          httpStatus: resp.status,
          targetWebhook: webhookUrl,
          dispatchedPayload: formattedPayload
        });
      } catch (err) {
        return sendJson(res, 200, {
          status: 'simulated_local_only',
          note: 'Remote webhook unreachable from local environment (' + (err as Error).message + '); showing generated SIEM payload below.',
          dispatchedPayload: formattedPayload
        });
      }
    }

    return sendJson(res, 200, {
      status: 'simulated_siem_event',
      note: 'No external webhook URL provided. Here is the exact Zero-Knowledge SIEM payload ready for Splunk / Datadog / Sentinel:',
      dispatchedPayload: formattedPayload
    });
  }

  sendJson(res, 404, { error: 'Not found: ' + pathname });
});

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`☁️  [AIndigo Cloud Control Plane v1.00.00-beta] Active on http://127.0.0.1:${PORT}`);
});
