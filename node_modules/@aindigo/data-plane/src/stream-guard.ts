import { VaultSession, rehydrateFromVault, destroyVaultSession } from './dlp-vault.js';

/**
 * High-risk command signatures for the Autonomous Agent Tool-Call Firewall
 */
const DANGEROUS_AGENT_PATTERNS: { name: string; regex: RegExp }[] = [
  { name: 'DESTRUCTIVE_FS_WIPE', regex: /\brm\s+-[rf]{1,2}\s+(?:\/|\*|~|\.\.)/i },
  { name: 'SQL_DESTRUCTIVE_DDL', regex: /\b(?:DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE)\b/i },
  { name: 'CREDENTIAL_FILE_EXFIL', regex: /\b(?:cat|type|Get-Content)\s+[^\n]*?(?:\.env|id_rsa|\.aws\/credentials)/i },
  { name: 'EXTERNAL_WEBHOOK_EXFIL', regex: /\b(?:curl|wget|Invoke-WebRequest)\b[^\n]*?-d\s+[^\n]*?\$/i },
];

export interface FirewallCheckResult {
  blocked: boolean;
  violationType?: string;
}

/**
 * Scans LLM output or tool_calls arguments for destructive commands or prompt-injection exfiltration
 */
export function inspectAgentOutputFirewall(textChunk: string): FirewallCheckResult {
  for (const rule of DANGEROUS_AGENT_PATTERNS) {
    if (rule.regex.test(textChunk)) {
      return { blocked: true, violationType: rule.name };
    }
  }
  return { blocked: false };
}

/**
 * Creates a chunk-boundary-safe SSE stream that re-hydrates synthetic vault tokens
 * even when a synthetic token is split across two network chunks, while enforcing the Agent Firewall.
 */
export function createRehydratingSseStream(
  rawChunks: string[],
  vaultSession: VaultSession,
  protocol: 'openai' | 'anthropic',
  modelRouted: string
): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();

  // Combine text chunks cleanly across token boundaries before emitting SSE frames
  const fullCombinedText = rawChunks.join('');
  const firewallCheck = inspectAgentOutputFirewall(fullCombinedText);

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      try {
        if (firewallCheck.blocked) {
          const blockEvent = {
            error: 'AGENT_FIREWALL_INTERCEPTED',
            violation: firewallCheck.violationType,
            message: `AIndigo Agent Firewall terminated stream: blocked [${firewallCheck.violationType}] execution.`,
          };
          controller.enqueue(encoder.encode(`event: error\ndata: ${JSON.stringify(blockEvent)}\n\n`));
          controller.close();
          return;
        }

        // Re-hydrate across the assembled sliding window so split tokens never fail
        const rehydratedFullText = rehydrateFromVault(fullCombinedText, vaultSession);

        // Stream back in realistic word-by-word SSE chunks
        const words = rehydratedFullText.split(/(?=[ \n])/);

        for (let i = 0; i < words.length; i++) {
          const piece = words[i] ?? '';
          if (protocol === 'openai') {
            const chunkPayload = {
              id: `chatcmpl-aindigo-${vaultSession.sessionId.slice(0, 8)}`,
              object: 'chat.completion.chunk',
              created: Math.floor(Date.now() / 1000),
              model: modelRouted,
              choices: [
                {
                  index: 0,
                  delta: { content: piece },
                  finish_reason: null,
                },
              ],
            };
            controller.enqueue(encoder.encode(`data: ${JSON.stringify(chunkPayload)}\n\n`));
          } else {
            // Native Anthropic / Claude Code SSE format
            const chunkPayload = {
              type: 'content_block_delta',
              index: 0,
              delta: { type: 'text_delta', text: piece },
            };
            controller.enqueue(
              encoder.encode(`event: content_block_delta\ndata: ${JSON.stringify(chunkPayload)}\n\n`)
            );
          }
        }

        // Emit protocol-appropriate stream termination
        if (protocol === 'openai') {
          controller.enqueue(encoder.encode(`data: [DONE]\n\n`));
        } else {
          controller.enqueue(
            encoder.encode(`event: message_stop\ndata: {"type":"message_stop"}\n\n`)
          );
        }
        controller.close();
      } finally {
        // Always wipe the vault from RAM as soon as the stream ends
        destroyVaultSession(vaultSession.sessionId);
      }
    },
  });
}
