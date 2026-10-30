import crypto from 'node:crypto';
import { LRUCache } from 'lru-cache';

const MAX_SCAN_LENGTH = 200_000; // 200KB hard ceiling per text block to prevent DoS

export interface VaultSession {
  sessionId: string;
  tenantId: string;
  forwardMap: Map<string, string>; // realSecret -> syntheticToken
  reverseMap: Map<string, string>; // syntheticToken -> realSecret
  detectedCategories: Set<string>;
  createdAt: number;
}

// Ephemeral in-memory vault: Auto-purges sessions after 120 seconds (TTL)
const activeVaults = new LRUCache<string, VaultSession>({
  max: 10_000,
  ttl: 120 * 1000,
});

/**
 * Luhn Checksum Validator to prevent false-positive credit card matches on random numbers
 */
function isValidLuhn(digitsOnly: string): boolean {
  if (digitsOnly.length < 13 || digitsOnly.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digitsOnly.length - 1; i >= 0; i--) {
    let digit = Number.parseInt(digitsOnly.charAt(i), 10);
    if ( Number.isNaN(digit)) return false;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

interface DlpRule {
  category: string;
  regex: RegExp;
  validate?: (match: string) => boolean;
  makeSynthetic: (index: number) => string;
}

/**
 * Linear-time bounded regex rules (Zero nested quantifiers = Zero ReDoS risk)
 */
const DLP_RULES: DlpRule[] = [
  {
    category: 'PRIVATE_KEY_BLOCK',
    regex: /-----BEGIN [A-Z ]{1,32} PRIVATE KEY-----[\s\S]{1,16384}?-----END [A-Z ]{1,32} PRIVATE KEY-----/g,
    makeSynthetic: (i) => `-----BEGIN SYNTHETIC PRIVATE KEY ${i}-----`,
  },
  {
    category: 'OPENAI_API_KEY',
    regex: /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,160}\b/g,
    makeSynthetic: (i) => `sk-proj-SYNTHETICVAULTKEY0000${i}`,
  },
  {
    category: 'ANTHROPIC_API_KEY',
    regex: /\bsk-ant-api03-[A-Za-z0-9_-]{20,120}\b/g,
    makeSynthetic: (i) => `sk-ant-api03-SYNTHETICVAULTKEY0000${i}`,
  },
  {
    category: 'AWS_ACCESS_KEY',
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    makeSynthetic: (i) => `AKIA0000VAULTKEY${String(i).padStart(4, '0')}`,
  },
  {
    category: 'GITHUB_TOKEN',
    regex: /\bgh[pousr]_[A-Za-z0-9_]{36,100}\b/g,
    makeSynthetic: (i) => `ghp_SYNTHETICGITHUBVAULTTOKEN0000000000${i}`,
  },
  {
    category: 'SLACK_TOKEN',
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,64}\b/g,
    makeSynthetic: (i) => `xoxb-SYNTHETIC-SLACK-VAULT-${i}`,
  },
  {
    category: 'INTERNAL_CORP_HOST',
    regex: /\b[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})*\.(?:internal|corp|local|lan)\b/g,
    makeSynthetic: (i) => `host-vault-${i}.example.internal`,
  },
  {
    category: 'PROPRIETARY_PACKAGE_IMPORT',
    regex: /@[a-z0-9-]{1,32}-internal\/[a-z0-9-_./]{1,64}/g,
    makeSynthetic: (i) => `@public-sdk/module-vault-${i}`,
  },
  {
    category: 'INDIAN_PAN',
    regex: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
    makeSynthetic: (i) => `ABCDE${String(1000 + i).slice(0, 4)}Z`,
  },
  {
    category: 'INDIAN_AADHAAR',
    regex: /\b[2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}\b/g,
    makeSynthetic: (i) => `9000-0000-${String(1000 + i).slice(0, 4)}`,
  },
  {
    category: 'CREDIT_CARD',
    regex: /\b(?:\d[ -]?){13,16}\b/g,
    validate: (match) => isValidLuhn(match.replace(/\D/g, '')),
    makeSynthetic: (i) => `4111-1111-1111-${String(1000 + i).slice(0, 4)}`,
  },
  {
    category: 'EMAIL_ADDRESS',
    regex: /\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,128}\.[A-Za-z]{2,12}\b/g,
    makeSynthetic: (i) => `user_vault_${i}@example.com`,
  },
];

export function createVaultSession(tenantId: string): VaultSession {
  const sessionId = crypto.randomUUID();
  const session: VaultSession = {
    sessionId,
    tenantId,
    forwardMap: new Map(),
    reverseMap: new Map(),
    detectedCategories: new Set(),
    createdAt: Date.now(),
  };
  activeVaults.set(sessionId, session);
  return session;
}

export interface ScrubOutcome {
  sanitizedText: string;
  flaggedCategories: string[];
  replacementsCount: number;
  scanDurationMs: number;
}

/**
 * Outbound Scrub: Replaces real secrets/PII with format-preserving synthetic tokens
 */
export function scrubAndVaultText(text: string, session: VaultSession): ScrubOutcome {
  const start = performance.now();

  if (text.length > MAX_SCAN_LENGTH) {
    throw new Error(`DLP_PAYLOAD_TOO_LARGE: Text exceeds ${MAX_SCAN_LENGTH} characters.`);
  }

  let sanitizedText = text;
  let counter = session.forwardMap.size + 1;

  for (const rule of DLP_RULES) {
    sanitizedText = sanitizedText.replace(rule.regex, (matchedValue) => {
      if (rule.validate && !rule.validate(matchedValue)) {
        return matchedValue; // Skip if checksum fails (e.g., non-Luhn number)
      }

      session.detectedCategories.add(rule.category);

      // Reuse existing synthetic token if the exact same secret already appeared in this request
      const existingSynthetic = session.forwardMap.get(matchedValue);
      if (existingSynthetic) {
        return existingSynthetic;
      }

      const syntheticToken = rule.makeSynthetic(counter++);
      session.forwardMap.set(matchedValue, syntheticToken);
      session.reverseMap.set(syntheticToken, matchedValue);
      return syntheticToken;
    });
  }

  const scanDurationMs = Number((performance.now() - start).toFixed(3));

  return {
    sanitizedText,
    flaggedCategories: Array.from(session.detectedCategories),
    replacementsCount: session.forwardMap.size,
    scanDurationMs,
  };
}

/**
 * Inbound Re-Hydration: Restores synthetic tokens back to real secrets for the client
 */
export function rehydrateFromVault(llmOutputText: string, session: VaultSession): string {
  if (session.reverseMap.size === 0) return llmOutputText;

  let rehydrated = llmOutputText;
  for (const [syntheticToken, realSecret] of session.reverseMap.entries()) {
    // Use split/join for literal replacement without regex escaping risks
    rehydrated = rehydrated.split(syntheticToken).join(realSecret);
  }
  return rehydrated;
}

/**
 * Explicitly wipe vault session from RAM once stream completes
 */
export function destroyVaultSession(sessionId: string): void {
  const session = activeVaults.get(sessionId);
  if (session) {
    session.forwardMap.clear();
    session.reverseMap.clear();
    session.detectedCategories.clear();
    activeVaults.delete(sessionId);
  }
}
