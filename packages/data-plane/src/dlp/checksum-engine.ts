import {
  isValidVerhoeff12Id,
  isValidPaymentCard,
  isValidIndianPan,
  isValidIndianGstin,
  isValidIndianIfsc,
  isValidIban,
  isValidUsSsn,
  isValidUsAbaRouting,
  isValidUkNhsNumber,
  isValidSaudiNationalId,
  isValidUaeEmiratesId,
  isValidAustralianAbn,
  isValidAustralianTfn,
  classifyGithubToken,
} from "./checksum-validators.js";

export type DetectorType =
  | "GITHUB_PAT"
  | "INDIAN_GSTIN"
  | "INDIAN_PAN"
  | "INDIAN_IFSC"
  | "IBAN"
  | "UAE_EMIRATES_ID"
  | "PAYMENT_CARD"
  | "IN_VERHOEFF_12_ID"
  | "AU_ABN"
  | "UK_NHS"
  | "SAUDI_NATIONAL_ID"
  | "US_SSN"
  | "US_ABA_ROUTING"
  | "AU_TFN";

export interface DetectedSecretSpan {
  type: DetectorType;
  start: number;
  end: number;
  rawMatch: string;
  replacement: string;
  severity: "CRITICAL_VERIFIED" | "HIGH_PREFIX_MATCH";
}

export interface ScanAndRedactResult {
  redactedText: string;
  detections: DetectedSecretSpan[];
}

interface DetectorSpec {
  type: DetectorType;
  priority: number;
  candidateRegex: RegExp;
  contextRegex?: RegExp;
  requireContext?: (rawMatch: string) => boolean;
  validate: (rawMatch: string, hasContext: boolean) => { valid: boolean; severity?: "CRITICAL_VERIFIED" | "HIGH_PREFIX_MATCH" };
}

const CONTEXT_WINDOW_RADIUS = 56;

const DETECTOR_SPECS: ReadonlyArray<DetectorSpec> = [
  {
    type: "GITHUB_PAT",
    priority: 1,
    candidateRegex: /(?<![A-Za-z0-9_])(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z]{22}_[0-9A-Za-z]{59})(?![A-Za-z0-9_])/g,
    validate: (raw) => {
      const c = classifyGithubToken(raw);
      return { valid: c.shouldRedact, severity: c.severity === "NONE" ? undefined : c.severity };
    },
  },
  {
    type: "INDIAN_GSTIN",
    priority: 2,
    candidateRegex: /(?<![A-Za-z0-9_])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Za-z0-9_])/g,
    validate: (raw) => ({ valid: isValidIndianGstin(raw) }),
  },
  {
    type: "IBAN",
    priority: 3,
    candidateRegex: /(?<![A-Za-z0-9_])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?(?![A-Za-z0-9_])/g,
    validate: (raw) => ({ valid: isValidIban(raw) }),
  },
  {
    type: "UAE_EMIRATES_ID",
    priority: 4,
    candidateRegex: /(?<![A-Za-z0-9_])784[- ]?(?:19\d{2}|20\d{2})[- ]?\d{7}[- ]?\d(?![A-Za-z0-9_])/g,
    validate: (raw) => ({ valid: isValidUaeEmiratesId(raw) }),
  },
  {
    type: "PAYMENT_CARD",
    priority: 5,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}|\d{4}[ -]\d{6}[ -]\d{5}|\d{13,19})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:card|visa|mastercard|amex|cc|pan|billing|payment|card_number|credit|debit)\b/i,
    requireContext: (raw) => !/[ -]/.test(raw) && raw.length !== 16 && raw.length !== 15,
    validate: (raw, hasContext) => {
      if (!/[ -]/.test(raw) && (raw.length !== 16 && raw.length !== 15) && !hasContext) return { valid: false };
      return { valid: isValidPaymentCard(raw) };
    },
  },
  {
    type: "INDIAN_PAN",
    priority: 6,
    candidateRegex: /(?<![A-Za-z0-9_])[A-Z]{3}[ABCFGHLJPTK][A-Z]\d{4}[A-Z](?![A-Za-z0-9_])/g,
    validate: (raw) => ({ valid: isValidIndianPan(raw) }),
  },
  {
    type: "INDIAN_IFSC",
    priority: 7,
    candidateRegex: /(?<![A-Za-z0-9_])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9_])/g,
    contextRegex: /\b(?:ifsc|bank|branch|neft|rtgs|imps|account)\b/i,
    requireContext: (raw) => !/\d/.test(raw.slice(5)),
    validate: (raw, hasContext) => {
      if (!/\d/.test(raw.slice(5)) && !hasContext) return { valid: false };
      return { valid: isValidIndianIfsc(raw) };
    },
  },
  {
    type: "IN_VERHOEFF_12_ID",
    priority: 8,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:[2-9]\d{3}[ -]\d{4}[ -]\d{4}|[2-9]\d{11})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:aadhaar|aadhar|uidai|uid|kyc|vid)\b/i,
    requireContext: (raw) => !/[ -]/.test(raw),
    validate: (raw, hasContext) => {
      if (!/[ -]/.test(raw) && !hasContext) return { valid: false };
      return { valid: isValidVerhoeff12Id(raw) };
    },
  },
  {
    type: "AU_ABN",
    priority: 9,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:\d{2}[ -]\d{3}[ -]\d{3}[ -]\d{3}|\d{11})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:abn|australian business)\b/i,
    requireContext: (raw) => !/[ -]/.test(raw),
    validate: (raw, hasContext) => {
      if (!/[ -]/.test(raw) && !hasContext) return { valid: false };
      return { valid: isValidAustralianAbn(raw) };
    },
  },
  {
    type: "UK_NHS",
    priority: 10,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:\d{3}[ -]\d{3}[ -]\d{4}|\d{10})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:nhs|patient|health_id)\b/i,
    requireContext: () => true,
    validate: (raw, hasContext) => ({ valid: hasContext && isValidUkNhsNumber(raw) }),
  },
  {
    type: "SAUDI_NATIONAL_ID",
    priority: 11,
    candidateRegex: /(?<![A-Za-z0-9_.-])[12]\d{9}(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:iqama|saudi|national_id|nin|hijri|resident_id)\b/i,
    requireContext: () => true,
    validate: (raw, hasContext) => ({ valid: hasContext && isValidSaudiNationalId(raw) }),
  },
  {
    type: "US_SSN",
    priority: 12,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:\d{3}-\d{2}-\d{4}|\d{9})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:ssn|social[ _-]?security|taxpayer|soc_sec)\b/i,
    requireContext: (raw) => !raw.includes("-"),
    validate: (raw, hasContext) => ({ valid: isValidUsSsn(raw, hasContext) }),
  },
  {
    type: "US_ABA_ROUTING",
    priority: 13,
    candidateRegex: /(?<![A-Za-z0-9_.-])\d{9}(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:aba|routing|rtn|transit|ach)\b/i,
    requireContext: () => true,
    validate: (raw, hasContext) => ({ valid: hasContext && isValidUsAbaRouting(raw) }),
  },
  {
    type: "AU_TFN",
    priority: 14,
    candidateRegex: /(?<![A-Za-z0-9_.-])(?:\d{3}[ -]\d{3}[ -]\d{3}|\d{9})(?![A-Za-z0-9_.-])/g,
    contextRegex: /\b(?:tfn|tax[ _-]?file)\b/i,
    requireContext: () => true,
    validate: (raw, hasContext) => ({ valid: hasContext && isValidAustralianTfn(raw) }),
  },
];

function hasSurroundingContext(text: string, start: number, end: number, contextRegex?: RegExp): boolean {
  if (!contextRegex) return true;
  const lastNewlineBefore = text.lastIndexOf("\n", start);
  const nextNewlineAfter = text.indexOf("\n", end);
  const lineStart = lastNewlineBefore === -1 ? 0 : lastNewlineBefore + 1;
  const lineEnd = nextNewlineAfter === -1 ? text.length : nextNewlineAfter;

  const winStart = Math.max(lineStart, start - CONTEXT_WINDOW_RADIUS);
  const winEnd = Math.min(lineEnd, end + CONTEXT_WINDOW_RADIUS);
  const snippet = text.slice(winStart, winEnd);
  return contextRegex.test(snippet);
}

export function scanAndRedactWithChecksums(
  text: string,
  onVaultToken?: (type: DetectorType, rawMatch: string, index: number) => string
): ScanAndRedactResult {
  const candidates: Array<DetectedSecretSpan & { priority: number }> = [];

  for (const spec of DETECTOR_SPECS) {
    const regex = new RegExp(spec.candidateRegex.source, spec.candidateRegex.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      const rawMatch = match[0];
      const start = match.index;
      const end = start + rawMatch.length;

      const hasContext = hasSurroundingContext(text, start, end, spec.contextRegex);
      if (spec.requireContext && spec.requireContext(rawMatch) && !hasContext) {
        continue;
      }

      const res = spec.validate(rawMatch, hasContext);
      if (res.valid) {
        // DIAGNOSTIC LOGGING TO IDENTIFY WHICH DETECTOR MATCHED UNWANTED TOKENS
        console.log(`[DLP_MATCH_DEBUG] Type: ${spec.type}, Match: "${rawMatch}", Start: ${start}, HasContext: ${hasContext}`);
        candidates.push({
          type: spec.type,
          priority: spec.priority,
          start,
          end,
          rawMatch,
          replacement: "",
          severity: res.severity ?? "CRITICAL_VERIFIED",
        });
      }
    }
  }

  candidates.sort((a, b) => {
    const lenDiff = (b.end - b.start) - (a.end - a.start);
    if (lenDiff !== 0) return lenDiff;
    if (a.priority !== b.priority) return a.priority - b.priority;
    return a.start - b.start;
  });

  const accepted: DetectedSecretSpan[] = [];
  for (const cand of candidates) {
    const overlaps = accepted.some((existing) => cand.start < existing.end && cand.end > existing.start);
    if (!overlaps) {
      accepted.push(cand);
    }
  }

  accepted.sort((a, b) => a.start - b.start);

  accepted.forEach((span, idx) => {
    span.replacement = onVaultToken
      ? onVaultToken(span.type, span.rawMatch, idx + 1)
      : `[REDACTED_${span.type}]`;
  });

  let redactedText = text;
  for (let i = accepted.length - 1; i >= 0; i--) {
    const span = accepted[i];
    redactedText = redactedText.slice(0, span.start) + span.replacement + redactedText.slice(span.end);
  }

  return { redactedText, detections: accepted };
}