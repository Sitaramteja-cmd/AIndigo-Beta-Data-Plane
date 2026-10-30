import crypto from 'node:crypto';
import { LRUCache } from 'lru-cache';

export interface ModelPricing {
  inputPer1M: number;  // USD per 1,000,000 prompt tokens
  outputPer1M: number; // USD per 1,000,000 completion tokens
  downgradeTarget?: string;
}

/**
 * Enterprise Model Pricing & Smart Downgrade Map (USD per 1M tokens)
 */
export const MODEL_CATALOG: Record<string, ModelPricing> = {
  // Anthropic Models
  'claude-3-7-sonnet': {
    inputPer1M: 3.00,
    outputPer1M: 15.00,
    downgradeTarget: 'claude-3-5-haiku',
  },
  'claude-3-5-haiku': {
    inputPer1M: 0.80,
    outputPer1M: 4.00,
  },
  // OpenAI Models
  'gpt-4o': {
    inputPer1M: 2.50,
    outputPer1M: 10.00,
    downgradeTarget: 'gpt-4o-mini',
  },
  'gpt-4o-mini': {
    inputPer1M: 0.15,
    outputPer1M: 0.60,
  },
  // Google Gemini Models
  'gemini-2.5-pro': {
    inputPer1M: 1.25,
    outputPer1M: 10.00,
    downgradeTarget: 'gemini-2.5-flash',
  },
  'gemini-2.5-flash': {
    inputPer1M: 0.15,
    outputPer1M: 0.60,
  },
};

const DEFAULT_PRICING: ModelPricing = {
  inputPer1M: 1.00,
  outputPer1M: 3.00,
};

// Sliding-Window Agent Loop Tracker (Key: keyHash:promptHash -> Count within 60s TTL)
const loopTracker = new LRUCache<string, number>({
  max: 25_000,
  ttl: 60 * 1000, // 60-second sliding window
});

const MAX_IDENTICAL_PROMPTS_PER_MINUTE = 3;
const SOFT_CAP_THRESHOLD_RATIO = 0.80; // Trigger auto-downgrade at 80% budget utilization

export interface LoopCheckResult {
  isLooping: boolean;
  attemptCount: number;
  promptFingerprint: string;
}

/**
 * Detects if an autonomous agent (Devin, Claude Code, SWE-Agent) is stuck in a repetitive retry loop
 */
export function checkAgentTrajectoryLoop(keyHash: string, normalizedPrompt: string): LoopCheckResult {
  const promptFingerprint = crypto
    .createHash('sha256')
    .update(normalizedPrompt.trim().toLowerCase())
    .digest('hex')
    .slice(0, 16);

  const compositeKey = `${keyHash}:${promptFingerprint}`;
  const currentCount = (loopTracker.get(compositeKey) || 0) + 1;
  loopTracker.set(compositeKey, currentCount);

  return {
    isLooping: currentCount > MAX_IDENTICAL_PROMPTS_PER_MINUTE,
    attemptCount: currentCount,
    promptFingerprint,
  };
}

export interface BudgetRoutingDecision {
  allowed: boolean;
  status: 'NORMAL' | 'SOFT_CAP_DOWNGRADE' | 'HARD_CAP_BLOCK';
  utilizationPct: number;
  modelRequested: string;
  modelRouted: string;
  budgetDowngraded: boolean;
}

/**
 * Evaluates current department spend against monthly budget cap and decides model routing
 */
export function evaluateBudgetAndRouteModel(
  modelRequested: string,
  currentSpendUsd: number,
  monthlyBudgetUsd: number
): BudgetRoutingDecision {
  const utilizationRatio = monthlyBudgetUsd > 0 ? currentSpendUsd / monthlyBudgetUsd : 1;
  const utilizationPct = Number((utilizationRatio * 100).toFixed(2));

  // Stage 3: 100%+ Spend -> Hard Block
  if (utilizationRatio >= 1.0) {
    return {
      allowed: false,
      status: 'HARD_CAP_BLOCK',
      utilizationPct,
      modelRequested,
      modelRouted: modelRequested,
      budgetDowngraded: false,
    };
  }

  // Stage 2: 80% - 99.9% Spend -> Smart FinOps Auto-Downgrade
  const modelSpec = MODEL_CATALOG[modelRequested];
  if (utilizationRatio >= SOFT_CAP_THRESHOLD_RATIO && modelSpec?.downgradeTarget) {
    return {
      allowed: true,
      status: 'SOFT_CAP_DOWNGRADE',
      utilizationPct,
      modelRequested,
      modelRouted: modelSpec.downgradeTarget,
      budgetDowngraded: true,
    };
  }

  // Stage 1: 0% - 79.9% Spend -> Normal Flagship Routing
  return {
    allowed: true,
    status: 'NORMAL',
    utilizationPct,
    modelRequested,
    modelRouted: modelRequested,
    budgetDowngraded: false,
  };
}

export interface CostCalculation {
  actualCostUsd: number;
  originalRequestedCostUsd: number;
  finopsSavedUsd: number;
}

/**
 * Calculates exact USD cost for actual routed model vs. requested model to prove ROI savings
 */
export function calculateTurnCostAndSavings(
  modelRequested: string,
  modelRouted: string,
  promptTokens: number,
  completionTokens: number
): CostCalculation {
  const requestedPricing = MODEL_CATALOG[modelRequested] ?? DEFAULT_PRICING;
  const routedPricing = MODEL_CATALOG[modelRouted] ?? DEFAULT_PRICING;

  const originalRequestedCostUsd =
    (promptTokens / 1_000_000) * requestedPricing.inputPer1M +
    (completionTokens / 1_000_000) * requestedPricing.outputPer1M;

  const actualCostUsd =
    (promptTokens / 1_000_000) * routedPricing.inputPer1M +
    (completionTokens / 1_000_000) * routedPricing.outputPer1M;

  const finopsSavedUsd = Math.max(0, originalRequestedCostUsd - actualCostUsd);

  return {
    actualCostUsd: Number(actualCostUsd.toFixed(6)),
    originalRequestedCostUsd: Number(originalRequestedCostUsd.toFixed(6)),
    finopsSavedUsd: Number(finopsSavedUsd.toFixed(6)),
  };
}
