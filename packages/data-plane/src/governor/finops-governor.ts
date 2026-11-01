import type { VirtualKeyMetadata } from "../vault/virtual-key-vault.js";

export interface FinOpsGovernorConfig {
  thresholdPercent: number; // 0 to 100
  modelMappings: Record<string, string>; // { "gpt-4o": "gpt-4o-mini" }
  enabled?: boolean;
}

export interface GovernorEvaluationResult {
  effectiveModel: string;
  downshifted: boolean;
  utilizationPercent: number;
  reason?: string;
}

export class FinOpsGovernor {
  private thresholdPercent: number;
  private modelMappings: Map<string, string>;
  private enabled: boolean;

  constructor(config: FinOpsGovernorConfig) {
    if (
      typeof config.thresholdPercent !== "number" ||
      !Number.isFinite(config.thresholdPercent) ||
      config.thresholdPercent < 0 ||
      config.thresholdPercent > 100
    ) {
      throw new Error("GOVERNOR_CONFIG_ERROR: thresholdPercent must be a finite number between 0 and 100.");
    }

    this.thresholdPercent = config.thresholdPercent;
    this.enabled = config.enabled ?? true;
    this.modelMappings = new Map();

    const rawMappings = config.modelMappings || {};
    for (const [from, to] of Object.entries(rawMappings)) {
      const cleanFrom = from.trim().toLowerCase();
      const cleanTo = to.trim().toLowerCase();

      if (cleanFrom === cleanTo) {
        throw new Error(`GOVERNOR_CONFIG_ERROR: Self-mapping not allowed ('${from}' -> '${to}').`);
      }
      this.modelMappings.set(cleanFrom, cleanTo);
    }

    for (const [from, to] of this.modelMappings.entries()) {
      if (this.modelMappings.has(to)) {
        throw new Error(`GOVERNOR_CONFIG_ERROR: Chained/looped mapping detected ('${from}' -> '${to}' -> '${this.modelMappings.get(to)}').`);
      }
    }
  }

  public evaluate(
    metadata: VirtualKeyMetadata,
    requestedModel: string,
    nowMs: number = Date.now()
  ): GovernorEvaluationResult {
    if (!this.enabled || metadata.budget_limit_micros <= 0) {
      return {
        effectiveModel: requestedModel,
        downshifted: false,
        utilizationPercent: 0,
      };
    }

    const isMonthlyReset =
      metadata.budget_period === "monthly" && nowMs >= metadata.period_reset_at;

    const effectiveSpendMicros = isMonthlyReset
      ? metadata.reserved_micros
      : metadata.current_spend_micros + metadata.reserved_micros;

    const utilization = (effectiveSpendMicros / metadata.budget_limit_micros) * 100;

    if (utilization < this.thresholdPercent) {
      return {
        effectiveModel: requestedModel,
        downshifted: false,
        utilizationPercent: Number(utilization.toFixed(2)),
      };
    }

    const cleanReq = requestedModel.trim().toLowerCase();
    const targetModel = this.modelMappings.get(cleanReq);

    if (!targetModel) {
      return {
        effectiveModel: requestedModel,
        downshifted: false,
        utilizationPercent: Number(utilization.toFixed(2)),
        reason: "NO_MAPPING_CONFIGURED",
      };
    }

    const allowed = metadata.allowed_models.map((m) => m.toLowerCase());
    const isAllowed = allowed.includes("*") || allowed.includes(targetModel);

    if (!isAllowed) {
      return {
        effectiveModel: requestedModel,
        downshifted: false,
        utilizationPercent: Number(utilization.toFixed(2)),
        reason: "TARGET_NOT_ALLOWED",
      };
    }

    return {
      effectiveModel: targetModel,
      downshifted: true,
      utilizationPercent: Number(utilization.toFixed(2)),
      reason: `BUDGET_UTILIZATION_${Math.round(utilization)}%_EXCEEDED_THRESHOLD_${this.thresholdPercent}%`,
    };
  }
}