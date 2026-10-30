import { z } from 'zod';
export const DlpActionSchema = z.enum(['redact', 'block', 'audit']);
export const DetectedEntitySchema = z.object({
    type: z.string(),
    token: z.string(),
    syntheticPlaceholder: z.string(),
    start: z.number().int().nonnegative(),
    end: z.number().int().nonnegative(),
});
export const GatewayMetadataSchema = z.object({
    tenantId: z.string().min(1),
    department: z.string().min(1),
    overheadMs: z.number().nonnegative(),
    dlpAction: DlpActionSchema,
    flaggedCategories: z.array(z.string()),
    modelRequested: z.string().min(1),
    modelRouted: z.string().min(1),
    budgetDowngraded: z.boolean(),
    tokensEstimated: z.object({
        prompt: z.number().int().nonnegative(),
        completion: z.number().int().nonnegative(),
    }),
});
export const VirtualKeyRecordSchema = z.object({
    keyHash: z.string().min(64).max(64),
    tenantId: z.string().min(1),
    department: z.string().min(1),
    provider: z.enum(['openai', 'anthropic', 'gemini']),
    encryptedUpstreamKey: z.string().min(1),
    keyIv: z.string().min(1),
    keyAuthTag: z.string().min(1),
    monthlyBudgetUsd: z.number().positive(),
    currentSpendUsd: z.number().nonnegative(),
    dlpMode: DlpActionSchema,
    isActive: z.boolean(),
});
export const AuditReceiptSchema = z.object({
    receiptId: z.string().min(1),
    tenantId: z.string().min(1),
    department: z.string().min(1),
    modelRequested: z.string().min(1),
    modelRouted: z.string().min(1),
    promptTokens: z.number().int().nonnegative(),
    completionTokens: z.number().int().nonnegative(),
    costUsd: z.number().nonnegative(),
    savedUsd: z.number().nonnegative(),
    dlpFlags: z.array(z.string()),
    promptSha256: z.string().length(64),
    previousReceiptHash: z.string().length(64),
    receiptHmac: z.string().length(64),
    createdAt: z.string().min(1),
});
export const TelemetryBatchSchema = z.object({
    dataPlaneNodeId: z.string().min(1),
    receipts: z.array(AuditReceiptSchema).min(1).max(500),
});
//# sourceMappingURL=types.js.map