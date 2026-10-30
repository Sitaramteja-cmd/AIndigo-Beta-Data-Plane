import { z } from 'zod';
export declare const DlpActionSchema: z.ZodEnum<{
    redact: "redact";
    block: "block";
    audit: "audit";
}>;
export type DlpAction = z.infer<typeof DlpActionSchema>;
export declare const DetectedEntitySchema: z.ZodObject<{
    type: z.ZodString;
    token: z.ZodString;
    syntheticPlaceholder: z.ZodString;
    start: z.ZodNumber;
    end: z.ZodNumber;
}, z.core.$strip>;
export type DetectedEntity = z.infer<typeof DetectedEntitySchema>;
export declare const GatewayMetadataSchema: z.ZodObject<{
    tenantId: z.ZodString;
    department: z.ZodString;
    overheadMs: z.ZodNumber;
    dlpAction: z.ZodEnum<{
        redact: "redact";
        block: "block";
        audit: "audit";
    }>;
    flaggedCategories: z.ZodArray<z.ZodString>;
    modelRequested: z.ZodString;
    modelRouted: z.ZodString;
    budgetDowngraded: z.ZodBoolean;
    tokensEstimated: z.ZodObject<{
        prompt: z.ZodNumber;
        completion: z.ZodNumber;
    }, z.core.$strip>;
}, z.core.$strip>;
export type GatewayMetadata = z.infer<typeof GatewayMetadataSchema>;
export declare const VirtualKeyRecordSchema: z.ZodObject<{
    keyHash: z.ZodString;
    tenantId: z.ZodString;
    department: z.ZodString;
    provider: z.ZodEnum<{
        openai: "openai";
        anthropic: "anthropic";
        gemini: "gemini";
    }>;
    encryptedUpstreamKey: z.ZodString;
    keyIv: z.ZodString;
    keyAuthTag: z.ZodString;
    monthlyBudgetUsd: z.ZodNumber;
    currentSpendUsd: z.ZodNumber;
    dlpMode: z.ZodEnum<{
        redact: "redact";
        block: "block";
        audit: "audit";
    }>;
    isActive: z.ZodBoolean;
}, z.core.$strip>;
export type VirtualKeyRecord = z.infer<typeof VirtualKeyRecordSchema>;
export declare const AuditReceiptSchema: z.ZodObject<{
    receiptId: z.ZodString;
    tenantId: z.ZodString;
    department: z.ZodString;
    modelRequested: z.ZodString;
    modelRouted: z.ZodString;
    promptTokens: z.ZodNumber;
    completionTokens: z.ZodNumber;
    costUsd: z.ZodNumber;
    savedUsd: z.ZodNumber;
    dlpFlags: z.ZodArray<z.ZodString>;
    promptSha256: z.ZodString;
    previousReceiptHash: z.ZodString;
    receiptHmac: z.ZodString;
    createdAt: z.ZodString;
}, z.core.$strip>;
export type AuditReceipt = z.infer<typeof AuditReceiptSchema>;
export declare const TelemetryBatchSchema: z.ZodObject<{
    dataPlaneNodeId: z.ZodString;
    receipts: z.ZodArray<z.ZodObject<{
        receiptId: z.ZodString;
        tenantId: z.ZodString;
        department: z.ZodString;
        modelRequested: z.ZodString;
        modelRouted: z.ZodString;
        promptTokens: z.ZodNumber;
        completionTokens: z.ZodNumber;
        costUsd: z.ZodNumber;
        savedUsd: z.ZodNumber;
        dlpFlags: z.ZodArray<z.ZodString>;
        promptSha256: z.ZodString;
        previousReceiptHash: z.ZodString;
        receiptHmac: z.ZodString;
        createdAt: z.ZodString;
    }, z.core.$strip>>;
}, z.core.$strip>;
export type TelemetryBatch = z.infer<typeof TelemetryBatchSchema>;
//# sourceMappingURL=types.d.ts.map