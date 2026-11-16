import {
  createVaultSession,
  scrubAndVaultText,
  destroyVaultSession,
} from '../dlp-vault.js';

export type DlpMode = 'redact' | 'block' | 'audit';

export interface ProtectedMessage {
  role: string;
  content: string;
}

export interface DlpRequestPreparation {
  mode: DlpMode;
  vaultSession: ReturnType<typeof createVaultSession>;
  providerMessages: ProtectedMessage[];
  flaggedCategories: string[];
  replacementsCount: number;
  blocked: boolean;
}

export function prepareDlpRequest(
  tenantId: string,
  messages: ProtectedMessage[],
  mode: DlpMode
): DlpRequestPreparation {
  const vaultSession = createVaultSession(tenantId);

  try {
    const scannedMessages = messages.map((message) => {
      const outcome = scrubAndVaultText(message.content, vaultSession);

      return {
        role: message.role,
        content: outcome.sanitizedText,
      };
    });

    const flaggedCategories = Array.from(vaultSession.detectedCategories);
    const replacementsCount = vaultSession.forwardMap.size;
    const blocked = mode === 'block' && flaggedCategories.length > 0;

    if (mode === 'audit' || blocked) {
      vaultSession.forwardMap.clear();
      vaultSession.reverseMap.clear();
    }

    return {
      mode,
      vaultSession,
      providerMessages:
        mode === 'redact'
          ? scannedMessages
          : messages.map((message) => ({ ...message })),
      flaggedCategories,
      replacementsCount,
      blocked,
    };
  } catch (error) {
    destroyVaultSession(vaultSession.sessionId);
    throw error;
  }
}
