import test from 'node:test';
import assert from 'node:assert/strict';
import { prepareDlpRequest } from './request-protection.js';
import { destroyVaultSession, rehydrateFromVault } from '../dlp-vault.js';

const sensitiveMessage = {
  role: 'user',
  content: 'Contact me at teja.testing@example.com',
};

test('redact mode sanitizes messages and retains reversible mappings', () => {
  const result = prepareDlpRequest('tenant-test', [sensitiveMessage], 'redact');

  try {
    assert.equal(result.blocked, false);
    assert.ok(result.flaggedCategories.includes('EMAIL_ADDRESS'));
    assert.notEqual(
      result.providerMessages[0].content,
      sensitiveMessage.content
    );
    assert.ok(result.vaultSession.reverseMap.size > 0);

    const restored = rehydrateFromVault(
      result.providerMessages[0].content,
      result.vaultSession
    );

    assert.equal(restored, sensitiveMessage.content);
  } finally {
    destroyVaultSession(result.vaultSession.sessionId);
  }
});

test('block mode detects sensitive data and clears reversible mappings', () => {
  const result = prepareDlpRequest('tenant-test', [sensitiveMessage], 'block');

  try {
    assert.equal(result.blocked, true);
    assert.ok(result.flaggedCategories.includes('EMAIL_ADDRESS'));
    assert.equal(result.providerMessages[0].content, sensitiveMessage.content);
    assert.equal(result.vaultSession.forwardMap.size, 0);
    assert.equal(result.vaultSession.reverseMap.size, 0);
  } finally {
    destroyVaultSession(result.vaultSession.sessionId);
  }
});

test('block mode allows messages without detected sensitive data', () => {
  const message = {
    role: 'user',
    content: 'Please explain how an API gateway works.',
  };

  const result = prepareDlpRequest('tenant-test', [message], 'block');

  try {
    assert.equal(result.blocked, false);
    assert.deepEqual(result.flaggedCategories, []);
    assert.equal(result.providerMessages[0].content, message.content);
  } finally {
    destroyVaultSession(result.vaultSession.sessionId);
  }
});

test('audit mode detects sensitive data but sends original messages without mappings', () => {
  const result = prepareDlpRequest('tenant-test', [sensitiveMessage], 'audit');

  try {
    assert.equal(result.blocked, false);
    assert.ok(result.flaggedCategories.includes('EMAIL_ADDRESS'));
    assert.equal(result.providerMessages[0].content, sensitiveMessage.content);
    assert.ok(result.replacementsCount > 0);
    assert.equal(result.vaultSession.forwardMap.size, 0);
    assert.equal(result.vaultSession.reverseMap.size, 0);
  } finally {
    destroyVaultSession(result.vaultSession.sessionId);
  }
});

test('categories accumulate across all messages in one request', () => {
  const messages = [
    sensitiveMessage,
    {
      role: 'user',
      content: 'A second message contains another@example.com',
    },
  ];

  const result = prepareDlpRequest('tenant-test', messages, 'redact');

  try {
    assert.ok(result.flaggedCategories.includes('EMAIL_ADDRESS'));
    assert.equal(result.replacementsCount, 2);
    assert.notEqual(result.providerMessages[0].content, messages[0].content);
    assert.notEqual(result.providerMessages[1].content, messages[1].content);
  } finally {
    destroyVaultSession(result.vaultSession.sessionId);
  }
});


test('destroyVaultSession clears all sensitive mappings and categories', () => {
  const result = prepareDlpRequest('tenant-cleanup-test', [sensitiveMessage], 'redact');
  const session = result.vaultSession;

  assert.ok(session.forwardMap.size > 0);
  assert.ok(session.reverseMap.size > 0);
  assert.ok(session.detectedCategories.size > 0);

  destroyVaultSession(session.sessionId);

  assert.equal(session.forwardMap.size, 0);
  assert.equal(session.reverseMap.size, 0);
  assert.equal(session.detectedCategories.size, 0);

  assert.equal(
    rehydrateFromVault(result.providerMessages[0].content, session),
    result.providerMessages[0].content
  );
});

test('destroyVaultSession safely handles repeated destruction', () => {
  const result = prepareDlpRequest('tenant-cleanup-test', [sensitiveMessage], 'redact');
  const sessionId = result.vaultSession.sessionId;

  destroyVaultSession(sessionId);

  assert.doesNotThrow(() => destroyVaultSession(sessionId));
  assert.equal(result.vaultSession.forwardMap.size, 0);
  assert.equal(result.vaultSession.reverseMap.size, 0);
  assert.equal(result.vaultSession.detectedCategories.size, 0);
});