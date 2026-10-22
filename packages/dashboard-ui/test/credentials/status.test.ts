import { describe, expect, it } from 'vitest';

import { credentialStatus } from '../../src/credentials/status.ts';

describe('credentialStatus', () => {
  it('is exposed exactly when the credential was seen in a live session', () => {
    expect(credentialStatus({ exposedAt: '2026-10-21T09:00:00.000Z' })).toBe('exposed');
    expect(credentialStatus({ exposedAt: null })).toBe('ok');
  });
});
