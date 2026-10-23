import { describe, expect, it } from 'vitest';

import { CredentialStatus } from '../../src/index.ts';

describe('CredentialStatus', () => {
  it('names only statuses that need attention, so a credential with none is the healthy case', () => {
    expect(CredentialStatus.options).not.toContain('ok');
    expect(CredentialStatus.options).toContain('rotation_overdue');
  });
});
