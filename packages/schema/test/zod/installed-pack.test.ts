import { describe, expect, it } from 'vitest';

import { InstalledPack, InstallPackRequest } from '../../src/zod/installed-pack.ts';

describe('installed-pack contracts', () => {
  it('InstallPackRequest requires a registry coordinate', () => {
    expect(
      InstallPackRequest.safeParse({ namespace: 'aka-labs', packId: 'secrets', version: '1.0.0' })
        .success,
    ).toBe(true);
    // bad namespace / loose version are rejected by the shared registry primitives
    expect(
      InstallPackRequest.safeParse({ namespace: 'Aka Labs', packId: 'secrets', version: '1.0.0' })
        .success,
    ).toBe(false);
    expect(
      InstallPackRequest.safeParse({ namespace: 'aka-labs', packId: 'secrets', version: 'latest' })
        .success,
    ).toBe(false);
  });

  it('InstalledPack carries metadata (no rules) and defaults enabled to true', () => {
    const parsed = InstalledPack.parse({
      id: '00000000-0000-4000-8000-000000000001',
      tenantId: '00000000-0000-4000-8000-000000000002',
      namespace: 'aka-labs',
      packId: 'core-pii',
      version: '1.0.0',
      name: 'Core PII',
    });
    expect(parsed.enabled).toBe(true);
    expect(parsed).not.toHaveProperty('rules');
  });
});
