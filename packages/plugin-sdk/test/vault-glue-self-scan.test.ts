import { beforeEach, describe, expect, it, vi } from 'vitest';

import type * as RulePacks from '../src/rule-packs.ts';
import type { VaultGlue } from '../src/vault-glue.ts';

const registerBundledPacks = vi.fn<() => void>();

vi.mock('../src/rule-packs.ts', async (importOriginal) => {
  const actual = await importOriginal<typeof RulePacks>();
  registerBundledPacks.mockImplementation(actual.registerBundledPacks);
  return { ...actual, registerBundledPacks };
});

const SECRET = 'AKIAIOSFODNN7EXAMPLE';

async function freshGlue(): Promise<VaultGlue> {
  vi.resetModules();
  const { createInjectedVaultGlue } = await import('../src/vault-glue.ts');
  return createInjectedVaultGlue({
    tokenize: () => Promise.resolve(Symbol('refused')),
    detokenize: () => Promise.resolve(Symbol('refused')),
    describePointer: () => Promise.resolve(null),
    resolvePointerIdentity: () => Promise.resolve(null),
  });
}

describe('the self-scan', () => {
  beforeEach(() => {
    registerBundledPacks.mockClear();
  });

  it('registers the bundled packs once across calls', async () => {
    const glue = await freshGlue();

    const first = await glue.tokenizeText(`key=${SECRET}`);
    const second = await glue.tokenizeText(`again=${SECRET}`);

    expect(first.text).toBe('key=[REDACTED:SECRET]');
    expect(second.text).toBe('again=[REDACTED:SECRET]');
    expect(registerBundledPacks).toHaveBeenCalledTimes(1);
  });

  it('keeps blanking every call after a failed registration, without retrying it', async () => {
    const glue = await freshGlue();
    registerBundledPacks.mockImplementationOnce(() => {
      throw new Error('bundled packs failed to parse');
    });

    const first = await glue.tokenizeText(`key=${SECRET}`);
    const second = await glue.tokenizeText(`again=${SECRET}`);

    expect(first).toEqual({ text: '[REDACTED]', pointers: [], degraded: [], redacted: [] });
    expect(second).toEqual({ text: '[REDACTED]', pointers: [], degraded: [], redacted: [] });
    expect(registerBundledPacks).toHaveBeenCalledTimes(1);
  });
});
