import type { MatchResult } from '@akasecurity/detections';
import { describe, expect, it } from 'vitest';

import type { VaultCore } from '../src/vault-glue.ts';
import { createInjectedVaultGlue } from '../src/vault-glue.ts';

const SECRET = 'AKIAIOSFODNN7EXAMPLE';
// Assembled at runtime so the source holds no literal pointer token.
const POINTER = ['[[aka', 'secret', `AE.${'A'.repeat(26)}.${'A'.repeat(16)}]]`].join(':');

function finding(start: number, rawMatch = SECRET): MatchResult {
  return {
    ruleId: 'aws-access-key',
    category: 'secret',
    severity: 'critical',
    rawMatch,
    confidence: 0.9,
    span: { start, end: start + rawMatch.length },
  };
}

function mapVault(): VaultCore & { held: Map<string, string> } {
  const held = new Map<string, string>();
  return {
    held,
    tokenize: (raw) => {
      held.set(POINTER, raw);
      return Promise.resolve(POINTER);
    },
    detokenize: (token) => Promise.resolve(held.get(token) ?? Symbol('missing')),
    describePointer: () => Promise.resolve(null),
    resolvePointerIdentity: () => Promise.resolve(null),
  };
}

describe('createInjectedVaultGlue', () => {
  it('tokenizes a reversible finding through the injected core and destroys the rest', async () => {
    const vault = mapVault();
    const glue = createInjectedVaultGlue(vault);
    const kept = finding(4);
    const text = `key=${SECRET} again=${SECRET}`;
    const destroyed = finding(text.lastIndexOf(SECRET));

    const result = await glue.tokenizeText(text, {
      findings: [kept, destroyed],
      reversible: new Set([kept]),
    });

    expect(result.text).toBe(`key=${POINTER} again=[REDACTED:SECRET]`);
    expect(result.pointers).toEqual([POINTER]);
    expect(result.redacted).toEqual([{ category: 'secret' }]);
    expect(vault.held.get(POINTER)).toBe(SECRET);
  });

  it('resolves pointers back through the same core', async () => {
    const vault = mapVault();
    const glue = createInjectedVaultGlue(vault);
    const { text } = await glue.tokenizeText(`key=${SECRET}`, { findings: [finding(4)] });

    const back = await glue.detokenizeText(text, { target: 'human', reason: 'explicit-reveal' });

    expect(back).toEqual({ text: `key=${SECRET}`, revealed: 1 });
  });
});
