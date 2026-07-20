import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import type { BuiltinPolicyId, DetectionCategory } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { parsePosture } from '../src/onboard-posture.ts';

// The wizard composes the adjusted --posture map in the setup.md conversational
// layer: the recommended base with the user's changed packs overlaid. onboard.ts
// only ever parsePostures the already-merged JSON, so this overlay is modeled
// here as a fixture rather than shipped TypeScript.
function adjust(
  recommended: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
  overrides: Partial<Record<DetectionCategory, BuiltinPolicyId>>,
): Partial<Record<DetectionCategory, BuiltinPolicyId>> {
  return { ...recommended, ...overrides };
}

describe('parsePosture', () => {
  it('accepts a valid per-category palette map', () => {
    const p = parsePosture('{"secret":"warn","code_context":"monitor","pii":"block"}');
    expect(p).toEqual({ secret: 'warn', code_context: 'monitor', pii: 'block' });
  });
  it('rejects an unknown category', () => {
    expect(() => parsePosture('{"not_a_category":"warn"}')).toThrow();
  });
  it('rejects a non-palette action (e.g. log/allow)', () => {
    expect(() => parsePosture('{"secret":"log"}')).toThrow();
    expect(() => parsePosture('{"secret":"allow"}')).toThrow();
  });
  it('rejects malformed JSON', () => {
    expect(() => parsePosture('{secret:warn}')).toThrow();
  });
  it('rejects an empty object / array (nothing to write)', () => {
    expect(() => parsePosture('{}')).toThrow();
    expect(() => parsePosture('[]')).toThrow();
  });
});

describe('adjust round-trip', () => {
  it('the adjusted map (2 packs changed, 6 kept) round-trips through parsePosture to what onboard.ts writes', () => {
    const recommended = severityFloorPosture();
    const merged = adjust(recommended, { secret: 'redact', config: 'warn' });

    // The 2 overridden packs win; the other 6 stay at the recommended base.
    expect(merged.secret).toBe('redact');
    expect(merged.config).toBe('warn');
    for (const cat of ['pii', 'financial', 'phi', 'code_flaw', 'custom', 'code_context'] as const) {
      expect(merged[cat]).toBe(recommended[cat]);
    }
    // All 8 packs are present, and parsePosture — the seam onboard.ts's --posture
    // writer feeds — reconstructs exactly the adjusted map onboard.ts would write.
    expect(Object.keys(merged).sort()).toEqual(Object.keys(recommended).sort());
    expect(parsePosture(JSON.stringify(merged))).toEqual(merged);
  });
});
