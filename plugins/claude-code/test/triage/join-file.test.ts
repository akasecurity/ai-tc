import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { buildJoinEntries } from '../../src/triage/join-file.ts';

const hit = (over: Partial<TriageHit>): TriageHit => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'critical',
  maskedMatch: 'A***Z',
  rawMatch: 'AKIAIOSFODNN7EXAMPLE',
  context: 'export KEY=AKIAIOSFODNN7EXAMPLE # prod',
  confidence: 0.9,
  id: '0',
  valueFingerprint: 'ab'.repeat(32),
  keyVersion: 1,
  ...over,
});

describe('buildJoinEntries', () => {
  it('drops raw and masks context (no raw substring in any field)', () => {
    const e = buildJoinEntries([hit({})])[0];
    if (!e) throw new Error('expected an entry');
    const blob = JSON.stringify(e);
    expect(blob).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(e.id).toBe('0');
    expect(e.valueFingerprint).toBe('ab'.repeat(32));
    expect('rawMatch' in e).toBe(false);
    expect('context' in e).toBe(false);
  });
  it('masks a SECOND secret that appears in the same context window', () => {
    const a = 'AKIAIOSFODNN7EXAMPLE';
    const b = 'ghp_0123456789abcdefABCDEF0123456789abcd';
    const shared = `A=${a} B=${b}`;
    const es = buildJoinEntries([
      hit({ id: '0', rawMatch: a, context: shared }),
      hit({ id: '1', rawMatch: b, context: shared, ruleId: 'core-secret/gh' }),
    ]);
    for (const e of es) {
      expect(e.maskedContext).not.toContain(a);
      expect(e.maskedContext).not.toContain(b);
    }
  });
  it('masks EVERY occurrence when the same value appears twice in one window (no abort)', () => {
    const a = 'AKIAIOSFODNN7EXAMPLE';
    // The value appears twice in the context. indexOf-only masking would leave the
    // second copy raw and trip the assertRawFree backstop, aborting the preview.
    const doubled = `KEY=${a} and again KEY2=${a} end`;
    const es = buildJoinEntries([hit({ id: '0', rawMatch: a, context: doubled })]);
    const e = es[0];
    if (!e) throw new Error('expected an entry');
    // masked (not aborted) and raw-free — no occurrence survives
    expect(e.maskedContext).not.toContain(a);
    expect(e.maskedContext.includes(a)).toBe(false);
  });

  it('carries no valueFingerprint through when the hit lacked one', () => {
    const e = buildJoinEntries([hit({ valueFingerprint: undefined, keyVersion: undefined })])[0];
    if (!e) throw new Error('expected an entry');
    expect(e.valueFingerprint).toBeUndefined();
  });
});
