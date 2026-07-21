import type { SuppressionEntry } from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  renderPosturePlan,
  renderShowcase,
  renderSuppressionGate,
} from '../../src/triage/gate-display.ts';
import type { JoinEntry } from '../../src/triage/join-file.ts';
import type { ShowcaseCategory } from '../../src/triage/writeback.ts';

const FP_A = 'ab'.repeat(32);
const FP_B = 'cd'.repeat(32);

const entry = (over: Partial<SuppressionEntry> = {}): SuppressionEntry => ({
  ruleId: 'core-secret/aws',
  category: 'secret',
  valueFingerprint: FP_A,
  keyVersion: 1,
  maskedValue: 'A***Z',
  justification: 'test placeholder in an example fixture',
  ...over,
});

const join = (over: Partial<JoinEntry> = {}): JoinEntry => ({
  id: '0',
  ruleId: 'core-secret/aws',
  category: 'secret',
  valueFingerprint: FP_A,
  keyVersion: 1,
  maskedMatch: 'A***Z',
  maskedContext: 'export KEY=A***Z # prod',
  ...over,
});

describe('renderSuppressionGate', () => {
  it('renders masked value, rule, and masked context for each FP', () => {
    const out = renderSuppressionGate([entry()], [join()]);
    expect(out).toContain('A***Z');
    expect(out).toContain('core-secret/aws');
    expect(out).toContain('export KEY=A***Z # prod');
  });

  it('pulls the correct maskedContext per entry by joining on fingerprint', () => {
    const out = renderSuppressionGate(
      [entry({ valueFingerprint: FP_A }), entry({ valueFingerprint: FP_B, maskedValue: 'G***d' })],
      [
        join({ id: '0', valueFingerprint: FP_A, maskedContext: 'CTX_AWS export A***Z' }),
        join({
          id: '1',
          valueFingerprint: FP_B,
          maskedMatch: 'G***d',
          maskedContext: 'CTX_GH token G***d',
        }),
      ],
    );
    expect(out).toContain('CTX_AWS export A***Z');
    expect(out).toContain('CTX_GH token G***d');
    // ensure the two contexts are not cross-wired to the wrong value
    const awsIdx = out.indexOf('A***Z');
    const ctxAwsIdx = out.indexOf('CTX_AWS');
    const ctxGhIdx = out.indexOf('CTX_GH');
    expect(awsIdx).toBeGreaterThanOrEqual(0);
    expect(ctxAwsIdx).toBeLessThan(ctxGhIdx);
  });

  it('falls back to ruleId + maskedValue when the entry has no fingerprint match', () => {
    // entry fingerprint absent from join; match by ruleId+maskedValue instead
    const out = renderSuppressionGate(
      [entry({ valueFingerprint: 'ff'.repeat(32) })],
      [join({ valueFingerprint: 'ee'.repeat(32) })],
    );
    expect(out).toContain('export KEY=A***Z # prod');
  });

  it('degrades gracefully when no join entry matches (no crash, notes missing context)', () => {
    const out = renderSuppressionGate([entry({ maskedValue: 'Q***q' })], []);
    expect(out).toContain('Q***q');
    expect(out).toContain('core-secret/aws');
    expect(out.toLowerCase()).toMatch(/context (unavailable|not available|missing)/);
  });

  it('RAW SAFETY: output contains no raw secret substring from a masked-only fixture', () => {
    // The real raw value never enters this function; assert it never appears in output.
    const RAW = 'AKIAIOSFODNN7EXAMPLE';
    const out = renderSuppressionGate([entry()], [join()]);
    expect(out).not.toContain(RAW);
    expect(out).not.toContain('AKIAIOSFODNN7');
  });

  it('returns a stable message for an empty suppression list', () => {
    const out = renderSuppressionGate([], []);
    expect(out.length).toBeGreaterThan(0);
    expect(out.toLowerCase()).toMatch(/no|none|nothing/);
  });
});

describe('renderShowcase', () => {
  const show = (over: Partial<ShowcaseCategory> = {}): ShowcaseCategory => ({
    category: 'secret',
    action: 'warn',
    genuineCount: 0,
    fpCount: 1,
    reasoning: 'canonical fake AWS example key',
    ...over,
  });

  it('renders per-category counts (genuine/fp/total), action, and reasoning', () => {
    const out = renderShowcase([show({ genuineCount: 3, fpCount: 158, action: 'warn' })]);
    expect(out).toContain('secret');
    expect(out).toContain('3 genuine');
    expect(out).toContain('158 false-positive');
    expect(out).toContain('161 hits'); // total = genuine + fp
    expect(out).toContain('warn');
    expect(out).toContain('canonical fake AWS example key');
  });

  it('still shows a genuine-hit category that produced NO false positives', () => {
    const out = renderShowcase([
      show({
        category: 'pii',
        action: 'block',
        genuineCount: 2,
        fpCount: 0,
        reasoning: 'real PII',
      }),
    ]);
    expect(out).toContain('pii');
    expect(out).toContain('2 genuine');
    expect(out).toContain('0 false-positive');
    expect(out).toContain('block');
    expect(out).toContain('real PII');
  });

  it('renders every category in the showcase', () => {
    const out = renderShowcase([
      show({ category: 'secret' }),
      show({ category: 'pii', reasoning: 'emails' }),
      show({ category: 'financial', reasoning: 'card-shaped test numbers' }),
    ]);
    expect(out).toContain('secret');
    expect(out).toContain('pii');
    expect(out).toContain('financial');
    expect(out).toContain('card-shaped test numbers');
  });

  it('returns a stable message for an empty showcase', () => {
    const out = renderShowcase([]);
    expect(out.length).toBeGreaterThan(0);
    expect(out.toLowerCase()).toMatch(/no/);
  });
});

describe('renderPosturePlan', () => {
  it('lists every category in the plan with its target action', () => {
    const out = renderPosturePlan({ secret: 'warn', pii: 'monitor', financial: 'block' }, {});
    expect(out).toContain('secret: warn');
    expect(out).toContain('pii: monitor');
    expect(out).toContain('financial: block');
  });

  it('marks a category with no existing row as new', () => {
    const out = renderPosturePlan({ secret: 'warn' }, {});
    expect(out).toContain('secret: warn (new)');
  });

  it('flags an enforcement downgrade (stronger stored -> weaker planned)', () => {
    // stored block (rank 4) -> planned warn (rank 2): a downgrade the human must see.
    const out = renderPosturePlan({ secret: 'warn' }, { secret: 'block' });
    expect(out).toContain('LOWERED from block');
    expect(out).toContain('Heads up');
    expect(out).toContain('secret');
  });

  it('maps stored log to the monitor palette when reporting a downgrade base', () => {
    // stored redact (rank 3) -> planned monitor (rank 1): downgrade, labelled monitor.
    const out = renderPosturePlan({ pii: 'monitor' }, { pii: 'redact' });
    expect(out).toContain('LOWERED from redact');
  });

  it('does NOT flag an upgrade or an unchanged posture', () => {
    // stored log(=monitor) -> planned warn is an UPGRADE; stored warn -> warn unchanged.
    const out = renderPosturePlan({ secret: 'warn', pii: 'warn' }, { secret: 'log', pii: 'warn' });
    expect(out).not.toContain('LOWERED');
    expect(out).not.toContain('Heads up');
    expect(out).toContain('secret: warn (was monitor)');
    expect(out).toContain('pii: warn (unchanged)');
  });

  it('summarizes multiple downgrades in the footer', () => {
    const out = renderPosturePlan(
      { secret: 'warn', financial: 'monitor' },
      { secret: 'block', financial: 'redact' },
    );
    expect(out).toMatch(/2 detection levels/);
    expect(out).toContain('secret');
    expect(out).toContain('financial');
  });

  it('returns a stable message when the plan carries no posture', () => {
    const out = renderPosturePlan({}, {});
    expect(out.toLowerCase()).toMatch(/no per-category/);
  });
});
