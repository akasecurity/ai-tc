import type { MaskedSecretFinding } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { renderResolvedSummary } from '../../src/remediation/redaction-summary.ts';
import { buildChecklistEntries } from '../../src/remediation/rotation-checklist.ts';

const RAW_VALUES = [
  ['sk', '_live_', 'exampleRawStripeOne'].join(''),
  ['sk', '_live_', 'exampleRawStripeTwo'].join(''),
  ['AKIA', 'EXAMPLERAWVALUE'].join(''),
] as const;

const findings: readonly MaskedSecretFinding[] = [
  {
    provider: 'stripe',
    maskedToken: 'sk_live_…one',
    where: { filePath: '/transcripts/one.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-03T00:00:00Z',
  },
  {
    provider: 'aws',
    maskedToken: 'AKIA…ALUE',
    where: { filePath: '/transcripts/one.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-01T00:00:00Z',
  },
  {
    provider: 'stripe',
    maskedToken: 'sk_live_…two',
    where: { filePath: '/transcripts/two.jsonl' },
    state: 'unknown',
    observedAt: '2026-07-02T00:00:00Z',
  },
];

const entries = buildChecklistEntries(findings);

const POINTERED_SENTENCE = /replaced with recoverable vault pointers/g;

describe('renderResolvedSummary', () => {
  it('renders the partial header, the Redacted-N-of-M line, and the pointer sentence together on a pointered partial strike', () => {
    // Two of three findings struck (both as recoverable pointers); the third
    // transcript still holds a live key.
    const [, , thirdFinding] = findings;
    const summary = renderResolvedSummary({
      findings,
      redactedKeys: 2,
      unredactedFindings: thirdFinding === undefined ? [] : [thirdFinding],
      pointeredKeys: 2,
      entries,
      location: 'repo root',
    });

    // The partial strike never earns the clean "resolved" framing — even when
    // every struck value is recoverable.
    expect(summary).toContain('Leaked secrets — partially redacted');
    expect(summary).not.toContain('Leaked secrets — resolved');
    expect(summary).toContain('Redacted 2 of 3 keys');
    expect(summary).toContain('1 key still needs attention in /transcripts/two.jsonl');
    expect(summary).toContain(
      '2 values were replaced with recoverable vault pointers — ' +
        'view them in the dashboard or with `aka vault show`.',
    );
    // The recoverability sentence rides the redaction line exactly once.
    expect(summary.match(POINTERED_SENTENCE)).toHaveLength(1);
    for (const rawValue of RAW_VALUES) {
      expect(summary).not.toContain(rawValue);
    }
  });

  it('keeps the resolved framing and appends the pointer sentence exactly once on a pointered complete strike', () => {
    const summary = renderResolvedSummary({
      findings,
      redactedKeys: 3,
      unredactedFindings: [],
      pointeredKeys: 3,
      entries,
      location: 'repo root',
    });

    expect(summary).toContain('Leaked secrets — resolved');
    expect(summary).not.toContain('partially redacted');
    expect(summary).toContain(
      '✓ Redacted 3 keys across 2 transcripts. ' +
        '3 values were replaced with recoverable vault pointers — ' +
        'view them in the dashboard or with `aka vault show`.',
    );
    expect(summary.match(POINTERED_SENTENCE)).toHaveLength(1);
  });

  it('renders byte-identical output for pointeredKeys: 0 and an omitted pointeredKeys — no pointer sentence', () => {
    const [, , thirdFinding] = findings;
    const unredactedFindings = thirdFinding === undefined ? [] : [thirdFinding];

    // Partial shape: an irreversible strike keeps its wording untouched.
    const zeroPartial = renderResolvedSummary({
      findings,
      redactedKeys: 2,
      unredactedFindings,
      pointeredKeys: 0,
      entries,
      location: 'repo root',
    });
    const omittedPartial = renderResolvedSummary({
      findings,
      redactedKeys: 2,
      unredactedFindings,
      entries,
      location: 'repo root',
    });
    expect(zeroPartial).toBe(omittedPartial);
    expect(zeroPartial).not.toContain('recoverable');

    // Complete shape: same byte-stability guarantee.
    const zeroResolved = renderResolvedSummary({
      findings,
      redactedKeys: 3,
      unredactedFindings: [],
      pointeredKeys: 0,
      entries,
      location: 'repo root',
    });
    const omittedResolved = renderResolvedSummary({
      findings,
      redactedKeys: 3,
      unredactedFindings: [],
      entries,
      location: 'repo root',
    });
    expect(zeroResolved).toBe(omittedResolved);
    expect(zeroResolved).not.toContain('recoverable');
  });
});
