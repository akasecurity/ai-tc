import { describe, expect, it } from 'vitest';

import {
  buildReviewInfo,
  decisionToStatus,
  deriveReviewReasons,
  distinctDataClasses,
  distinctTransports,
  effectiveStatus,
  isCustomDecision,
  REVIEW_SEVERITY_RANK,
  reviewSeverityRank,
  topDataClass,
  trustDefaultStatus,
} from '../../src/zod/shares-access.ts';

// ─── Effective status / isCustom ──────────────────────────────────────────────

describe('trustDefaultStatus', () => {
  it('allows recognized and internal, sends everything else to review', () => {
    expect(trustDefaultStatus('recognized')).toBe('allowed');
    expect(trustDefaultStatus('internal')).toBe('allowed');
    expect(trustDefaultStatus('unverified')).toBe('review');
    expect(trustDefaultStatus('ip')).toBe('review');
  });
});

describe('decisionToStatus', () => {
  it('maps block to blocked and allow to allowed', () => {
    expect(decisionToStatus('block')).toBe('blocked');
    expect(decisionToStatus('allow')).toBe('allowed');
  });
});

describe('effectiveStatus', () => {
  it('falls back to the trust default when no override exists', () => {
    expect(effectiveStatus('unverified', null)).toBe('review');
    expect(effectiveStatus('recognized', null)).toBe('allowed');
  });

  it('lets an override force the status either way', () => {
    expect(effectiveStatus('unverified', 'allow')).toBe('allowed');
    expect(effectiveStatus('recognized', 'block')).toBe('blocked');
  });
});

describe('isCustomDecision', () => {
  it('is false with no override', () => {
    expect(isCustomDecision('unverified', null)).toBe(false);
  });

  it('is false for an override that matches the trust default', () => {
    expect(isCustomDecision('recognized', 'allow')).toBe(false);
  });

  it('is true only when the override changes the effective status', () => {
    expect(isCustomDecision('unverified', 'allow')).toBe(true);
    expect(isCustomDecision('recognized', 'block')).toBe(true);
  });
});

// ─── Review posture ───────────────────────────────────────────────────────────

describe('deriveReviewReasons', () => {
  it('flags a raw IP destination', () => {
    expect(deriveReviewReasons('ip', ['https'])).toEqual(['raw_ip']);
  });

  it('flags an unverified domain — the posture an external destination carries', () => {
    expect(deriveReviewReasons('unverified', ['https'])).toEqual(['unverified_domain']);
  });

  it('flags http as a plaintext transport', () => {
    expect(deriveReviewReasons('recognized', ['http'])).toEqual(['plaintext_transport']);
  });

  it('flags ws as a plaintext transport', () => {
    expect(deriveReviewReasons('recognized', ['ws'])).toEqual(['plaintext_transport']);
  });

  it('does not flag wss — the encrypted websocket transport', () => {
    expect(deriveReviewReasons('recognized', ['wss'])).toEqual([]);
  });

  it('flags the set when any single endpoint is plaintext', () => {
    expect(deriveReviewReasons('recognized', ['https', 'ws'])).toEqual(['plaintext_transport']);
  });

  it('reports every applicable reason, most-severe first', () => {
    expect(deriveReviewReasons('ip', ['wss'])).toEqual(['raw_ip']);
    expect(deriveReviewReasons('unverified', ['http'])).toEqual([
      'unverified_domain',
      'plaintext_transport',
    ]);
  });

  it('returns no reasons for a recognized destination over secure transports', () => {
    expect(deriveReviewReasons('recognized', ['https', 'grpc', 'wss'])).toEqual([]);
  });
});

describe('buildReviewInfo', () => {
  it('sets needsReview from the presence of any reason', () => {
    expect(buildReviewInfo('recognized', ['wss'])).toEqual({ needsReview: false, reasons: [] });
    expect(buildReviewInfo('recognized', ['ws'])).toEqual({
      needsReview: true,
      reasons: ['plaintext_transport'],
    });
  });
});

// ─── Rollups ──────────────────────────────────────────────────────────────────

describe('distinctTransports', () => {
  it('dedupes while preserving first-seen order', () => {
    expect(distinctTransports(['https', 'ws', 'https', 'wss'])).toEqual(['https', 'ws', 'wss']);
  });
});

describe('distinctDataClasses', () => {
  it('dedupes and re-sorts most-sensitive first', () => {
    expect(distinctDataClasses(['metrics', 'secrets', 'metrics', 'pii'])).toEqual([
      'secrets',
      'pii',
      'metrics',
    ]);
  });

  it('returns an empty array for no classes', () => {
    expect(distinctDataClasses([])).toEqual([]);
  });
});

describe('topDataClass', () => {
  it('returns the most-sensitive class present', () => {
    expect(topDataClass(['logs', 'pii', 'metrics'])).toBe('pii');
  });

  it("falls back to 'none' when the destination has no endpoints", () => {
    expect(topDataClass([])).toBe('none');
  });
});

// ─── Severity ordering ────────────────────────────────────────────────────────

describe('reviewSeverityRank', () => {
  it('ranks ip above unverified above plaintext', () => {
    expect(REVIEW_SEVERITY_RANK.raw_ip).toBeLessThan(REVIEW_SEVERITY_RANK.unverified_domain);
    expect(REVIEW_SEVERITY_RANK.unverified_domain).toBeLessThan(
      REVIEW_SEVERITY_RANK.plaintext_transport,
    );
  });

  it('takes the most severe rank among a destination reasons', () => {
    expect(reviewSeverityRank(['plaintext_transport', 'raw_ip'])).toBe(REVIEW_SEVERITY_RANK.raw_ip);
  });

  it('sorts a reasonless destination last', () => {
    expect(reviewSeverityRank([])).toBe(Number.POSITIVE_INFINITY);
  });
});
