import { describe, expect, it } from 'vitest';

import { SessionHoldResponse } from '../../src/zod/control-plane.ts';
import {
  EventMetadata,
  REVIEW_VALUE_MAX_CHARS,
  REVIEW_VALUES_MAX,
  ReviewValue,
} from '../../src/zod/event.ts';
import {
  CAPTURE_REPOS_MAX,
  CaptureSettings,
  POLICY_BUNDLE_SHAPE_ID,
  PolicyBundle,
  TOOL_OUTPUT_FORWARD_MAX_CHARS,
} from '../../src/zod/policy.ts';

const bundle = {
  version: 'v1',
  policies: [],
  customKeywords: [],
  fetchedAt: '2026-10-28T10:00:00.000Z',
};

describe('CaptureSettings', () => {
  it('is optional on the bundle, so a bundle without it parses with nothing set', () => {
    const parsed = PolicyBundle.parse(bundle);
    expect(parsed.capture).toBeUndefined();
  });

  it('carries each member through the bundle parse', () => {
    const capture = {
      toolOutput: { maxChars: 16_384 },
      reviewValueRepos: ['github.com/acme/app'],
      sessionHold: true,
    };
    expect(PolicyBundle.parse({ ...bundle, capture }).capture).toEqual(capture);
  });

  it('bounds the tool output cap', () => {
    expect(CaptureSettings.safeParse({ toolOutput: { maxChars: 0 } }).success).toBe(false);
    expect(
      CaptureSettings.safeParse({ toolOutput: { maxChars: TOOL_OUTPUT_FORWARD_MAX_CHARS + 1 } })
        .success,
    ).toBe(false);
    expect(
      CaptureSettings.safeParse({ toolOutput: { maxChars: TOOL_OUTPUT_FORWARD_MAX_CHARS } })
        .success,
    ).toBe(true);
  });

  it('carries a repository list on the tool output setting', () => {
    const toolOutput = { maxChars: 100, repos: ['github.com/acme/app'] };
    expect(CaptureSettings.parse({ toolOutput }).toolOutput).toEqual(toolOutput);
    expect(CaptureSettings.safeParse({ toolOutput: { maxChars: 100, repos: [''] } }).success).toBe(
      false,
    );
  });

  it('bounds the repository list', () => {
    const repos = Array.from(
      { length: CAPTURE_REPOS_MAX + 1 },
      (_, i) => `h.example/o/r${String(i)}`,
    );
    expect(CaptureSettings.safeParse({ reviewValueRepos: repos }).success).toBe(false);
    expect(CaptureSettings.safeParse({ reviewValueRepos: [''] }).success).toBe(false);
  });

  it('is named in the bundle shape stamp, nested keys included', () => {
    const named = POLICY_BUNDLE_SHAPE_ID.split(',');
    expect(named).toContain('capture');
    for (const key of Object.keys(CaptureSettings.shape)) expect(named).toContain(`capture.${key}`);
  });
});

describe('EventMetadata review values and truncation', () => {
  it('accepts neither field by default and both when set', () => {
    expect(EventMetadata.parse({})).toEqual({});
    const metadata = {
      contentTruncatedFrom: 90_000,
      reviewValues: [{ ruleId: 'core-pii/email', value: 'a@b.example' }],
    };
    expect(EventMetadata.parse(metadata)).toEqual(metadata);
  });

  it('bounds the review values', () => {
    const many = Array.from({ length: REVIEW_VALUES_MAX + 1 }, () => ({ ruleId: 'r', value: 'v' }));
    expect(EventMetadata.safeParse({ reviewValues: many }).success).toBe(false);
    expect(ReviewValue.safeParse({ ruleId: 'r', value: '' }).success).toBe(false);
    expect(
      ReviewValue.safeParse({ ruleId: 'r', value: 'x'.repeat(REVIEW_VALUE_MAX_CHARS + 1) }).success,
    ).toBe(false);
  });

  it('refuses a negative truncation length', () => {
    expect(EventMetadata.safeParse({ contentTruncatedFrom: -1 }).success).toBe(false);
  });
});

describe('SessionHoldResponse', () => {
  it('reads a held and a not-held answer', () => {
    expect(SessionHoldResponse.parse({ held: false })).toEqual({ held: false });
    expect(
      SessionHoldResponse.parse({ held: true, reason: 'Paused by your organization.' }),
    ).toEqual({ held: true, reason: 'Paused by your organization.' });
  });

  it('refuses a reason carrying control characters', () => {
    expect(SessionHoldResponse.safeParse({ held: true, reason: 'a\u001b[2Jb' }).success).toBe(
      false,
    );
  });

  it('refuses a body without `held`', () => {
    expect(SessionHoldResponse.safeParse({ reason: 'x' }).success).toBe(false);
  });
});
