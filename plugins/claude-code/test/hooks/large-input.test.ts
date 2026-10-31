import {
  LARGE_INPUT_SCAN_BUDGET_MS,
  LARGE_INPUT_START_BUDGET_MS,
  LARGE_INPUT_THRESHOLD_CHARS,
} from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import {
  HOOK_SCAN_DEADLINE_MS,
  callScanBudgetSpent,
  largeInputBound,
} from '../../src/hooks/large-input.ts';
import { RESPONSE_SCAN_DEADLINE_MS } from '../../src/hooks/scan-response.ts';

describe('largeInputBound', () => {
  it('passes the SDK defaults through', () => {
    const bound = largeInputBound(HOOK_SCAN_DEADLINE_MS);
    expect(bound).toMatchObject({
      thresholdChars: LARGE_INPUT_THRESHOLD_CHARS,
      budgetMs: LARGE_INPUT_SCAN_BUDGET_MS,
      startBudgetMs: LARGE_INPUT_START_BUDGET_MS,
    });
  });

  it('reads what is left of one fixed deadline on every call', () => {
    let clock = 1_000;
    const bound = largeInputBound(6_000, () => clock);
    expect(bound.remainingMs?.()).toBe(5_000);
    // A second large field gets what the first one left, not a fresh budget.
    clock = 4_500;
    expect(bound.remainingMs?.()).toBe(1_500);
    clock = 7_000;
    expect(bound.remainingMs?.()).toBe(-1_000);
  });

  // The deadline has to leave room inside the host's 10 s for the store, the
  // decision and the reply, and one full scan has to fit under it.
  it.each([
    ['UserPromptSubmit/PreToolUse', HOOK_SCAN_DEADLINE_MS],
    ['PostToolUse', RESPONSE_SCAN_DEADLINE_MS],
  ])('%s deadline fits one bounded scan inside the host timeout', (_label, deadline) => {
    expect(deadline).toBeLessThan(10_000);
    expect(deadline).toBeGreaterThan(LARGE_INPUT_START_BUDGET_MS + LARGE_INPUT_SCAN_BUDGET_MS);
  });
});

describe('callScanBudgetSpent', () => {
  it('counts from the call start, so a long-lived server still scans', () => {
    const serverUptime = 10 * 60_000;
    expect(callScanBudgetSpent(serverUptime, () => serverUptime + 5)).toBe(false);
    expect(callScanBudgetSpent(serverUptime, () => serverUptime + HOOK_SCAN_DEADLINE_MS + 1)).toBe(
      true,
    );
  });
});
