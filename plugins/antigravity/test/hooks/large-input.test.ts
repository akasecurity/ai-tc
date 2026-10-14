import {
  LARGE_INPUT_SCAN_BUDGET_MS,
  LARGE_INPUT_START_BUDGET_MS,
  LARGE_INPUT_THRESHOLD_CHARS,
} from '@akasecurity/plugin-sdk';
import { describe, expect, it } from 'vitest';

import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from '../../src/hooks/large-input.ts';
import { WATCHDOG_MS } from '../../src/hooks/shared.ts';

describe('largeInputBound', () => {
  it('passes the SDK defaults through', () => {
    expect(largeInputBound(HOOK_SCAN_DEADLINE_MS)).toMatchObject({
      thresholdChars: LARGE_INPUT_THRESHOLD_CHARS,
      budgetMs: LARGE_INPUT_SCAN_BUDGET_MS,
      startBudgetMs: LARGE_INPUT_START_BUDGET_MS,
    });
  });

  it('reads what is left of one fixed deadline on every call', () => {
    let clock = 1_000;
    const bound = largeInputBound(5_500, () => clock);
    expect(bound.remainingMs?.()).toBe(4_500);
    // A second large field gets what the first one left, not a fresh budget.
    clock = 4_500;
    expect(bound.remainingMs?.()).toBe(1_000);
    clock = 6_000;
    expect(bound.remainingMs?.()).toBe(-500);
  });

  // On this host the refusal is a payload the hook has to PRINT, and the
  // watchdog prints an allow over anything still undecided. So the deadline
  // must end every bounded scan well before the watchdog fires, with time left
  // for closing the store, deciding and emitting — and one full scan has to fit
  // under it.
  it('ends inside the fail-open watchdog and still fits one bounded scan', () => {
    expect(HOOK_SCAN_DEADLINE_MS).toBeLessThanOrEqual(WATCHDOG_MS - 2_000);
    expect(HOOK_SCAN_DEADLINE_MS).toBeGreaterThan(
      LARGE_INPUT_START_BUDGET_MS + LARGE_INPUT_SCAN_BUDGET_MS,
    );
  });
});
