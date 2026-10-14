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
    const bound = largeInputBound(15_000, () => clock);
    expect(bound.remainingMs?.()).toBe(14_000);
    // A second large field gets what the first one left, not a fresh budget.
    clock = 13_500;
    expect(bound.remainingMs?.()).toBe(1_500);
    clock = 16_000;
    expect(bound.remainingMs?.()).toBe(-1_000);
  });

  // The watchdog answers an undecided body with silence, which both dialects
  // read as no opinion — so a refusal still being decided when it fires is a
  // call let through. The deadline must end every bounded scan well before
  // that, with time left for closing the store, deciding and emitting, and a
  // full scan of each field a call can carry has to fit under it.
  it('ends inside the fail-open watchdog and fits a bounded scan per field', () => {
    expect(HOOK_SCAN_DEADLINE_MS).toBeLessThanOrEqual(WATCHDOG_MS - 5_000);
    expect(HOOK_SCAN_DEADLINE_MS).toBeGreaterThan(
      2 * (LARGE_INPUT_START_BUDGET_MS + LARGE_INPUT_SCAN_BUDGET_MS),
    );
  });
});
