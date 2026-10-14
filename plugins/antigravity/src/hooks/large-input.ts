// The large-input bound PreToolUse passes to its runtime. A field at or above
// the threshold is scanned in a worker under a hard deadline, and one whose
// scan does not finish is REFUSED (`CaptureResult.scanIncomplete`) — the one
// place this hook denies because it could not decide. Without it a large
// enough field keeps the in-process scan busy past the watchdog, and what the
// call gets then is a race: the watchdog's allow for a field nothing finished
// scanning, or the host's kill, which this host reads as a deny with no reason
// attached. The refusal is a decision instead, and it says why.
//
// Pure (no I/O) so it unit-tests without a hook process: hook entry files run
// main() on import and must NEVER be imported by tests.
import type { LargeInputScanOptions } from '@akasecurity/plugin-sdk';
import {
  LARGE_INPUT_SCAN_BUDGET_MS,
  LARGE_INPUT_START_BUDGET_MS,
  LARGE_INPUT_THRESHOLD_CHARS,
} from '@akasecurity/plugin-sdk';

// When PreToolUse stops spending time on bounded scans, in milliseconds since
// the hook process started (performance.now()'s origin). Every bounded scan in
// the process draws on it, so several large fields cannot add up past it.
//
// It sits INSIDE `runHookFailOpen`'s 8 s watchdog rather than the host's 10 s,
// because the watchdog is armed after the process starts and resolves the race
// with an allow: a refusal still being decided when it fires is printed as
// `{"decision":"allow"}`. The 2.5 s between this and the watchdog cover module
// load, closing the store, the decision and the emit.
export const HOOK_SCAN_DEADLINE_MS = 5_500;

/**
 * The runtime's `largeInput` option for a hook whose bounded scans must all be
 * over by `deadlineAt` (on `now`'s clock). The remaining time is read when each
 * bounded scan starts, so it is fixed by the deadline rather than by how many
 * fields came before.
 */
export function largeInputBound(
  deadlineAt: number,
  now: () => number = () => performance.now(),
): LargeInputScanOptions {
  return {
    thresholdChars: LARGE_INPUT_THRESHOLD_CHARS,
    budgetMs: LARGE_INPUT_SCAN_BUDGET_MS,
    startBudgetMs: LARGE_INPUT_START_BUDGET_MS,
    remainingMs: () => deadlineAt - now(),
  };
}
