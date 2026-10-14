// The large-input bound every scanning hook passes to its runtime. A field at or
// above the threshold is scanned in a worker under a hard deadline, and one
// whose scan does not finish is REFUSED (`CaptureResult.scanIncomplete`) — the
// one place a hook fails closed. Without it a large enough field keeps the
// in-process scan busy past the host's 10 s timeout, and a hook the host kills
// lets the whole call through unscanned.
//
// Pure (no I/O) so it unit-tests without a hook process: hook entry files run
// main() on import and must NEVER be imported by tests.
import type { LargeInputScanOptions } from '@akasecurity/plugin-sdk';
import {
  LARGE_INPUT_SCAN_BUDGET_MS,
  LARGE_INPUT_START_BUDGET_MS,
  LARGE_INPUT_THRESHOLD_CHARS,
} from '@akasecurity/plugin-sdk';

// When UserPromptSubmit and PreToolUse stop spending time on bounded scans, in
// milliseconds since the hook process started (performance.now()'s origin) —
// the same clock PostToolUse's RESPONSE_SCAN_DEADLINE_MS is read on. Every
// bounded scan in the process draws on it, so several large fields cannot add
// up past the host's timeout; the rest of the 10 s covers the store, the
// decision and the reply.
export const HOOK_SCAN_DEADLINE_MS = 6_000;

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
