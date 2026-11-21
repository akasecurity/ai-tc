// The large-input bound the scanning hooks pass to their runtime — preToolUse,
// beforeSubmitPrompt and postToolUse. A field at or above the threshold is
// scanned in a worker under a hard deadline, and one whose scan does not finish
// comes back with `CaptureResult.scanIncomplete` set. preToolUse and
// beforeSubmitPrompt REFUSE it — the places those hooks deny because they could
// not decide. The result hook has no channel to refuse on, so it reports the
// field as too large to scan instead, never as clean. Without the bound a large enough field
// keeps the in-process scan busy past the watchdog or the host's timeout, and
// both of those end in silence: the call goes to the host's own permission
// flow, or the text to the model, with nothing scanned and nothing said.
//
// Pure (no I/O) so it unit-tests without a hook process: hook entry files run
// main() on import and must NEVER be imported by tests.
import type { LargeInputScanOptions } from '@akasecurity/plugin-sdk';
import {
  LARGE_INPUT_SCAN_BUDGET_MS,
  LARGE_INPUT_START_BUDGET_MS,
  LARGE_INPUT_THRESHOLD_CHARS,
} from '@akasecurity/plugin-sdk';

// When a hook stops spending time on bounded scans, in milliseconds since
// the hook process started (performance.now()'s origin). Every bounded scan in
// the process draws on it, so several large fields cannot add up past it.
//
// It sits INSIDE `runHookFailOpen`'s 24 s watchdog (./shared.ts) rather than
// the 30 s `timeout` hooks.json registers, because the watchdog is armed after the process
// starts and resolves the race with silence: a refusal still being decided
// when it fires is never written. The 9 s between this and the watchdog cover
// module load, a contended store, the decision and the emit. On preToolUse a
// full bounded scan of every field a call carries (two at most) fits under it;
// a structured tool result's many leaves all draw on this one deadline.
export const HOOK_SCAN_DEADLINE_MS = 15_000;

/**
 * The runtime's `largeInput` option for a hook whose bounded scans must all be
 * over by `deadlineAt` (on `now`'s clock). The remaining time is read when each
 * bounded scan starts, so it is fixed by the deadline rather than by how many
 * fields came before.
 *
 * `refuses` says whether the hook refuses a field it could not scan: true for
 * preToolUse, which denies it, and false for the prompt and result hooks, which
 * can only report it — so the SDK writes no line saying such a field "was
 * refused" beside the hook's own notice that it went through unchanged.
 */
export function largeInputBound(
  deadlineAt: number,
  refuses: boolean,
  now: () => number = () => performance.now(),
): LargeInputScanOptions {
  return {
    thresholdChars: LARGE_INPUT_THRESHOLD_CHARS,
    budgetMs: LARGE_INPUT_SCAN_BUDGET_MS,
    startBudgetMs: LARGE_INPUT_START_BUDGET_MS,
    remainingMs: () => deadlineAt - now(),
    refuses,
  };
}

/**
 * The bound every hook in this package passes its runtime: `largeInputBound`
 * against `HOOK_SCAN_DEADLINE_MS`, so no hook can pair the bound with another
 * deadline.
 */
export function hookLargeInputBound(refuses: boolean, now?: () => number): LargeInputScanOptions {
  return largeInputBound(HOOK_SCAN_DEADLINE_MS, refuses, now);
}
