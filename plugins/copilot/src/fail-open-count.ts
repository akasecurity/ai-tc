/**
 * The detached fail-open counting child.
 *
 * Started by `runHookFailOpen` (see src/hooks/shared.ts) once a hook body has
 * thrown or outrun its watchdog and the hook has already written whatever it
 * writes on that path — on every shipped hook, nothing. It records one exit in
 * the machine's hook fail-open tally, which `aka status` renders.
 *
 *   node scripts/fail-open-count.js
 *
 * A separate process because the tally write is synchronous filesystem work
 * that nothing can interrupt: a write that stalls on a wedged home stalls this
 * process, never the hook's exit.
 *
 * Never throws: `recordHookFailOpen` swallows every filesystem error, and the
 * home lookup, which throws when the platform cannot name a home, is guarded
 * here. Always exits 0.
 */
import { dataDir, recordHookFailOpen } from '@akasecurity/plugin-sdk';

try {
  recordHookFailOpen(dataDir(), Date.now());
} catch {
  // Nothing to report to — this process is detached with stdio ignored.
}
process.exit(0);
