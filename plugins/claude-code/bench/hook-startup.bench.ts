/**
 * What one hook call costs, end to end, as the host pays it: a fresh `node`
 * process running the BUILT script with one payload on stdin.
 *
 * The hooks run on every matched tool call and once per turn, so this is a
 * per-call tax on every session. Most of it is process start-up — compiling and
 * evaluating the bundle, building the schemas, opening the store — rather than
 * the scan itself, which is why the rows here spawn the real artifact instead of
 * timing `runPreToolUse` in-process. The `node -e 0` row is the floor every
 * other row stands on: the number a change can move is the gap above it.
 *
 * Wall time only, because that is what vitest's bench reports. For CPU time and
 * an interleaved comparison of two builds (for example before and after a
 * change), `bench/hook-cost.ts` spawns the same payloads and prints both.
 *
 * The rows are the warm, steady-state cost: the store, the once-per-session
 * markers and the compile cache are created by a first call before any row is
 * timed.
 *
 * NO ASSERTIONS about time: nothing in this repository gates a PR on
 * wall-clock. The control below checks something else — that the hooks really
 * run, by requiring a decision for a bundled rule's own example — and it runs
 * at module scope, where a throw fails the run, because a bench body that
 * throws is swallowed and a hook that exited at once would otherwise read as
 * a very fast one.
 */
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bench, describe } from 'vitest';

import {
  assertHooksRun,
  createBenchHome,
  HOOK_PAYLOADS,
  type HookVariant,
  runHook,
} from './hook-process.ts';

const SCRIPTS_DIR = fileURLToPath(new URL('../scripts/', import.meta.url));
const { env, cleanup } = createBenchHome();
process.on('exit', cleanup);

const variants = (Object.keys(HOOK_PAYLOADS) as HookVariant[]).map((name) => ({
  name,
  script: join(SCRIPTS_DIR, HOOK_PAYLOADS[name].entry),
  payload: JSON.stringify(HOOK_PAYLOADS[name].payload),
}));

// The warm-up, then the control.
for (const variant of variants) {
  const sample = runHook(variant, env);
  if (sample.status !== 0) throw new Error(`${variant.name} exited ${String(sample.status)}`);
}
assertHooksRun(SCRIPTS_DIR, env);

describe('one hook call, as a fresh node process', () => {
  bench('node -e 0 (baseline)', () => {
    runHook({ script: undefined, payload: '' }, env);
  });

  for (const variant of variants) {
    bench(variant.name, () => {
      runHook(variant, env);
    });
  }
});
