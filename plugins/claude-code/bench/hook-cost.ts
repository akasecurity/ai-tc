/**
 * The per-call cost of the built hook scripts, interleaved with a bare
 * `node -e 0` baseline so that machine load lands on every variant alike.
 *
 *   node bench/hook-cost.ts [--iterations 40] [--dir label=path ...]
 *
 * Each round runs every variant once, in an order rotated per round, then the
 * medians and 90th percentiles of wall and CPU time are printed with each
 * hook's median cost over the baseline. `--dir` may be given more than once to
 * compare two builds of `scripts/` in the same loop (for example a copy taken
 * before a change against the current build); it defaults to this package's
 * own `scripts/`. CPU time is the steadier of the two readings on a busy
 * machine, and the delta over the baseline is the number a user pays per call.
 *
 * The numbers are the warm, steady-state cost: an untimed first pass creates
 * the store, the once-per-session markers and the compile cache before any
 * round is timed. Prints a table and asserts nothing about time: this is a
 * measurement, not a gate. It does exit non-zero when a control call shows
 * the hooks under measurement are not actually running.
 */
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import {
  assertHooksRun,
  createBenchHome,
  HOOK_PAYLOADS,
  type HookVariant,
  runHook,
} from './hook-process.ts';

const { values } = parseArgs({
  options: {
    iterations: { type: 'string', default: '40' },
    dir: { type: 'string', multiple: true },
  },
});

const iterations = Number(values.iterations);
if (!Number.isInteger(iterations) || iterations < 1) throw new Error('--iterations must be >= 1');

const packageRoot = fileURLToPath(new URL('..', import.meta.url));
const dirs = (values.dir ?? [`built=${join(packageRoot, 'scripts')}`]).map((spec) => {
  const at = spec.indexOf('=');
  const [label, path] = at === -1 ? [spec, spec] : [spec.slice(0, at), spec.slice(at + 1)];
  const dir = resolve(path);
  if (!existsSync(join(dir, 'pre-tool-use.js'))) {
    throw new Error(`${dir} holds no built hooks — run the package build first`);
  }
  return { label, dir };
});

interface Variant {
  name: string;
  script: string | undefined;
  payload: string;
}

const variants: Variant[] = [{ name: 'baseline (node -e 0)', script: undefined, payload: '' }];
for (const { label, dir } of dirs) {
  for (const [name, spec] of Object.entries(HOOK_PAYLOADS) as [
    HookVariant,
    (typeof HOOK_PAYLOADS)[HookVariant],
  ][]) {
    variants.push({
      name: dirs.length > 1 ? `${label}: ${name}` : name,
      script: join(dir, spec.entry),
      payload: JSON.stringify(spec.payload),
    });
  }
}

const quantile = (sorted: number[], q: number): number =>
  sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))] ?? Number.NaN;

const { env, cleanup } = createBenchHome();
try {
  // One untimed pass: the first run of each hook creates the store, its
  // once-per-session markers and its compile cache, which no later call pays
  // again — so every number below is the warm, steady-state cost. Then the
  // control: each build under measurement must really run its hooks.
  for (const variant of variants) runHook(variant, env);
  for (const { dir } of dirs) assertHooksRun(dir, env);

  const wall = new Map<string, number[]>(variants.map((v) => [v.name, []]));
  const cpu = new Map<string, number[]>(variants.map((v) => [v.name, []]));
  for (let round = 0; round < iterations; round++) {
    for (let k = 0; k < variants.length; k++) {
      const variant = variants[(round + k) % variants.length];
      if (variant === undefined) continue;
      const sample = runHook(variant, env);
      if (sample.status !== 0) throw new Error(`${variant.name} exited ${String(sample.status)}`);
      wall.get(variant.name)?.push(sample.wallMs);
      cpu.get(variant.name)?.push(sample.cpuMs);
    }
  }

  const stats = variants.map((v) => {
    const w = [...(wall.get(v.name) ?? [])].sort((a, b) => a - b);
    const c = [...(cpu.get(v.name) ?? [])].sort((a, b) => a - b);
    return {
      name: v.name,
      w50: quantile(w, 0.5),
      w90: quantile(w, 0.9),
      c50: quantile(c, 0.5),
      c90: quantile(c, 0.9),
    };
  });
  const base = stats[0];
  const fmt = (n: number): string => n.toFixed(1).padStart(8);
  const width = Math.max(...stats.map((s) => s.name.length));
  const out = (line: string): void => {
    process.stdout.write(`${line}\n`);
  };
  out(
    `${String(iterations)} interleaved rounds, ${process.version}, ${process.platform}-${process.arch}`,
  );
  out(
    `${'variant'.padEnd(width)}  wall p50  wall p90   cpu p50   cpu p90  Δwall p50  Δcpu p50  cpu ratio`,
  );
  for (const s of stats) {
    const dw = base === undefined ? Number.NaN : s.w50 - base.w50;
    const dc = base === undefined ? Number.NaN : s.c50 - base.c50;
    const ratio = base === undefined ? Number.NaN : s.c50 / base.c50;
    out(
      `${s.name.padEnd(width)}${fmt(s.w50)}  ${fmt(s.w90)}  ${fmt(s.c50)}  ${fmt(s.c90)}  ${fmt(dw)}   ${fmt(dc)}   ${ratio.toFixed(2).padStart(7)}`,
    );
  }
} finally {
  cleanup();
}
