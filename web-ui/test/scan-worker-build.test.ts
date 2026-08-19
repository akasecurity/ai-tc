import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { SCAN_WORKER_RELATIVE_PATH } from '../app/lib/scan-worker.ts';

/**
 * `dist/` holds the scan worker the folder scan starts BY PATH, and two suites
 * here drive the real artifact (test/actions/scan.test.ts through the action,
 * test/e2e/scan-worker-bundle.e2e.test.ts directly). So it has to exist before
 * vitest starts, and nothing may write it while vitest runs.
 *
 * The second half is the one that is easy to lose, because the writer that
 * races the suite is not in this package's `test` script. `turbo run test`
 * schedules `web-ui#build` beside `web-ui#test` — the CLI's test task reaches it
 * through `^build` — and there is deliberately no ordering edge between the two
 * (turbo.json: a full `next build` must not sit on the critical path of
 * `pnpm test`). A `tsup` inlined into either script is therefore a SECOND
 * writer of `dist/`, and its `clean: true` removes and rewrites the worker
 * while a vitest fork is between `existsSync` and `new Worker(…)`. Measured on
 * CI: the same case failed on two runs an hour apart with two different
 * assertions — "shipped without its scan worker" when the file was gone at
 * `existsSync`, and no culprit quarantined when it vanished under the worker's
 * load — and passed on rerun both times.
 *
 * The shape that cannot race is ONE writer, and every reader ordered after it:
 * `build:worker` is the only script that runs tsup, and `build`, `test` and
 * `dev` all depend on it, so turbo finishes the write before any of them
 * starts and never runs a second one. A cache hit is a write too — turbo
 * restores a task's declared `outputs` — which is why `build`'s outputs must
 * not include `dist/**`: a replayed `web-ui#build` would otherwise rewrite the
 * worker beside a running `web-ui#test` exactly as a fresh tsup does.
 */
const PACKAGE_JSON = fileURLToPath(new URL('../package.json', import.meta.url));
const TURBO_JSON = fileURLToPath(new URL('../turbo.json', import.meta.url));

const WORKER_TASK = 'build:worker';
const WORKER_DIR = SCAN_WORKER_RELATIVE_PATH.split('/')[0] ?? '';

interface Manifest {
  scripts?: Record<string, string>;
}

interface TurboTask {
  dependsOn?: string[];
  outputs?: string[];
}

interface TurboConfig {
  tasks?: Record<string, TurboTask>;
}

const scripts = (JSON.parse(readFileSync(PACKAGE_JSON, 'utf8')) as Manifest).scripts ?? {};

// turbo.json is JSONC. Strip line comments before parsing — block comments are
// not used in it, and a regex that tried to handle them would eat the globs.
const tasks =
  (JSON.parse(readFileSync(TURBO_JSON, 'utf8').replace(/^\s*\/\/.*$/gm, '')) as TurboConfig)
    .tasks ?? {};

// A script writes `dist/` if it runs tsup itself OR runs the script that does
// (`pnpm run build:worker && vitest run` is the same second writer with the
// tsup one hop away).
const writesWorkerDir = (script: string): boolean =>
  /(^|[\s&|;])tsup(\s|$)/.test(script) || new RegExp(`\\b${WORKER_TASK}\\b`).test(script);

// A task turbo.json does not declare has no edges and no outputs; read it as the
// empty lists so the failure names the missing edge rather than the missing key.
const dependsOn = (task: string): string[] => tasks[task]?.dependsOn ?? [];
const outputs = (task: string): string[] => tasks[task]?.outputs ?? [];

// A glob covers `dist/` under more spellings than the `dist/`-prefix literal:
// turbo accepts (and keeps, in `resolvedTaskDefinition.outputs`) a leading
// `./`, and a bare `**` — or any `**/`-rooted glob — restores every directory
// including this one. Comparing the raw string against `dist/` alone passes
// `./dist/**` and `**` straight through, which puts a cache-hit `build` back in
// the race this suite exists to catch.
const normalizeGlob = (glob: string): string => glob.replace(/^\.\//, '');
const coversWorkerDir = (glob: string): boolean => {
  const normalized = normalizeGlob(glob);
  return (
    normalized === '**' || normalized.startsWith('**/') || normalized.startsWith(`${WORKER_DIR}/`)
  );
};

describe('the scan worker has one writer, and every consumer waits for it', () => {
  it(`\`${WORKER_TASK}\` is the only script that writes \`${WORKER_DIR}/\``, () => {
    // Pinned as an EXACT set rather than "build:worker runs tsup": a second
    // script that also ran it would be the second writer, and it is what a
    // well-meaning `tsup && vitest run` puts back.
    const writers = Object.entries(scripts)
      .filter(([, script]) => writesWorkerDir(script))
      .map(([name]) => name)
      .sort();
    expect(writers).toEqual([WORKER_TASK]);
  });

  it(`turbo declares \`${WORKER_DIR}/**\` as \`${WORKER_TASK}\`'s output`, () => {
    // Undeclared, a cache hit would restore nothing and a fresh checkout would
    // run the suites against a missing worker — the "shipped without its scan
    // worker" failure, made permanent instead of intermittent.
    expect(outputs(WORKER_TASK)).toContain(`${WORKER_DIR}/**`);
  });

  it(`\`${WORKER_TASK}\` is invalidated when a bundled dependency's source changes`, () => {
    // The worker bundles the plugin SDK's source; turbo's default inputs are
    // this package's own files, so without a dependency edge into the hash a
    // change to scan-worker.ts would replay a cached, stale worker.
    expect(dependsOn(WORKER_TASK)).toContain('^typecheck');
  });

  it.each(['build', 'test', 'dev'])(`\`%s\` depends on \`${WORKER_TASK}\``, (task) => {
    expect(dependsOn(task), `${task}.dependsOn`).toContain(WORKER_TASK);
  });

  it(`\`build\` does not declare \`${WORKER_DIR}/**\` as an output`, () => {
    // Overridden here rather than inherited: the root `build` task lists
    // `dist/**`, and a cache-hit `web-ui#build` replaying beside `web-ui#test`
    // would restore the worker into a directory the suite is reading.
    expect(tasks.build?.outputs, 'build.outputs must be declared in this package').toBeDefined();
    const restoresWorkerDir = outputs('build').some(coversWorkerDir);
    expect(restoresWorkerDir).toBe(false);
  });
});

describe('coversWorkerDir', () => {
  // Positive control: every spelling turbo accepts for "restore dist/" has to
  // flag true here, or the assertion above passes on a `build` task that
  // reintroduces the second-writer race under one of them.
  it.each([`${WORKER_DIR}/**`, `./${WORKER_DIR}/**`, `${WORKER_DIR}/*`, '**', '**/*', './**'])(
    'flags %s as covering the worker dir',
    (glob) => {
      expect(coversWorkerDir(glob)).toBe(true);
    },
  );

  it.each(['.next/**', '!.next/cache/**', `${WORKER_DIR}-other/**`])('does not flag %s', (glob) => {
    expect(coversWorkerDir(glob)).toBe(false);
  });
});
