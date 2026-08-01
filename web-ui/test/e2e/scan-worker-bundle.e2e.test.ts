/**
 * The dashboard's scan worker has to be reachable from the BUILT app, and that
 * is the one thing source-level tests cannot show.
 *
 * The trap is specific and it has already been measured on this code: a Next
 * build REPLACES `import.meta.url` with the build machine's own absolute source
 * path, baked into the server chunk as a string literal. So the plugin SDK's
 * resolve-a-sibling lookup — correct for the plugin's flat `scripts/` output —
 * finds the worker perfectly on the machine that ran the build and nothing at
 * all on a user's, where the failure is silent: the folder scan drops every
 * rule it cannot bound and carries on. Which is why this app states the
 * worker's location itself (app/lib/scan-worker.ts) and this suite drives the
 * REAL built artifact rather than the source it came from.
 *
 * What this suite covers, and what it does not:
 *
 *   covered here — the build emits the worker at exactly the path the runtime
 *   resolver computes; the resolver finds it from an app directory; the emitted
 *   file is genuinely self-contained (nothing that runs it has a node_modules
 *   to resolve from); and next.config.ts traces that same path.
 *
 *   covered at PACK TIME, not here — that the traced file actually lands in the
 *   published CLI. cli/scripts/bundle-web-ui.mjs asserts it and throws, so a
 *   tracing config that stops working fails `pnpm pack`/`publish` rather than
 *   shipping a dashboard whose scan quietly lost its bound. Running a full
 *   `next build` in this suite would put one on the critical path of every
 *   `pnpm test` (web-ui/turbo.json drops that edge deliberately).
 */
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { afterAll, describe, expect, it } from 'vitest';

import { SCAN_WORKER_RELATIVE_PATH, scanWorkerUrl } from '../../app/lib/scan-worker.ts';
import nextConfig from '../../next.config.ts';

// test/e2e -> web-ui
const APP_ROOT = fileURLToPath(new URL('../..', import.meta.url));
const BUILT_WORKER = join(APP_ROOT, ...SCAN_WORKER_RELATIVE_PATH.split('/'));

// A specifier that survived bundling is not a build failure — it is a runtime
// one, on a user's machine, at `new Worker(…)`. `node:`-prefixed builtins and
// their bare spellings are the only imports allowed to remain.
const NODE_BUILTINS = new Set(['worker_threads', 'node:worker_threads']);
const IMPORT_SPECIFIER = /(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"]+)['"]/g;

const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

describe('the built scan worker', () => {
  it('is emitted where the runtime resolver looks for it', () => {
    // If this fails, the `test` script no longer builds the worker first — and
    // every assertion below would be checking a stale artifact or none at all.
    expect(existsSync(BUILT_WORKER)).toBe(true);

    // The resolver's own answer, not a restatement of the path: it computes it
    // from `process.cwd()`, which under vitest is this package — the same shape
    // as the app directory the standalone server runs from.
    expect(scanWorkerUrl()).toEqual(new URL(`file://${BUILT_WORKER}`));
  });

  it('is traced into the standalone build under that same path', () => {
    // Nothing imports the worker — it is started by path — so Next's tracer
    // cannot discover it, and without this entry the standalone build ships
    // without it. Read from the config rather than restated, so a rename in
    // either place fails here instead of at a user's first scan.
    const traced = Object.values(nextConfig.outputFileTracingIncludes ?? {}).flat();
    expect(traced).toContain(`./${SCAN_WORKER_RELATIVE_PATH}`);
  });

  it('carries no specifier that would need a node_modules to resolve', () => {
    const source = readFileSync(BUILT_WORKER, 'utf8');
    const bare = new Set<string>();
    for (const [, specifier] of source.matchAll(IMPORT_SPECIFIER)) {
      if (specifier === undefined) continue;
      if (specifier.startsWith('.') || specifier.startsWith('/')) continue;
      if (NODE_BUILTINS.has(specifier)) continue;
      bare.add(specifier);
    }
    // Named rather than counted, so a regression says which dependency escaped.
    expect([...bare]).toEqual([]);
  });

  it('runs and scans with no node_modules anywhere above it', async () => {
    // A temp dir has no node_modules anywhere above it, which is the property
    // that makes this a test of self-containment rather than of the repo. The
    // `type` field mirrors the app package.json Next copies into standalone —
    // without it Node would read this ESM bundle as CommonJS and refuse it.
    const dir = tempDir('aka-web-scan-worker-');
    cpSync(BUILT_WORKER, join(dir, 'scan-worker.js'));
    writeFileSync(join(dir, 'package.json'), `${JSON.stringify({ type: 'module' })}\n`);

    const worker = new Worker(join(dir, 'scan-worker.js'), {
      workerData: {
        verified: [],
        unverified: [
          {
            specVersion: 1,
            id: 'pulled/aws-key',
            name: 'AWS key',
            category: 'secret',
            severity: 'high',
            matcher: { type: 'regex', pattern: 'AKIA[A-Z0-9]{16}', flags: 'g' },
          },
        ],
      },
    });

    try {
      const findings = await new Promise<{ ruleId: string; rawMatch: string }[]>(
        (resolve, reject) => {
          worker.on('error', reject);
          worker.on('exit', () => {
            reject(new Error('the worker exited before answering'));
          });
          worker.on('message', (message: { kind: string; findings?: never[] }) => {
            // The worker announces itself before it will take work; the parent
            // pool starts its deadline off exactly this message.
            if (message.kind === 'ready') {
              worker.postMessage({
                kind: 'scan',
                id: 1,
                text: 'deploy with AKIA0123456789ABCDEF now',
                attribute: false,
              });
            }
            if (message.kind === 'result') resolve(message.findings ?? []);
            if (message.kind === 'failed') reject(new Error('the worker reported a scan failure'));
          });
        },
      );

      expect(findings.map((f) => f.ruleId)).toEqual(['pulled/aws-key']);
      expect(findings[0]?.rawMatch).toBe('AKIA0123456789ABCDEF');
    } finally {
      await worker.terminate();
    }
  });
});
