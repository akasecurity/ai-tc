/**
 * The isolated scan's worker has to be reachable from the PUBLISHED plugin, and
 * that is the one thing source-level tests cannot show.
 *
 * The plugin ships `scripts/` and nothing else — no `src/`, no `node_modules`.
 * A worker URL resolved against a source path therefore points at a file that
 * was never packaged, and the trap is that it works perfectly in the repo and
 * under vitest: every local test passes and only an installed plugin fails, by
 * silently losing the bound it was installed for. So this suite drives the real
 * built artifact from a directory with nothing else in it.
 */
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { afterAll, describe, expect, it } from 'vitest';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

// The filename the SDK's resolver probes for (packages/plugin-sdk/src/
// isolated-scan.ts). tsup's entry key is what produces it, so the two have to
// be changed together or the worker becomes unreachable at runtime.
const WORKER_SCRIPT = 'scan-worker.js';

// Every emitted hook that builds a plugin runtime inlines the resolver, so each
// one must have the worker as a sibling. The three live hooks are the hot path;
// filescan and backfill scan far more text per invocation.
const RUNTIME_SCRIPTS = [
  'pre-tool-use.js',
  'post-tool-use.js',
  'user-prompt-submit.js',
  'filescan.js',
  'backfill.js',
];

const temps: string[] = [];

function isolatedCopyOfScripts(): string {
  // A temp dir has no node_modules anywhere above it, which is the property
  // that makes this a test of self-containment rather than of the repo.
  const dir = mkdtempSync(join(tmpdir(), 'aka-scan-worker-'));
  temps.push(dir);
  cpSync(SCRIPTS_DIR, join(dir, 'scripts'), { recursive: true });
  return dir;
}

afterAll(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

describe('the built scan worker', () => {
  it('is emitted beside the hooks that start it', () => {
    expect(existsSync(join(SCRIPTS_DIR, WORKER_SCRIPT))).toBe(true);
    for (const script of RUNTIME_SCRIPTS) {
      expect(existsSync(join(SCRIPTS_DIR, script))).toBe(true);
      // The inlined resolver looks for exactly this name next to itself. If the
      // tsup entry is renamed or dropped, every isolated scan degrades to the
      // built-in packs only — quietly, and only once installed.
      expect(readFileSync(join(SCRIPTS_DIR, script), 'utf8')).toContain(WORKER_SCRIPT);
    }
  });

  it('runs and scans with no node_modules anywhere above it', async () => {
    const dir = isolatedCopyOfScripts();
    const worker = new Worker(join(dir, 'scripts', WORKER_SCRIPT), {
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
            if (message.kind === 'result') resolve(message.findings ?? []);
            if (message.kind === 'failed') reject(new Error('the worker reported a scan failure'));
          });
          worker.postMessage({ id: 1, text: 'deploy with AKIA0123456789ABCDEF now' });
        },
      );

      expect(findings.map((f) => f.ruleId)).toEqual(['pulled/aws-key']);
      expect(findings[0]?.rawMatch).toBe('AKIA0123456789ABCDEF');
    } finally {
      await worker.terminate();
    }
  });
});
