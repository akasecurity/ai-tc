/**
 * The isolated scan's worker has to be reachable from the INSTALLED extension,
 * and that is the one thing source-level tests cannot show.
 *
 * Chrome launches `native-host/host.js` and nothing else — no `src/`, no
 * `node_modules`. `@akasecurity/plugin-sdk` starts the worker by a path
 * resolved as a sibling of the running script, so a worker URL resolved
 * against a source path points at a file that was never packaged. The trap is
 * that it works perfectly in the repo and under vitest: every local test
 * passes, and only an installed extension fails — by silently dropping every
 * pulled and custom rule while the built-in packs keep detecting.
 */
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { afterAll, describe, expect, it } from 'vitest';

// test/native-host -> plugins/browser-extension
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOST_DIR = join(PACKAGE_ROOT, 'native-host');

// The filename plugin-sdk's resolver probes for (packages/plugin-sdk/src/
// isolated-scan.ts). tsup's entry key is what produces it, so the two have to
// change together or the worker becomes unreachable at runtime.
const WORKER_SCRIPT = 'scan-worker.js';
const HOST_SCRIPT = 'host.js';

const temps: string[] = [];

afterAll(() => {
  for (const dir of temps) rmSync(dir, { recursive: true, force: true });
});

describe('the built scan worker', () => {
  it('is emitted beside the native host Chrome actually launches', () => {
    expect(existsSync(join(HOST_DIR, HOST_SCRIPT))).toBe(true);
    expect(existsSync(join(HOST_DIR, WORKER_SCRIPT))).toBe(true);
  });

  it('is the name the host’s own inlined resolver looks for', () => {
    // The shipped bundle inlines resolveWorkerUrl(), so the probed filename
    // ends up as a literal in host.js. If the tsup entry is renamed or
    // dropped, every isolated scan degrades to the built-in packs — quietly,
    // and only once installed.
    expect(readFileSync(join(HOST_DIR, HOST_SCRIPT), 'utf8')).toContain(WORKER_SCRIPT);
  });

  it('runs and scans with no node_modules anywhere above it', async () => {
    // A temp dir has no node_modules anywhere above it, which is what makes
    // this a test of self-containment rather than of the repo.
    const dir = mkdtempSync(join(tmpdir(), 'aka-ext-scan-worker-'));
    temps.push(dir);
    cpSync(HOST_DIR, join(dir, 'native-host'), { recursive: true });

    const worker = new Worker(join(dir, 'native-host', WORKER_SCRIPT), {
      workerData: {
        verified: [],
        // Only a rule the runtime treats as UNVERIFIED reaches a worker at all.
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
