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
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import { Rule } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

// test/native-host -> plugins/browser-extension
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOST_DIR = join(PACKAGE_ROOT, 'native-host');

// The filename plugin-sdk's resolver probes for (packages/plugin-sdk/src/
// isolated-scan.ts). tsup's entry key is what produces it, so the two have to
// change together or the worker becomes unreachable at runtime.
const WORKER_SCRIPT = 'scan-worker.js';
const HOST_SCRIPT = 'host.js';

// The pulled pack the host case installs. Its pattern is not among the bundled
// rules, so the runtime treats it as unverified — which is the ONLY condition
// under which a worker is started at all.
const PULLED_PACK_RULE = Rule.parse({
  specVersion: 1,
  id: 'e2e-worker/marker',
  name: 'Isolated-scan e2e marker',
  category: 'secret',
  severity: 'high',
  matcher: { type: 'regex', pattern: 'ZQXJ[0-9]{8}', flags: 'g' },
  examples: ['ZQXJ12345678'],
});
const PULLED_MATCH = 'ZQXJ12345678';

const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

/**
 * A throwaway `~/.aka` with the bundled packs plus the pulled rule above, and
 * the env that points the host's `os.homedir()` at it — HOME on POSIX,
 * USERPROFILE on Windows, both set so neither platform reads the real home.
 */
function seededHome(prefix: string): { home: string; dataDir: string } {
  const home = tempDir(prefix);
  const dataDir = join(home, '.aka', 'data');
  mkdirSync(dataDir, { recursive: true });
  const db = openLocalDatabase(dataDir);
  try {
    db.installedPacks.recordInventory([
      ...bundledDetections(),
      {
        namespace: 'e2e-worker',
        packId: 'marker',
        version: '1.0.0',
        name: 'Isolated-scan e2e pack',
        rules: [PULLED_PACK_RULE],
      },
    ]);
  } finally {
    db.close();
  }
  return { home, dataDir };
}

/**
 * One Chrome native-messaging frame: a 4-byte little-endian length prefix and
 * that many bytes of UTF-8 JSON (src/native-host/wire.ts). Built here rather
 * than imported from the source module on purpose — this suite drives the
 * BUILT host, and framing its input with the same source code the bundle was
 * compiled from would hide a framing change that only the bundle carries.
 */
function frame(message: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(message), 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

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

  it('is found by the built host’s own resolver, from the native-host bundle', async () => {
    // The three cases above prove the file is emitted, that its name is a
    // literal in host.js, and that it runs when started BY THIS SUITE. None of
    // them drives `resolveWorkerUrl()` as the shipped bundle inlines it — the
    // one half that fails only once installed, and the half that differs by
    // platform, since it is `fileURLToPath` over a bundled script's own URL
    // (drive letters, UNC paths, the `file:///C:/…` round trip).
    //
    // So this spawns the built host the way Chrome does — the script alone,
    // one framed message on stdin — against a throwaway home carrying a pulled
    // regex rule, which is the one condition that starts a worker at all.
    const { home, dataDir } = seededHome('aka-ext-host-home-');

    const result = spawnSync(process.execPath, [join(HOST_DIR, HOST_SCRIPT)], {
      input: frame({
        type: 'capture',
        requestId: 'e2e-worker-1',
        sessionId: 'e2e-worker-session',
        tool: 'claude-ai',
        kind: 'prompt',
        text: `here is a token ${PULLED_MATCH} for you`,
      }),
      // The host reads until stdin ENDS, so spawnSync's close is what ends its
      // message loop and lets the process exit. Bytes rather than a string:
      // the length prefix is binary and utf8 encoding would corrupt it.
      encoding: 'buffer',
      env: { ...processEnv(), HOME: home, USERPROFILE: home },
      maxBuffer: 64 * 1024 * 1024,
    });
    // The spawn itself first, BEFORE touching its streams. A failed spawn
    // leaves `stderr` undefined, so reading it here throws
    // `Cannot read properties of undefined` and buries the real cause — and the
    // likeliest first failure on the Windows leg this suite was just added to
    // is exactly a spawn failure.
    expect(result.error).toBeUndefined();
    // Fail-open next: whatever else happened, the bridge must not have died.
    expect(result.status).toBe(0);
    const stderr = result.stderr.toString('utf8');

    const after = openLocalDatabase(dataDir);
    try {
      // Positive control, part one: the rule was MEASURED. Only a rule the
      // runtime treats as unverified reaches the timing pre-flight, and that
      // pre-flight runs in a worker of its own — so this row cannot exist
      // unless the resolver found the script from inside the built host.
      const key = ruleProbeKey(PULLED_PACK_RULE);
      expect(key).toBeDefined();
      expect(after.ruleProbeCache.getVerdict(key ?? '')?.verdict).toBe('safe');

      // Part two: being unverified, it runs ONLY in the scan worker. A host
      // that lost its worker drops these rules and keeps the built-in packs,
      // so a finding from this rule is proof the isolated scan answered.
      // Without both controls the absence check below is vacuous — a host that
      // never isolated anything also never warns about losing its worker.
      const recent = await after.findings.recentFindings({ limit: 50 });
      expect(recent.map((f) => f.ruleId)).toContain('e2e-worker/marker');
    } finally {
      after.close();
    }

    // And the resolver never fell back. This is the line the installed
    // extension would print, on every machine, if the worker URL pointed at a
    // source path that was never packaged.
    expect(stderr).not.toContain('the scan worker script was not found');
  });
});

// The host env, read once so the child spawn inherits PATH/node while pointing
// the home dir at a throwaway. Overriding the home is the only way to redirect
// ~/.aka — the host must not (and does not) hard-resolve it.
function processEnv(): NodeJS.ProcessEnv {
  // eslint-disable-next-line n/no-process-env -- an e2e spawn of the real host needs the host PATH
  return process.env;
}
