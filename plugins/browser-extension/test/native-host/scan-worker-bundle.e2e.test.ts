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
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { openLocalDatabase } from '@akasecurity/persistence';
import {
  bundledDetections,
  LARGE_INPUT_THRESHOLD_CHARS,
  ruleProbeKey,
} from '@akasecurity/plugin-sdk';
import { Rule } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';

// test/native-host -> plugins/browser-extension
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOST_DIR = join(PACKAGE_ROOT, 'native-host');

// The filename plugin-sdk's resolver probes for (packages/plugin-sdk/src/
// isolated-scan.ts). tsup's entry key is what produces it, so the two have to
// change together or the worker becomes unreachable at runtime.
const WORKER_SCRIPT = 'scan-worker.js';
const HOST_SCRIPT = 'host.js';

// The largest the built worker may be. Its start is charged to a 500ms budget
// inside the 2s a prompt capture is given (src/native-host/host.ts), and what
// that start mostly costs is loading this file, so a bundle that grows is a
// worker that starts later on every machine and misses the budget on a slow
// one. It was 474KB when this was set; it once doubled to 1MB when zod's
// locale files were pulled in.
const MAX_WORKER_BYTES = 600_000;

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

/**
 * Every frame in a native-messaging stdout buffer, parsed. The inverse of
 * `frame` above, and written here for the same reason: the BUILT host's framing
 * is what is under test.
 */
function unframe(buffer: Buffer): unknown[] {
  const messages: unknown[] = [];
  let at = 0;
  while (at + 4 <= buffer.length) {
    const length = buffer.readUInt32LE(at);
    messages.push(JSON.parse(buffer.subarray(at + 4, at + 4 + length).toString('utf8')));
    at += 4 + length;
  }
  return messages;
}

afterAll(() => {
  removeTrees(temps);
});

describe('the built scan worker', () => {
  it('is emitted beside the native host Chrome actually launches', () => {
    expect(existsSync(join(HOST_DIR, HOST_SCRIPT))).toBe(true);
    expect(existsSync(join(HOST_DIR, WORKER_SCRIPT))).toBe(true);
  });

  it('is small enough to start inside the capture’s start budget', () => {
    const bytes = statSync(join(HOST_DIR, WORKER_SCRIPT)).size;
    expect(
      bytes,
      `${WORKER_SCRIPT} is ${String(bytes)} bytes. The native host gives the worker 500ms to ` +
        `start, and loading this file is most of that; a larger bundle refuses long prompts on ` +
        `slow machines. Find what the bundle newly pulls in before raising this.`,
    ).toBeLessThanOrEqual(MAX_WORKER_BYTES);
    // A size that reads as zero is a file that was never built, not a small one.
    expect(bytes).toBeGreaterThan(MAX_WORKER_BYTES / 4);
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

// A prompt at or above the large-input threshold is scanned in this same worker
// whatever the ruleset, under a deadline the relay can still answer inside —
// so on a host that lost its worker, every such prompt is REFUSED rather than
// let through. That makes the worker shipping beside host.js a condition of
// sending a long prompt at all, and these two rows drive both sides of it
// through the built host.
//
// They drive the built host's own request handler, imported from host.js, with
// the capture's start and scan budgets replaced by generous test-only ones.
// What these rows exist to show is that the worker is FOUND and STARTS beside
// host.js; the product's 500ms start budget turns a slow start into the same
// refusal as a missing worker, and a loaded runner starts a worker slowly, so
// under that budget the present-worker row failed with no defect in the build.
// The budgets themselves are pinned by host.test.ts, and what the start costs
// is pinned by the worker's size above.
describe('a prompt past the large-input threshold, through the built host', () => {
  const LARGE = `${'lorem ipsum dolor sit amet '.repeat(Math.ceil(LARGE_INPUT_THRESHOLD_CHARS / 27))}end`;
  const TEST_START_BUDGET_MS = 10_000;
  const TEST_DEADLINE_MS = 15_000;

  // Imports the built host from `hostDir` the way Chrome would load it, with
  // nothing on stdin so its own message loop ends at once, and answers one
  // capture through the handler that loop would call.
  const DRIVER = `
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [hostPath, requestPath, startBudgetMs, deadlineMs] = process.argv.slice(2);
const host = await import(pathToFileURL(hostPath).href);
const request = JSON.parse(readFileSync(requestPath, 'utf8'));
const response = await host.handleRequest(request, undefined, (receivedAt) => ({
  ...host.captureLargeInput(receivedAt),
  startBudgetMs: Number(startBudgetMs),
  budgetMs: Number(deadlineMs),
  remainingMs: () => receivedAt + Number(deadlineMs) - performance.now(),
}));
process.stdout.write(JSON.stringify(response), () => process.exit(0));
`;

  function capture(hostDir: string): { reply: Record<string, unknown>; stderr: string } {
    const home = tempDir('aka-ext-large-home-');
    const work = tempDir('aka-ext-large-driver-');
    const driver = join(work, 'drive-host.mjs');
    const request = join(work, 'request.json');
    writeFileSync(driver, DRIVER);
    writeFileSync(
      request,
      JSON.stringify({
        type: 'capture',
        requestId: 'e2e-large-1',
        sessionId: 'e2e-large-session',
        tool: 'chatgpt',
        kind: 'prompt',
        text: LARGE,
      }),
    );
    const result = spawnSync(
      process.execPath,
      [
        driver,
        join(hostDir, HOST_SCRIPT),
        request,
        String(TEST_START_BUDGET_MS),
        String(TEST_DEADLINE_MS),
      ],
      {
        input: '',
        encoding: 'utf8',
        env: { ...processEnv(), HOME: home, USERPROFILE: home },
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    expect(result.error).toBeUndefined();
    expect(result.status, result.stderr).toBe(0);
    return { reply: JSON.parse(result.stdout) as Record<string, unknown>, stderr: result.stderr };
  }

  it('is scanned by the shipped worker and judged on its content', () => {
    // Benign text, so a judged prompt is a `log` — and a refusal here would
    // mean the worker beside host.js could not be found or started.
    const { reply, stderr } = capture(HOST_DIR);
    expect(stderr).not.toContain('the scan worker script was not found');
    expect(reply.scanIncomplete, `the worker did not answer: ${stderr}`).toBeUndefined();
    expect(reply).toEqual({
      type: 'capture',
      requestId: 'e2e-large-1',
      ok: true,
      action: 'log',
      ruleIds: [],
    });
  });

  it('is refused as an explicit block when the worker is missing', () => {
    // A copy of the built host without its worker: the state an install that
    // never shipped it is in. The row above is the control — same prompt,
    // same build, only the worker removed.
    const dir = tempDir('aka-ext-no-worker-');
    const hostDir = join(dir, 'native-host');
    cpSync(HOST_DIR, hostDir, {
      recursive: true,
      filter: (source) => basename(source) !== WORKER_SCRIPT,
    });
    expect(existsSync(join(hostDir, HOST_SCRIPT))).toBe(true);
    expect(existsSync(join(hostDir, WORKER_SCRIPT))).toBe(false);

    const refusal = {
      type: 'capture',
      requestId: 'e2e-large-1',
      ok: true,
      action: 'block',
      text: null,
      ruleIds: [],
      scanIncomplete: 'unavailable',
    };
    const { reply, stderr } = capture(hostDir);
    expect(reply).toEqual(refusal);
    expect(stderr).toContain('the scan worker script was not found');
    expect(JSON.stringify(reply)).not.toContain('lorem ipsum');

    // And the same refusal as Chrome would receive it: the script alone, the
    // capture as a framed message on stdin, the reply framed on stdout, under
    // the product's own budgets. No worker means nothing to wait for, so those
    // budgets decide nothing here.
    const launched = launchAsChrome(hostDir);
    expect(launched).toEqual(refusal);
    expect(JSON.stringify(launched)).not.toContain('lorem ipsum');
  });

  function launchAsChrome(hostDir: string): Record<string, unknown> {
    const home = tempDir('aka-ext-large-home-');
    const result = spawnSync(process.execPath, [join(hostDir, HOST_SCRIPT)], {
      input: frame({
        type: 'capture',
        requestId: 'e2e-large-1',
        sessionId: 'e2e-large-session',
        tool: 'chatgpt',
        kind: 'prompt',
        text: LARGE,
      }),
      encoding: 'buffer',
      env: { ...processEnv(), HOME: home, USERPROFILE: home },
      maxBuffer: 64 * 1024 * 1024,
    });
    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const replies = unframe(result.stdout);
    expect(replies).toHaveLength(1);
    return replies[0] as Record<string, unknown>;
  }
});

// The host env, read once so the child spawn inherits PATH/node while pointing
// the home dir at a throwaway. Overriding the home is the only way to redirect
// ~/.aka — the host must not (and does not) hard-resolve it.
function processEnv(): NodeJS.ProcessEnv {
  // eslint-disable-next-line n/no-process-env -- an e2e spawn of the real host needs the host PATH
  return process.env;
}
