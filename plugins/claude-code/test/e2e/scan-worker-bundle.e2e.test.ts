/**
 * The isolated scan's worker has to be reachable from the PUBLISHED plugin, and
 * that is the one thing source-level tests cannot show.
 *
 * The plugin ships `scripts/` and nothing else — no `src/`, no `node_modules`.
 * A worker URL resolved against a source path therefore points at a file that
 * was never packaged, and the trap is that it works perfectly in the repo and
 * under vitest: every local test passes and only an installed plugin fails, by
 * silently losing the bound it was installed for. So this suite drives the real
 * built artifacts — the worker from a directory with nothing else in it, and a
 * real hook whose own inlined resolver has to find it.
 */
import { spawnSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';

import { openLocalDatabase } from '@akasecurity/persistence';
import { bundledDetections, ruleProbeKey } from '@akasecurity/plugin-sdk';
import { Rule } from '@akasecurity/schema';
import { afterAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';

// test/e2e -> plugins/claude-code
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');

// The filename the SDK's resolver probes for (packages/plugin-sdk/src/
// isolated-scan.ts). tsup's entry key is what produces it, so the two have to
// be changed together or the worker becomes unreachable at runtime.
const WORKER_SCRIPT = 'scan-worker.js';

// A string only `guarded-scan.ts` emits, and it is reachable only through
// `createPluginRuntime`. Any emitted script carrying it therefore builds a
// runtime, scans, and needs the worker beside it — which is what makes this a
// derived list rather than one somebody has to remember to extend when a new
// runtime-bearing hook is added. Cut short of the scope clause that follows it
// ("the rest of this process" here, something else for a caller that builds a
// scanner per unit of work), which is a parameter rather than part of the
// marker.
const RUNTIME_MARKER = 'isolated scanning is off for ';

// The hooks that must be in the derived set. Not a substitute for deriving it:
// this is the check that the marker itself has not been renamed away, which
// would otherwise empty the set and make every assertion below vacuous.
const KNOWN_RUNTIME_SCRIPTS = [
  'pre-tool-use.js',
  'post-tool-use.js',
  'user-prompt-submit.js',
  'filescan.js',
  'backfill.js',
];

// The pulled pack the hook case installs. Its pattern is not among the bundled
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

// A COMPILED-IN rule and a value it matches, for the missing-worker case below.
// The built-in packs are what must keep detecting when the worker is gone, so
// this pair is that case's positive control — taken from the rule's own
// `examples` rather than written by hand, since this repo is public and a
// hand-rolled literal here would be secret-shaped for no reason.
const BUNDLED_RULE_ID = 'secrets/aws-access-key';
const BUNDLED_MATCH = 'AKIAIOSFODNN7EXAMPLE';

const temps: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

function runtimeBearingScripts(): string[] {
  return readdirSync(SCRIPTS_DIR).filter(
    (name) =>
      name.endsWith('.js') &&
      readFileSync(join(SCRIPTS_DIR, name), 'utf8').includes(RUNTIME_MARKER),
  );
}

afterAll(() => {
  removeTrees(temps);
});

describe('the built scan worker', () => {
  it('is emitted beside every hook that builds a runtime', () => {
    expect(existsSync(join(SCRIPTS_DIR, WORKER_SCRIPT))).toBe(true);

    const derived = runtimeBearingScripts();
    // If the marker string is ever reworded, this is what fails — rather than
    // the set quietly becoming empty and every check below passing on nothing.
    expect(derived).toEqual(expect.arrayContaining(KNOWN_RUNTIME_SCRIPTS));

    for (const script of derived) {
      // The inlined resolver looks for exactly this name next to itself. If the
      // tsup entry is renamed or dropped, every isolated scan degrades to the
      // built-in packs only — quietly, and only once installed.
      expect(readFileSync(join(SCRIPTS_DIR, script), 'utf8')).toContain(WORKER_SCRIPT);
    }
  });

  it('runs and scans with no node_modules anywhere above it', async () => {
    // A temp dir has no node_modules anywhere above it, which is the property
    // that makes this a test of self-containment rather than of the repo.
    const dir = tempDir('aka-scan-worker-');
    cpSync(SCRIPTS_DIR, join(dir, 'scripts'), { recursive: true });

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

  it('is found by a real hook’s own resolver, from the built scripts', async () => {
    // The assertions above prove the file is emitted and that it runs. Neither
    // drives `resolveWorkerUrl()` as the SHIPPED bundle inlines it — and that
    // is the half that fails only once installed. So this runs a built hook
    // end to end against a throwaway home with a pulled regex rule installed,
    // which is the one condition that starts a worker at all.
    const home = tempDir('aka-worker-home-');
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

    const result = spawnSync(process.execPath, [join(SCRIPTS_DIR, 'user-prompt-submit.js')], {
      input: JSON.stringify({
        prompt: `here is a token ${PULLED_MATCH} for you`,
        session_id: 'e2e-worker-session',
        cwd: home,
        hook_event_name: 'UserPromptSubmit',
      }),
      encoding: 'utf8',
      // The scripts resolve ~/.aka through os.homedir(), which reads HOME on
      // POSIX and USERPROFILE on Windows. Keep both pointed at the throwaway.
      env: { ...processEnv(), HOME: home, USERPROFILE: home },
      maxBuffer: 64 * 1024 * 1024,
    });

    // Fail-open first: whatever else happened, the hook must not have broken.
    expect(result.status).toBe(0);
    // The positive control. Without it the stderr assertion below is vacuous —
    // a hook that never isolated anything also never warns about losing its
    // worker. A finding from the PULLED rule can only exist if the worker was
    // resolved, started, and answered.
    const after = openLocalDatabase(dataDir);
    try {
      // Positive control, part one: the rule was measured. Only a rule the
      // runtime treats as UNVERIFIED reaches the timing gate, and the gate runs
      // in a worker of its own — so this row cannot exist unless the resolver
      // found the script from inside the built hook.
      const key = ruleProbeKey(PULLED_PACK_RULE);
      expect(key).toBeDefined();
      expect(after.ruleProbeCache.getVerdict(key ?? '')?.verdict).toBe('safe');

      // Part two: being unverified, it runs ONLY in the scan worker. A hook
      // that lost its worker drops these rules and keeps the built-in packs, so
      // a finding from this rule is proof the isolated scan answered.
      const recent = await after.findings.recentFindings({ limit: 50 });
      expect(recent.map((f) => f.ruleId)).toContain('e2e-worker/marker');
    } finally {
      after.close();
    }
    // And the resolver never fell back. This is the line the shipped plugin
    // would print, once, on every machine, if the worker URL pointed at a
    // source path that was never packaged.
    expect(result.stderr).not.toContain('the scan worker script was not found');
  });

  it('blames the install, not the rules, when it is missing from a real hook', async () => {
    // The inverse of the case above, and the one that matters to a user: an
    // install where the worker never arrived. What breaks then is not one
    // rule — it is EVERY pulled/custom regex rule on the machine, in every
    // scan, until the install is repaired. So the hook has one job here beyond
    // staying out of the way, which is to say which of those two happened.
    //
    // Driven against the built scripts rather than the source, because the
    // whole failure only exists once packaged: in the repo the resolver finds
    // `scan-worker.ts` and this state is unreachable.
    const dir = tempDir('aka-worker-missing-');
    const scripts = join(dir, 'scripts');
    cpSync(SCRIPTS_DIR, scripts, { recursive: true });
    rmSync(join(scripts, WORKER_SCRIPT));
    // The copy is what the assertions rest on: with the worker still present
    // every one of them would read the opposite way round.
    expect(existsSync(join(scripts, WORKER_SCRIPT))).toBe(false);
    expect(existsSync(join(SCRIPTS_DIR, WORKER_SCRIPT))).toBe(true);

    const home = tempDir('aka-worker-missing-home-');
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

    const result = spawnSync(process.execPath, [join(scripts, 'user-prompt-submit.js')], {
      input: JSON.stringify({
        // Both a pulled match and a BUILT-IN one. The built-in is the positive
        // control for the absence check below: it needs a rule that still fires
        // here, or an empty findings list satisfies "the pulled rule did not
        // fire" whether it was correctly dropped or the hook stopped scanning
        // altogether.
        prompt: `here is a token ${PULLED_MATCH} and a key ${BUNDLED_MATCH} for you`,
        session_id: 'e2e-worker-missing-session',
        cwd: home,
        hook_event_name: 'UserPromptSubmit',
      }),
      encoding: 'utf8',
      env: { ...processEnv(), HOME: home, USERPROFILE: home },
      maxBuffer: 64 * 1024 * 1024,
    });

    // Fail-open first, as ever: a broken install must not break the session.
    expect(result.status).toBe(0);

    // The diagnosis reaches the user. It exists inside `isolated-scan.ts` on
    // every build; what this pins is that it survives the trip to stderr rather
    // than being replaced by a timing verdict one frame before it gets there.
    expect(result.stderr).toContain('the scan worker script was not found next to this bundle');
    expect(result.stderr).toContain('reinstalling AKA brings them straight back');
    // And it states the real span. A hook builds its runtime once and scans many
    // fields in that process, so a line claiming one scan would understate a
    // whole-category gap as momentary — and talk the reader out of the reinstall
    // the same sentence just asked for.
    expect(result.stderr).toContain('excluded from every scan on this machine');
    // Not a rule problem, in any of the three spellings that would make it read
    // like one. The rule id is the load-bearing one: a user who sees it goes and
    // audits a ruleset that is fine, and the reinstall never occurs to them.
    expect(result.stderr).not.toContain('ReDoS timing budget');
    expect(result.stderr).not.toContain('quarantined rule');
    expect(result.stderr).not.toContain('e2e-worker/marker');

    const after = openLocalDatabase(dataDir);
    try {
      // The safety behaviour underneath the message, unchanged. Nothing was
      // measured, so nothing may be cached: a verdict written here would
      // disable a rule forever on the strength of a missing file, and would
      // survive the reinstall that fixes everything else.
      const key = ruleProbeKey(PULLED_PACK_RULE);
      expect(key).toBeDefined();
      expect(after.ruleProbeCache.getVerdict(key ?? '')).toBeUndefined();

      // And it was DROPPED rather than run here. Running it on this thread to
      // find out whether it is safe is the exact unbounded call the worker
      // exists to replace, so its absence from the findings is the property —
      // the same rule fires in the case above, where the worker was present.
      //
      // The built-in assertion comes FIRST and is what makes the absence mean
      // anything: it is the half that proves this hook still scanned and still
      // recorded, so the pulled rule is missing because it was dropped rather
      // than because nothing ran. Without it the check below passes on an empty
      // list, which is exactly what it did before this control was added.
      const recent = await after.findings.recentFindings({ limit: 50 });
      expect(recent.map((f) => f.ruleId)).toContain(BUNDLED_RULE_ID);
      expect(recent.map((f) => f.ruleId)).not.toContain('e2e-worker/marker');
    } finally {
      after.close();
    }
  });
});

// The host env, read once so the child spawn inherits PATH/node while pointing
// the home dir at a throwaway. Overriding the home is the only way to redirect
// ~/.aka — the scripts must not (and do not) hard-resolve it.
function processEnv(): NodeJS.ProcessEnv {
  // eslint-disable-next-line n/no-process-env -- an e2e spawn of the real scripts needs the host PATH
  return process.env;
}
