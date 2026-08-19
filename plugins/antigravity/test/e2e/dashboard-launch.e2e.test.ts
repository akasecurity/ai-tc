/**
 * The dashboard launcher's WIRING, which only the built script can show.
 *
 * `src/dashboard.ts` is an entry script: top-level code, no exported seam. Its
 * two pure halves are unit-tested next door (`dashboard-launch.test.ts` covers
 * `akaMissing` and the two messages, `bare-command.test.ts` covers the plan),
 * and BOTH can stay green while the script wires them together wrongly — probing
 * one shape and spawning another, or dropping `...plan.options` and losing the
 * Windows cwd anchor with it. That seam is a process boundary, so nothing short
 * of running the real script reaches it.
 *
 * So this drives `scripts/dashboard.js` against a controlled `aka` on PATH and
 * reads back what the launcher actually spawned. The stub records its own argv
 * and cwd, which is what turns "it printed a URL" into "it reached the CLI, with
 * these arguments, from the directory the plan chose".
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { planBareCommand } from '@akasecurity/plugin-sdk/bare-command';
import { afterEach, describe, expect, it } from 'vitest';

import { INSTALL_HINT } from '../../src/dashboard-launch.ts';
import {
  assertCommandNotOnPath,
  assertShimResolves,
  nodeOnlyPathEntries,
  shimmedPath,
  WINDOWS_SYSTEM_DIRS,
  WINDOWS_SYSTEM_ENV,
  writeCommandShim,
} from '../helpers/path-shim.ts';

// test/e2e -> plugins/antigravity
const PLUGIN_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const LAUNCHER = join(PLUGIN_ROOT, 'scripts', 'dashboard.js');

// The launcher spawns DETACHED and unrefs, then exits without waiting — so the
// stub's record appears after the parent has already returned. Poll for it
// rather than reading once; a single read is a race the fast machine wins and
// the loaded one loses.
//
// This and LAUNCHER_TIMEOUT_MS are both spent INSIDE a test body, on top of
// `assertShimResolves`'s own probe deadline, and each one has a diagnostic
// worth reaching: "the stub recorded 0 calls", or a spawn result to read. So
// CASE_TIMEOUT_MS is set above their sum — at the package's 20s default the
// three together overrun it and vitest wins the race, replacing every one of
// those diagnostics with a bare timeout that names none of them.
const RECORD_TIMEOUT_MS = 5_000;
const LAUNCHER_TIMEOUT_MS = 15_000;
const CASE_TIMEOUT_MS = 60_000;

// How long a poll sleeps between reads. Long enough not to spin a core for the
// whole window — this suite runs three times over (once per plugin) alongside
// the rest of a package's tests on a shared runner.
const POLL_INTERVAL_MS = 10;

const dirs: string[] = [];
const tempDir = (): string => {
  const dir = mkdtempSync(join(tmpdir(), 'aka-dashboard-e2e-'));
  dirs.push(dir);
  return dir;
};

afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() ?? '', { recursive: true, force: true });
});

interface Spawned {
  argv: string[];
  cwd: string;
}

// A controlled `aka` that records every call instead of starting a server.
//
// APPENDS rather than overwrites, because the launcher invokes it twice — once
// to probe, once to launch — and both are under test here. Overwriting made the
// first read return the PROBE's argv, which is a race the poll below cannot see
// through: a valid record is already there, just not the one being asked about.
//
// `assertShimResolves`'s own `--version` probe never reaches this body: the shim
// prologue answers and exits first, which is what keeps a resolution check from
// being counted as an invocation.
function writeAkaStub(binDir: string, recordPath: string): void {
  writeCommandShim(
    binDir,
    'aka',
    `require('node:fs').appendFileSync(${JSON.stringify(recordPath)}, JSON.stringify({
  argv: process.argv.slice(2),
  cwd: process.cwd(),
}) + '\\n');
`,
  );
}

// PATH carries the stub, a dir holding node ALONE where a shebang needs one (a
// POSIX shim resolves `node` by name — never what happens to live beside it,
// which under a shared install prefix is where `npm i -g` puts a real `aka`)
// and — on win32 only — the system dirs cmd.exe and where.exe are found
// through. Nothing else from the host: a real `aka` on the developer's PATH
// must not be reachable, since this suite's whole subject is which one gets
// spawned. `nodeOnlyPathEntries` is empty on win32, where the `.cmd` shim names
// its interpreter outright and materialising one would buy nothing.
function launcherEnv(binDir: string): NodeJS.ProcessEnv {
  return {
    ...WINDOWS_SYSTEM_ENV,
    PATH: shimmedPath(
      binDir,
      [...nodeOnlyPathEntries(tempDir()), ...WINDOWS_SYSTEM_DIRS].join(delimiter),
    ),
  };
}

function runLauncher(env: NodeJS.ProcessEnv, args: string[]): string {
  const result = spawnSync(process.execPath, [LAUNCHER, ...args], {
    env,
    encoding: 'utf8',
    timeout: LAUNCHER_TIMEOUT_MS,
  });
  return result.stdout;
}

// Sleep, synchronously, without burning a core. `Atomics.wait` is the only
// synchronous sleep Node has; the alternative is a `Date.now()` spin, which
// pegs a CPU for the whole poll window and starves the suites sharing the
// runner. Off the main thread it would be the same call, so no branch is needed.
function sleep(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

// Every complete call the stub has recorded so far, once there are at least
// `want` of them. A partially-flushed last line parses as invalid JSON and is
// simply not counted yet, so a short read is waited out rather than reported as
// a malformed spawn.
function readCalls(recordPath: string, want: number): Spawned[] {
  const deadline = Date.now() + RECORD_TIMEOUT_MS;
  let calls: Spawned[] = [];
  while (Date.now() < deadline) {
    if (existsSync(recordPath)) {
      calls = readFileSync(recordPath, 'utf8')
        .split('\n')
        .flatMap((line) => {
          if (line.trim() === '') return [];
          try {
            return [JSON.parse(line) as Spawned];
          } catch {
            return [];
          }
        });
      if (calls.length >= want) return calls;
    }
    sleep(POLL_INTERVAL_MS);
  }
  throw new Error(
    `the aka stub recorded ${String(calls.length)} call(s) at ${recordPath}, wanted ${String(want)}`,
  );
}

describe('the built dashboard launcher', () => {
  it(
    'spawns the CLI it probed, with the forwarded flags and the plan’s cwd',
    () => {
      const binDir = tempDir();
      const recordPath = join(binDir, 'spawned.json');
      writeAkaStub(binDir, recordPath);
      const env = launcherEnv(binDir);

      // The plan the launcher itself will build. Read rather than re-derived: the
      // probe below has to mirror the launcher's spawn shape exactly, and it is
      // also what says which cwd the child should report.
      const plan = planBareCommand('aka', ['dashboard'], { env });
      // A shim that does not land is NOT an ENOENT — resolution walks the rest of
      // PATH. Here that would be a real `aka dashboard` starting a real server on
      // the developer's machine, so prove resolution before driving anything.
      assertShimResolves('aka', env, {
        shell: plan.viaShell,
        ...(plan.options.cwd === undefined ? {} : { cwd: plan.options.cwd }),
      });

      const stdout = runLauncher(env, ['--port', '5099', '--no-open']);

      // The user-facing half: the URL tracks the forwarded port.
      expect(stdout).toContain('http://localhost:5099/security');
      expect(stdout).not.toContain('npm i -g');

      // The half no unit test can reach: what was actually spawned.
      //
      // HOW MANY spawns there are is a property of the plan, not a constant.
      // `akaMissing` returns `plan.resolved === undefined` outright on the shell
      // path and never runs its probe there — a `.cmd` shim cannot answer a
      // shell-free ENOENT probe, and asking through a second cmd.exe would cost
      // a process to learn what the plan already knows. So the Windows shim leg
      // records ONE call and every other leg records two. Asserting two
      // unconditionally is a POSIX assumption, and it read as `recorded 1 call(s),
      // wanted 2` on Windows CI.
      const probed = !plan.viaShell;
      const calls = readCalls(recordPath, probed ? 2 : 1);
      const launch = calls[probed ? 1 : 0];

      if (probed) {
        // The probe asked the same `aka` the launch then ran, and asked it the one
        // question it is for. A launcher that probed a bare name of its own while
        // spawning the plan's would still print a URL and still start the server.
        const probe = calls[0];
        expect(probe?.argv).toEqual(['--help']);
        expect(probe?.cwd).toBe(plan.options.cwd ?? process.cwd());
      } else {
        // The shell leg's positive control: silence has to be the DOCUMENTED
        // silence. Without this the branch above is simply skipped there, and a
        // launcher that stopped probing on every platform would still pass.
        expect(calls).toHaveLength(1);
        expect(plan.resolved).toBeDefined();
      }

      // The flags reach the CLI untouched, in order.
      expect(launch?.argv).toEqual(['dashboard', '--port', '5099', '--no-open']);
      // The Windows cwd anchor, asserted against the plan rather than a platform
      // branch — so the POSIX leg checks the inherited cwd really is inherited and
      // the Windows leg checks the anchor really is applied.
      expect(launch?.cwd).toBe(plan.options.cwd ?? process.cwd());
    },
    CASE_TIMEOUT_MS,
  );

  it(
    'prints the install hint, and spawns nothing, when `aka` genuinely is not there',
    () => {
      // An empty bin dir: no stub, and neither the host PATH nor node's own bin
      // dir is inherited, so the name resolves nowhere. The case above is this
      // one's control — it shows the harness CAN see a spawn, so "no record"
      // here means none happened.
      const binDir = tempDir();
      const recordPath = join(binDir, 'spawned.json');
      const env = launcherEnv(binDir);
      // The plan the launcher itself will build, for the reason the positive
      // case reads one: PATH is not the whole of resolution. The win32 plan
      // anchors its spawn at `homedir()`, and both `cmd.exe` and the `where.exe`
      // lookup inside `planBareCommand` search that directory BEFORE PATH.
      const plan = planBareCommand('aka', ['dashboard'], { env });
      // Proven, not assumed: a real `aka` reachable from here would be spawned
      // for real, and this case would then fail on the message — after the
      // server was already running.
      assertCommandNotOnPath(env, 'aka', {
        ...(plan.options.cwd === undefined ? {} : { cwd: plan.options.cwd }),
      });

      const stdout = runLauncher(env, ['--no-open']);

      expect(stdout).toContain(INSTALL_HINT);
      expect(stdout).not.toContain('/security');
      expect(existsSync(recordPath)).toBe(false);
    },
    CASE_TIMEOUT_MS,
  );
});

describe('the launcher wiring the POSIX leg cannot observe', () => {
  // On POSIX the plan is deliberately a no-op — `file` is the bare name, options
  // are empty — so a launcher that probed a hardcoded `'aka'` with hardcoded
  // options behaves EXACTLY like one that used the plan, and the suite above
  // passes either way. Measured: replacing the probe with
  // `spawnSync('aka', [...probeArgs], { stdio: 'ignore' })` left both cases green.
  //
  // Only Windows can tell them apart, and only there does it matter — one shape
  // reaches a `.cmd` and the other cannot, so a mismatch is a false miss in one
  // direction and a false pass in the other. So the wiring is pinned as source
  // facts, which fail on the leg the author is actually running.
  const LAUNCHER_SOURCE = readFileSync(join(PLUGIN_ROOT, 'src', 'dashboard.ts'), 'utf8');
  const stale =
    'dashboard.ts no longer builds both the probe and the launch from one plan. On ' +
    'Windows that is a false "not installed" or a spawn the probe never checked. ' +
    'Restore it, or rewrite these cases to say what replaced it.';

  it('builds one plan and hands it to the probe', () => {
    expect(/\bplanBareCommand\(/.test(LAUNCHER_SOURCE), stale).toBe(true);
    expect(LAUNCHER_SOURCE.includes('akaMissing(plan,'), stale).toBe(true);
  });

  it('probes whatever the plan named, never a command name of its own', () => {
    expect(LAUNCHER_SOURCE.includes('spawnSync(file,'), stale).toBe(true);
    expect(LAUNCHER_SOURCE.includes("spawnSync('"), stale).toBe(false);
  });

  it('launches from the plan’s file and options, which is what carries the cwd anchor', () => {
    expect(LAUNCHER_SOURCE.includes('spawn(plan.file'), stale).toBe(true);
    expect(LAUNCHER_SOURCE.includes('...plan.options'), stale).toBe(true);
    expect(LAUNCHER_SOURCE.includes("spawn('"), stale).toBe(false);
  });
});
