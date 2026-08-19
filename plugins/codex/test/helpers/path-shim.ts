import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  copyFileSync,
  mkdtempSync,
  readdirSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { delimiter, join } from 'node:path';

/**
 * A controlled executable placed first on a child's PATH, so a suite driving a
 * BUILT script can fake the external command that script shells out to.
 *
 * This is the only way to fake such a command: the spawns live behind a process
 * boundary (`triage/judge.ts`'s `spawnClaude`, `provenance.ts`'s npm runner),
 * so their dependency-injection seams are in-process only and unreachable from
 * a test that runs the real built script.
 *
 * ## The shim fails OPEN, which is why every user of it must probe first
 *
 * A shim that does not land is NOT an `ENOENT`. Resolution simply continues
 * down the rest of PATH and finds the REAL installed binary — measured on a
 * POSIX host by joining PATH with the wrong separator, which resolved and ran
 * the real `claude`, returning that live binary's own error. For a judge stub
 * that means a suite quietly making a live model call with its seeded hits on
 * stdin; a sentinel checked afterwards reports the egress rather than
 * preventing it.
 *
 * So a caller asserts resolution BEFORE it drives anything —
 * `assertShimResolves` — and a failure there is a red setup, never a live call.
 *
 * ## Four ways a hand-rolled shim is POSIX-only
 *
 * 1. **Separator.** PATH is `:`-joined on POSIX and `;`-joined on Windows. A
 *    `:`-joined PATH on Windows is one malformed entry, so the shim dir is not
 *    on PATH at all. `shimmedPath` uses `path.delimiter`.
 * 2. **Extension.** An extensionless file with a `#!` line is executable on
 *    POSIX and unrunnable on Windows, which resolves a bare command name
 *    through `PATHEXT`. `writeCommandShim` writes a `.cmd` launcher there.
 * 3. **Mode bits.** `chmodSync(…, 0o755)` is a no-op on Windows, so a shim that
 *    relies on it has no executable bit to rely on. It is skipped there.
 * 4. **Where the launcher looks for its script.** `%~dp0` reads as "the
 *    directory this batch file is in" and is not that: `%0` holds the name AS
 *    TYPED, so for a batch cmd.exe resolved from PATH under a bare name it
 *    expands against the CURRENT DIRECTORY. `writeCommandShim` writes an
 *    absolute path instead.
 *
 * ## What ELSE the child's PATH reaches
 *
 * A POSIX shim's `#!/usr/bin/env node` line needs node on the child's PATH, and
 * the obvious way to put it there — `dirname(process.execPath)` — puts node's
 * SIBLINGS there too. Under nvm, or any prefix node shares with its global
 * installs, that is where `npm i -g` writes its bin shims, so the real `aka`
 * (or `claude`, `codex`, `agy`) rides in beside the interpreter and a suite
 * whose subject is "the command is not there" finds it. `nodeOnlyDir` is the
 * dir to use instead: the interpreter alone, and nothing that lives beside it.
 *
 * Shared by this package's suites because they sit behind one package wall.
 * Across a wall it cannot be imported, so `plugins/claude-code`,
 * `plugins/antigravity` and `packages/local-ops` carry peer copies — each taking a
 * `path-shim.test.ts` with it, or `assertShimResolves` can be weakened back
 * into a no-op with every caller staying green.
 */

/**
 * The argument the resolution probe sends.
 *
 * Deliberately `--version` rather than a bespoke flag: when resolution has
 * FAILED, the probe itself is what lands on the real binary, and `--version` is
 * the one argument every candidate here answers locally, from its own package
 * metadata, without contacting a model or a registry. A bespoke flag would be
 * rejected — usually harmlessly — by an argument parser this repo does not own.
 */
export const SHIM_PROBE_ARG = '--version';

/**
 * Whether a shim written by {@link writeCommandShim} needs a shell to be reached
 * at all on this platform.
 *
 * A win32 shim is a `.cmd` launcher, and libuv's own executable search tries
 * `.com` and `.exe` and stops — so a shell-free spawn cannot reach one, however
 * correctly it was written. This is a property of the ARTIFACT this module
 * writes, which is why it lives here rather than being re-derived by each
 * caller; a caller standing in for shipped code should read its subject's own
 * plan instead (see `planBareCommand`).
 */
export const SHIM_NEEDS_SHELL = process.platform === 'win32';

/**
 * The Windows system bits a child needs before a shelled spawn works at all,
 * for a caller that builds its child env from scratch rather than inheriting.
 *
 * `cmd.exe` and the `where.exe` a plan resolves with both live under System32,
 * and Node reads the interpreter's own location out of COMSPEC. A scrubbed env
 * carries none of them, so the child cannot spawn even a stub the caller wrote
 * itself. Opt in explicitly — this module will not widen a caller's env behind
 * its back, because the narrowness of that env is usually the point.
 *
 * Both are empty off win32.
 */
// eslint-disable-next-line n/no-process-env -- Windows reaches a .cmd only via System32 + COMSPEC
const HOST_ENV = process.env;
export const WINDOWS_SYSTEM_DIRS: readonly string[] =
  SHIM_NEEDS_SHELL && HOST_ENV.SystemRoot !== undefined
    ? [join(HOST_ENV.SystemRoot, 'System32'), HOST_ENV.SystemRoot]
    : [];
export const WINDOWS_SYSTEM_ENV: NodeJS.ProcessEnv = SHIM_NEEDS_SHELL
  ? {
      // Read case-insensitively on win32 by Node's own env proxy, so the OS's
      // stored casing (`SystemRoot`, `ComSpec`) does not have to be guessed.
      SystemRoot: HOST_ENV.SystemRoot,
      windir: HOST_ENV.windir,
      COMSPEC: HOST_ENV.COMSPEC,
      // cmd.exe defaults this when unset, but a child env that carries it is one
      // fewer thing between a `.cmd` and being found.
      PATHEXT: HOST_ENV.PATHEXT,
    }
  : {};

/**
 * How long the probe may take before the resolved binary is force-killed.
 *
 * Deliberately well under the 20s `testTimeout` every plugin package sets: the
 * probe runs inside a test body, so a deadline equal to vitest's own means
 * vitest wins the race and the refusal below — the entire point of failing
 * closed — is replaced by a bare "test timed out". A binary that has not
 * answered `--version` in ten seconds is not going to.
 */
const PROBE_TIMEOUT_MS = 10_000;

/** The token a shim prints for {@link SHIM_PROBE_ARG}, and nothing else does. */
export function shimMarker(command: string): string {
  return `AKA-TEST-SHIM-OK:${command}`;
}

/**
 * The prologue every shim body is written behind: the shebang and strict-mode
 * directive a POSIX shim needs, then the probe answer.
 *
 * The probe is answered FIRST — ahead of any sentinel write or argv parsing —
 * so probing can never be mistaken for an invocation by a suite asserting the
 * command was not spawned.
 */
function shimPrologue(command: string): string {
  return `#!/usr/bin/env node
'use strict';
// Answer the harness's resolution probe before doing anything else, so a probe
// is never recorded as an invocation.
if (process.argv.slice(2).includes(${JSON.stringify(SHIM_PROBE_ARG)})) {
  process.stdout.write(${JSON.stringify(shimMarker(command))});
  process.exit(0);
}
`;
}

/**
 * `basePath` with `binDir` prepended, joined the way the RUNNING platform joins
 * PATH. A literal `':'` here is the first of the four POSIX-only defects
 * above.
 *
 * An absent or empty `basePath` yields the bin dir ALONE, with no trailing
 * separator: an empty PATH entry is read as the current directory by execvp and
 * by libuv's own search, so the convenient-looking `${binDir}${delimiter}` would
 * quietly add the working directory to a search path whose whole purpose is that
 * only the shim is on it.
 */
export function shimmedPath(binDir: string, basePath: string | undefined): string {
  return basePath ? `${binDir}${delimiter}${basePath}` : binDir;
}

/** The name a POSIX shim's `#!/usr/bin/env node` line looks the interpreter up under. */
export const NODE_BIN = process.platform === 'win32' ? 'node.exe' : 'node';

export interface NodeOnlyPathOptions extends NodeOnlyDirOptions {
  /**
   * The platform to decide FOR, defaulting to the running one. Present so both
   * branches are drivable from either host, exactly as `writeCommandShim`'s is.
   */
  readonly platform?: NodeJS.Platform;
}

export interface NodeOnlyDirOptions {
  /**
   * The link attempt, `symlinkSync` by default. Exists so the copy fallback is
   * reachable from a host that grants symlinks — the way `writeCommandShim`
   * takes a `platform` — rather than only on a Windows account without the
   * privilege, which is where no suite would ever see it fail.
   */
  readonly symlink?: (target: string, path: string) => void;
}

/**
 * A fresh directory under `parent` holding this process's own node and NOTHING
 * else, for a child PATH that must reach a POSIX shim's shebang without reaching
 * whatever lives beside the interpreter.
 *
 * `dirname(process.execPath)` is not that. Under nvm — or any prefix node shares
 * with its global installs — `npm i -g` puts its bin shims beside the binary, so
 * a PATH carrying node's own dir for the shebang's sake carries a real `aka` too,
 * and the "genuinely not there" case then finds it. Measured: the dashboard
 * launcher's negative case resolved `~/.nvm/versions/node/<v>/bin/aka`, started
 * a real detached dashboard server, and only then failed on the message.
 *
 * A symlink where the platform grants one, a copy where it does not (a file
 * symlink on Windows needs a privilege an ordinary account may lack); either way
 * only the interpreter is reachable through the dir. Created with `mkdtempSync`
 * so it is empty by construction rather than by a check, and under a directory
 * the CALLER owns, so it rides the caller's own cleanup.
 */
export function nodeOnlyDir(parent: string, options: NodeOnlyDirOptions = {}): string {
  const dir = mkdtempSync(join(parent, 'node-only-'));
  const target = join(dir, NODE_BIN);
  try {
    (options.symlink ?? symlinkSync)(process.execPath, target);
  } catch {
    // Deliberately unconditional, and worth naming because the fallback is not
    // cheap — it writes the whole interpreter. What it is FOR is a filesystem
    // that grants writes but not links (a link needs a privilege on Windows,
    // and some network and non-native mounts have no symlinks at all). What it
    // also swallows is an EACCES or ENOENT on `dir` itself, which is not a link
    // problem — but the copy then fails on the same directory and throws, so
    // the real fault still surfaces rather than being converted into a pass.
    copyFileSync(process.execPath, target);
    // A no-op on Windows; on POSIX, the executable bit the shebang needs, held
    // here rather than trusted to what the copy preserved.
    chmodSync(target, 0o755);
  }
  return dir;
}

/**
 * Whether a shim written by {@link writeCommandShim} resolves its INTERPRETER
 * through the child's PATH.
 *
 * Only a POSIX shim does: it is a `#!/usr/bin/env node` script, and `env` walks
 * PATH for the name. The win32 shim is a `.cmd` that names `process.execPath`
 * outright, so nothing there looks `node` up at all. A property of the ARTIFACT
 * this module writes, kept beside {@link SHIM_NEEDS_SHELL} for the same reason:
 * a caller re-deriving it would be guessing at output it does not produce.
 *
 * Takes a `platform` for the reason {@link writeCommandShim} does: the branch
 * that matters here is the win32 one, and a constant read off the running host
 * can only ever be checked against itself — `process.platform !== 'win32'` on a
 * POSIX runner asserts `true === true`, so replacing the whole decision with
 * `true` stays green everywhere the suite actually runs.
 */
export const shimNeedsNodeOnPath = (platform: NodeJS.Platform = process.platform): boolean =>
  platform !== 'win32';

/** {@link shimNeedsNodeOnPath} for the running platform. */
export const SHIM_NEEDS_NODE_ON_PATH = shimNeedsNodeOnPath();

/**
 * The PATH entries a caller must add so a shim written by
 * {@link writeCommandShim} can reach its interpreter — one {@link nodeOnlyDir}
 * where the shebang needs one, and NOTHING on win32, where nothing reads it.
 *
 * Empty rather than symmetric on purpose. Materialising the interpreter costs
 * a link where the platform grants one and a copy of the whole binary — tens of
 * megabytes — where it does not, and Windows is exactly the platform that may
 * refuse the link (a file symlink needs a privilege an ordinary account and an
 * un-elevated runner may both lack). So the symmetric version pays the most
 * expensive form of this on the leg that can least afford it, for a shebang
 * that is never read: this suite is a peer copy in three plugins, `launcherEnv`
 * is called more than once each, and the Windows leg is already the slowest
 * one here.
 *
 * Spread into the PATH list, so a caller that stops needing one changes nothing
 * else:
 *
 * ```ts
 * shimmedPath(binDir, [...nodeOnlyPathEntries(parent), ...WINDOWS_SYSTEM_DIRS].join(delimiter))
 * ```
 */
export function nodeOnlyPathEntries(parent: string, options: NodeOnlyPathOptions = {}): string[] {
  return shimNeedsNodeOnPath(options.platform) ? [nodeOnlyDir(parent, options)] : [];
}

export interface CommandAbsenceOptions {
  /**
   * The working directory the spawn being stood in for will use, when it is not
   * this process's own.
   *
   * The axis {@link ShimResolutionOptions.cwd} exists for, in the direction that
   * fails SILENTLY. Windows searches the working directory before it walks PATH
   * — `cmd.exe` does, and so does the `where.exe` lookup inside
   * `planBareCommand` — so a real `command.cmd` sitting there is resolved
   * without PATH being consulted at all, and proving absence over PATH alone
   * reports a premise this check never established. That is not hypothetical for
   * the launcher: its Windows plan anchors the spawn at `homedir()` rather than
   * inheriting the caller's cwd, which is precisely where a user's own tools
   * land.
   *
   * Ignored on POSIX, where resolution never consults the cwd, so a call site
   * passes `plan.options.cwd` straight through without a platform branch of its
   * own.
   */
  readonly cwd?: string;
  /**
   * The platform whose resolution rules to apply. Defaults to the running one.
   *
   * A seam for the reason {@link shimNeedsNodeOnPath} takes one: the branch that
   * matters here is the win32 one, and gating it on a constant read off the
   * running host leaves it unreachable from every runner this suite is actually
   * run on. It decides the cwd rule ALONE — `env.PATH` is still split on the
   * running platform's delimiter, because that is the host that built it.
   */
  readonly platform?: NodeJS.Platform;
}

/**
 * Refuse unless NO directory the platform would search holds anything the bare
 * name `command` could resolve to — every entry on `env.PATH`, and on win32 the
 * caller's `cwd` ahead of them.
 *
 * The mirror of {@link assertShimResolves}, for the case whose subject is that
 * a command is absent: that premise has to be PROVEN, because a miss does not
 * fail closed. Resolution keeps walking PATH and finds the developer's real
 * installed CLI, so the case under test drives a live binary — for the dashboard
 * launcher, that means a real detached server on the machine running the suite,
 * started before any assertion can say why.
 *
 * Decided by LISTING rather than by spawning, so the check can never start the
 * thing it is looking for. The match is deliberately wide — `command` plus any
 * `command.*`, covering a `.cmd`, a `.exe` and the extensionless launcher an
 * npm global install writes — because over-refusing names a file to go and look
 * at, while under-refusing runs it.
 *
 * An entry nothing can resolve THROUGH is not a hit, and there are two of them:
 * one that does not exist (ENOENT) and one that is a regular FILE where a
 * directory was expected (ENOTDIR). `execvp` and libuv skip both and keep
 * walking, so refusing on either would report a resolution this PATH cannot
 * perform. A read that fails for any OTHER reason is rethrown rather than
 * swallowed: a directory that exists and cannot be read — a POSIX `--x`, where
 * `execvp` happily runs a known name inside it while `readdir` refuses — is a
 * premise this check could not establish, which is the one thing it must not
 * report as established.
 */
export function assertCommandNotOnPath(
  env: NodeJS.ProcessEnv,
  command: string,
  options: CommandAbsenceOptions = {},
): void {
  const lower = command.toLowerCase();
  const prefix = `${lower}.`;
  // The cwd goes FIRST because that is the order resolution uses, so a refusal
  // names the entry that would actually have won.
  const searched: { readonly dir: string; readonly source: string }[] = [
    ...((options.platform ?? process.platform) === 'win32' && options.cwd !== undefined
      ? [
          {
            dir: options.cwd,
            source: "the spawn's own working directory, which Windows searches BEFORE PATH",
          },
        ]
      : []),
    ...(env.PATH ?? '').split(delimiter).map((dir) => ({ dir, source: 'this PATH' })),
  ];
  for (const { dir, source } of searched) {
    if (dir === '') continue;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'ENOENT' || code === 'ENOTDIR') continue;
      throw e;
    }
    const hit = names.find((name) => {
      const name_ = name.toLowerCase();
      return name_ === lower || name_.startsWith(prefix);
    });
    if (hit !== undefined) {
      throw new Error(
        `a real "${command}" is reachable from ${source}: ${join(dir, hit)}. This is a SETUP ` +
          'failure, not a result: driving the case from here would resolve that binary instead ' +
          "of the stub, so the case would exercise the developer's own installed CLI. The PATH " +
          'must carry only the shim dir, the interpreter dir where one is needed and (win32) the ' +
          "system dirs — never node's own bin dir, which under a shared install prefix is where " +
          '`npm i -g` puts its shims too.',
      );
    }
  }
}

/**
 * Write `body` into `binDir` as something the platform will execute for the
 * bare name `command`, and return the file a caller would name in an error.
 *
 * POSIX gets the extensionless file the `#!` line makes runnable. Windows gets
 * the body as a plain `.js` beside a `<command>.cmd` launcher that runs it
 * under this process's own node — an absolute interpreter path, so the launcher
 * does not additionally depend on node being on the child's PATH.
 *
 * `platform` defaults to the running one and exists so both branches are
 * reachable from either host, the way `triage/judge.ts`'s `judgeEnv` takes one.
 * Writing the other platform's form is a resolution failure on this one, which
 * is what lets a POSIX runner drive the win32 branch against the real refusal
 * rather than against a description of it.
 */
export function writeCommandShim(
  binDir: string,
  command: string,
  body: string,
  platform: NodeJS.Platform = process.platform,
): string {
  const source = shimPrologue(command) + body;
  if (platform === 'win32') {
    const scriptPath = join(binDir, `${command}-shim.js`);
    writeFileSync(scriptPath, source);
    const launcherPath = join(binDir, `${command}.cmd`);
    // CRLF, because a batch file is read by cmd.exe. %* forwards argv, and
    // stdin passes through untouched.
    //
    // The script is named by ABSOLUTE path, not via %~dp0, and the difference
    // is what made every shim-driven suite fail on Windows. %0 holds the batch
    // file's name AS TYPED, and cmd.exe resolved this one from PATH under a
    // bare name — so %~dp0 expands that name against the CURRENT DIRECTORY
    // rather than against the directory the batch file actually sits in. The
    // spawn under test is anchored at the user's home, so `%~dp0<cmd>-shim.js`
    // resolved to a path in the home dir that nothing ever wrote, and node
    // answered `Cannot find module`. An absolute path has no such dependency.
    writeFileSync(launcherPath, `@echo off\r\n"${process.execPath}" "${scriptPath}" %*\r\n`);
    // No chmod: it is a no-op on Windows, and PATHEXT decides what runs.
    return launcherPath;
  }
  const shimPath = join(binDir, command);
  writeFileSync(shimPath, source);
  chmodSync(shimPath, 0o755);
  return shimPath;
}

export interface ShimResolutionOptions {
  /**
   * Mirror the spawn this shim stands in for. Pass `true` wherever the code
   * under test spawns with `shell` — on Windows that is the difference between
   * resolving a `.cmd` and skipping it, so a probe that disagrees with its
   * subject is a false verdict in one direction or the other.
   */
  readonly shell?: boolean;
  /**
   * The working directory the spawn being stood in for will use, when it is not
   * this process's own.
   *
   * PATH is not the whole of resolution: Windows searches the working directory
   * BEFORE walking PATH, so a probe run from a different cwd than its subject
   * verifies a resolution the subject never performs — and a binary sitting in
   * the subject's cwd wins silently. Pass whatever `cwd` reaches the real spawn.
   */
  readonly cwd?: string;
}

/**
 * Refuse to continue unless the bare name `command` resolves to the shim under
 * `env.PATH`.
 *
 * Resolution is not modelled, it is PERFORMED — the probe spawns the command
 * the same way the code under test will, so it agrees about `PATHEXT` and about
 * every other rule a hand-rolled resolver would have to restate. `options.shell`
 * and `options.cwd` are the axes the CALLER must supply, because they belong to
 * the spawn being stood in for rather than to the shim, and the probe cannot
 * discover either: get one wrong and the probe faithfully performs a resolution
 * its subject never performs.
 *
 * Throws — loudly, and naming the cause — rather than returning a boolean: a
 * caller that forgets to check a boolean is back to the fail-open behaviour
 * this exists to remove.
 */
export function assertShimResolves(
  command: string,
  env: NodeJS.ProcessEnv,
  options: ShimResolutionOptions = {},
): void {
  const marker = shimMarker(command);
  // Assigned on both paths below — the success value, or the failed spawn's own
  // stdout, which may still carry the marker.
  let output: string;
  let spawnFailure: string | undefined;
  try {
    output = execFileSync(command, [SHIM_PROBE_ARG], {
      env,
      encoding: 'utf8',
      timeout: PROBE_TIMEOUT_MS,
      killSignal: 'SIGKILL',
      stdio: ['ignore', 'pipe', 'pipe'],
      shell: options.shell ?? false,
      ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    });
  } catch (err) {
    // Narrowed rather than `unknown`: an unknown here stringifies to
    // [object Object] instead of the fields a reader needs.
    const e = err as {
      code?: string;
      status?: number;
      signal?: string;
      stdout?: string;
      stderr?: string;
    };
    // A non-zero exit still carries both streams, and stdout may hold the marker
    // — a shim that answered and then failed for its own reasons has resolved,
    // which is the only question being asked here. Reading it is what keeps a
    // real resolution from being reported as a miss.
    output = e.stdout ?? '';
    const status = e.status === undefined ? '(none)' : String(e.status);
    // stderr is the only thing that explains a genuine failure, so it belongs in
    // the one message written to diagnose one.
    const stderr = (e.stderr ?? '').trim();
    spawnFailure =
      `code=${e.code ?? '(none)'} status=${status} signal=${e.signal ?? '(none)'}` +
      (stderr === '' ? '' : ` stderr=${JSON.stringify(stderr.slice(0, 200))}`);
  }
  if (output.includes(marker)) return;

  const sawInstead =
    spawnFailure !== undefined
      ? `the spawn failed (${spawnFailure})`
      : `it answered ${JSON.stringify(output.trim().slice(0, 120))}`;
  throw new Error(
    [
      `PATH shim for "${command}" did not resolve to the test stub — ${sawInstead}.`,
      'This is a SETUP failure and the suite must not continue: a shim that does',
      'not land does NOT fail closed. Resolution carries on down PATH and finds',
      `the REAL installed "${command}", so driving the chain from here would make`,
      'a live call with the seeded fixtures as its input.',
      'On Windows the usual cause is that execFile does no PATHEXT resolution and',
      'refuses to spawn a .cmd/.bat without a shell (the CVE-2024-27980 fix) — see',
      "packages/local-ops/src/exec.ts's USE_SHELL for the same constraint in",
      'shipped code. On POSIX, check the shim is executable and that PATH was',
      'joined with path.delimiter.',
    ].join(' '),
  );
}
