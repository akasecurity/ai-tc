/**
 * How to spawn a command by BARE NAME so it works on Windows without turning a
 * broken feature into an execution vector.
 *
 * Three separate facts have to be handled together, and every one of them has
 * bitten this repo already:
 *
 *  1. **libuv does not do PATHEXT.** Its own search tries `.com` and `.exe` and
 *     nothing else, so a shell-free `execFileSync('claude', …)` never sees the
 *     `claude.cmd` an npm global install actually puts on PATH. The spawn fails
 *     with ENOENT — not with a message about batch files — which reads exactly
 *     like "the CLI is not installed". Handing the name to a shell is the usual
 *     way round it, and is what `packages/local-ops/src/exec.ts` does.
 *
 *  2. **Windows searches the working directory BEFORE PATH.** So the moment a
 *     shell is involved, a `claude.cmd` sitting in a cloned repo runs instead of
 *     the real CLI. Every Windows spawn here is therefore anchored in the user's
 *     home directory; nothing spawned through this module depends on the
 *     caller's cwd. POSIX PATH lookup never consults the cwd, so no anchor is
 *     needed — and none is added, because changing cwd there would be a
 *     behaviour change nobody asked for.
 *
 *  3. **A shell re-parses the argument vector.** Node joins `[file, ...args]`
 *     with a single space and hands the result to `cmd.exe` VERBATIM — it says
 *     so itself, in DEP0190: "the arguments are not escaped, only concatenated".
 *     So `shell: true` alone is not a fix, it is a command-injection surface
 *     wherever an argument carries content this repo did not choose. The
 *     Antigravity judge was exactly that case until its prompt moved to stdin,
 *     which is the real fix wherever a host offers one — this module is what
 *     covers an argument that still has to ride argv.
 *
 * What this module does about (3) is refuse rather than hope. On the shell path
 * every argument is quoted here, the whole command line is passed as a single
 * pre-joined string (which is also why DEP0190 never fires), and an argument
 * carrying something a double-quoted `cmd.exe` argument cannot survive is a
 * thrown {@link BareCommandUnsupportedError}, never a best-effort escape.
 *
 * The shell is also skipped entirely whenever it can be: a bare name that
 * resolves to a real executable is spawned by absolute path with no shell at
 * all, which removes the injection surface, the 8 KiB command-line ceiling and
 * the extra `cmd.exe` process in one step. A CLI installed from the binary
 * channel (`aka.exe`) takes that path.
 *
 * Reachable from every plugin, including the dashboard launcher, which is why
 * this is its own module with no heavy imports rather than part of the package
 * index: the launcher bundle must not pull in the detection packs.
 */
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';
import { win32 } from 'node:path';

/**
 * `cmd.exe`'s command-line ceiling. A longer line is truncated rather than
 * refused, so it must be checked rather than attempted. The direct-executable
 * path is bounded by `CreateProcessW`'s 32,767 instead and is not checked here.
 */
export const CMD_LINE_MAX = 8191;

/**
 * What Node puts in front of the quoted line before `cmd.exe` ever sees it:
 * `<COMSPEC> /d /s /c "<line>"`. It counts against the same 8,191 ceiling, so a
 * line measured on its own passes this check at 8,190 characters and is then
 * TRUNCATED by cmd.exe — which is the silent corruption the refusal exists to
 * prevent. The interpreter path is the variable part
 * (`C:\WINDOWS\system32\cmd.exe` is 27 characters, and Node reads it from
 * COMSPEC); 64 leaves room for a longer one plus the ` /d /s /c ` and the two
 * quotes.
 */
const CMD_WRAPPER_ALLOWANCE = 64;

/**
 * The extensions `CreateProcessW` can load as an image on its own.
 *
 * An ALLOWLIST, not a `.cmd`/`.bat` denylist, and the difference is the whole
 * npm case: a global install writes an EXTENSIONLESS launcher (a Bourne script,
 * for Git Bash) beside the shim, and `where` prints it FIRST —
 * `…\npm\aka` before `…\npm\aka.cmd`. A denylist calls that first line directly
 * executable and hands a shell script to CreateProcessW, which fails ENOEXEC —
 * a different code from the ENOENT callers test for, so it reads as "installed"
 * and the spawn then does nothing at all. Anything not listed here (a shim, a
 * `.ps1`, an extensionless launcher) goes through the shell, where cmd.exe
 * applies PATHEXT and finds the `.cmd` itself.
 */
const DIRECT_EXTENSIONS: ReadonlySet<string> = new Set(['.exe', '.com']);

/**
 * What a double-quoted `cmd.exe` argument cannot carry.
 *
 * Everything absent from this list — `& | < > ^ ( ) ; , ' \`` and whitespace —
 * is literal inside double quotes and needs no escaping, which is what keeps
 * the list this short. Each entry names a character CLASS and never a value:
 * these reasons reach a user-facing error, and the argument they describe may
 * be a live credential.
 */
const CMD_HAZARDS: readonly (readonly [string, string])[] = [
  ['"', 'a double quote, which would close the quoted argument'],
  ['%', 'a percent sign, which cmd.exe expands inside quotes and re-parses'],
  ['!', 'an exclamation mark, which cmd.exe expands when delayed expansion is on'],
  ['\r', 'a carriage return, which a Windows command line cannot carry'],
  ['\n', 'a line break, which a Windows command line cannot carry'],
  ['\0', 'a NUL byte'],
];

/** `\`, compared by code unit so the trailing-run scan allocates nothing. */
const BACKSLASH = 0x5c;

/** The error code a refused argv carries, so a caller can recognise it. */
export const BARE_COMMAND_ERROR_CODE = 'ERR_AKA_WINDOWS_ARGV';

/**
 * A bare-name spawn that cannot be performed on this host.
 *
 * `reason` is raw-free BY CONSTRUCTION — it names the argv index and the
 * character class that made the argument unusable, never the argument. That
 * matters because a refused argument is by definition one this repo did not
 * choose the content of, so it may itself be a raw scanned value.
 */
export class BareCommandUnsupportedError extends Error {
  readonly code = BARE_COMMAND_ERROR_CODE;
  readonly reason: string;

  constructor(reason: string) {
    super(`cannot spawn this command on Windows: ${reason}`);
    this.name = 'BareCommandUnsupportedError';
    this.reason = reason;
  }
}

/** Whether `err` is this module's refusal, narrowed so `reason` can be read. */
export function isBareCommandUnsupported(err: unknown): err is BareCommandUnsupportedError {
  return (
    typeof err === 'object' &&
    err !== null &&
    (err as { code?: unknown }).code === BARE_COMMAND_ERROR_CODE &&
    typeof (err as { reason?: unknown }).reason === 'string'
  );
}

/**
 * Why `args` cannot cross `cmd.exe`, or `undefined` when they can.
 *
 * Pure, so both branches are driven from any host. The message names the argv
 * INDEX rather than the value — see {@link BareCommandUnsupportedError}.
 */
export function cmdLineHazard(command: string, args: readonly string[]): string | undefined {
  for (const [index, arg] of [command, ...args].entries()) {
    for (const [char, why] of CMD_HAZARDS) {
      if (arg.includes(char)) {
        // Index 0 is the command name itself; report it as such rather than as
        // "argument -1" or by shifting every other index by one.
        const where = index === 0 ? 'the command name' : `argument ${String(index)}`;
        return `${where} contains ${why}`;
      }
    }
  }
  // Measured WITH the interpreter prefix Node adds, because that is the line
  // cmd.exe is handed and the ceiling applies to the whole of it.
  const length = quoteCommandLine(command, args).length + CMD_WRAPPER_ALLOWANCE;
  if (length > CMD_LINE_MAX) {
    return `the command line is ${String(length)} characters once cmd.exe's own prefix is counted, over its ${String(CMD_LINE_MAX)}`;
  }
  return undefined;
}

/**
 * One argument, quoted for the `cmd.exe` line Node builds.
 *
 * The trailing-backslash run is doubled because the CHILD's own argument parser
 * reads `\"` as an escaped quote: without it, `"C:\dir\"` reaches the child as
 * `C:\dir"` and the next argument is swallowed. Embedded quotes need no rule
 * here — {@link cmdLineHazard} has already refused them.
 *
 * Counted BACKWARDS from the end rather than matched with `/\\*$/`, and the
 * difference is quadratic. An unanchored `\\*$` restarts at every position, and
 * at each one it consumes the whole remaining run before `$` fails, so a value
 * carrying a long backslash run that is NOT at the end costs O(n²): 64k
 * backslashes followed by one other character measured 1,431 ms against 0.0000
 * ms for this loop. Nothing upstream bounds that length — {@link cmdLineHazard}
 * derives its ceiling FROM the quoted line, so the quoting is already paid for
 * by the time the refusal fires. This walks the trailing run once and touches
 * nothing before it.
 */
export function quoteForCmd(value: string): string {
  let runStart = value.length;
  while (runStart > 0 && value.charCodeAt(runStart - 1) === BACKSLASH) runStart -= 1;
  const trailingBackslashes = value.slice(runStart);
  const body = value.slice(0, runStart);
  return `"${body}${trailingBackslashes}${trailingBackslashes}"`;
}

/** The whole command line, quoted argument by argument. */
export function quoteCommandLine(command: string, args: readonly string[]): string {
  return [command, ...args].map(quoteForCmd).join(' ');
}

/**
 * How long `where.exe` may take before the answer is given up on.
 *
 * A PATH entry pointing at an unreachable network share makes that search block
 * for as long as the OS takes to give up, and this runs in front of a launcher
 * whose whole job is to return at once — ahead, too, of the judge's own 180s
 * spawn timeout, which cannot bound something that has not spawned yet. A
 * resolver that never answers is strictly worse than one that answers
 * `undefined`, which only falls back to the shell.
 */
const RESOLVE_TIMEOUT_MS = 5_000;

/**
 * Resolve a bare name to the file Windows would actually run, honouring
 * PATHEXT.
 *
 * Performed rather than modelled: `where.exe` is a real executable (so it needs
 * no shell of its own) and it searches in the same order cmd.exe does, which a
 * hand-rolled PATH walk would have to restate and would get wrong. Anchored at
 * `home` for the same reason every other spawn here is — `where` searches the
 * working directory first too, so an unanchored probe would happily report a
 * planted shim.
 *
 * The probe BINARY is resolved absolutely where the environment allows it (see
 * {@link systemWhere}), so the resolver is not itself decided by the search
 * order it exists to describe.
 *
 * Returns the FIRST line only, which is the one cmd.exe would pick; what that
 * line can be spawned as is {@link isDirectlyExecutable}'s question, not this
 * one's.
 *
 * Best effort: an unresolvable name yields `undefined` and the caller falls
 * back to letting the shell report it.
 */
/**
 * Absolute path to the system `where.exe`, or `undefined` when the environment
 * does not say where Windows is installed.
 *
 * This module's whole thesis is that Windows searches the working directory
 * before PATH — and the resolver is itself spawned by bare name, so it is
 * subject to the rule it exists to defeat. A `where.exe` in the anchor directory
 * would win the lookup and then get to answer every question asked of it. The
 * home anchor already makes that a far weaker position than a cloned repo
 * (planting there means write access to `$HOME`), so this is hardening rather
 * than a fix — but naming the file outright costs the same and leaves nothing in
 * the path depending on a search order.
 *
 * Looked up case-INSENSITIVELY. Windows' own case-insensitive `process.env` is a
 * Node proxy that a spread copy does not preserve: `{ ...process.env }` is a
 * plain object keyed however the OS spelled it, and callers here pass exactly
 * such a copy (`judgeEnv`). A lookup for the canonical `SystemRoot` alone would
 * therefore miss a perfectly valid environment and silently fall back.
 *
 * An ABSENT `env` reads `process.env` rather than giving up. A caller that
 * passes none gets a child that inherits this process's environment, so that is
 * exactly the environment the later spawn will search — resolving against
 * anything else would describe a lookup nobody performs. Without it the three
 * plugin dashboard launchers, which pass no env, were the only callers left on
 * the bare name: the ones a user triggers from a slash command in whatever
 * directory they happen to be in, while the consent-gated judges were hardened.
 *
 * Falls back to the bare name when the variable is absent from BOTH, which is
 * where this started — no worse than before, and still anchored.
 */
export function systemWhere(env: NodeJS.ProcessEnv | undefined): string | undefined {
  for (const [key, value] of Object.entries(env ?? process.env)) {
    if (key.toLowerCase() !== 'systemroot') continue;
    if (typeof value !== 'string' || value.trim() === '') return undefined;
    return win32.join(value, 'System32', 'where.exe');
  }
  return undefined;
}

export function resolveWindowsCommand(
  command: string,
  env: NodeJS.ProcessEnv | undefined,
  home: string,
): string | undefined {
  try {
    const probe = spawnSync(systemWhere(env) ?? 'where', [command], {
      encoding: 'utf8',
      cwd: home,
      windowsHide: true,
      timeout: RESOLVE_TIMEOUT_MS,
      ...(env === undefined ? {} : { env }),
    });
    if (probe.status !== 0 || typeof probe.stdout !== 'string') return undefined;
    // `where` prints every match, best first, one per line.
    const first = probe.stdout.split(/\r?\n/).find((line) => line.trim() !== '');
    return first?.trim();
  } catch {
    return undefined;
  }
}

/** Whether `file` can be handed straight to CreateProcess, no interpreter. */
export function isDirectlyExecutable(file: string): boolean {
  // win32.extname rather than the platform default: this only ever classifies a
  // Windows path, and POSIX extname reads `\` as an ordinary character — so
  // `C:\Users\a.dev\npm\aka` comes back with an extension of `.dev\npm\aka`
  // everywhere this is unit-tested.
  return DIRECT_EXTENSIONS.has(win32.extname(file).toLowerCase());
}

export interface BareCommandDeps {
  /** Host platform. A parameter so both branches run on every runner. */
  readonly platform?: NodeJS.Platform;
  /** The env the child will get — the resolver must search the same PATH. */
  readonly env?: NodeJS.ProcessEnv | undefined;
  /** The anchor directory; defaults to the user's home. */
  readonly home?: string;
  /** Resolution seam, so the win32 branches are drivable from POSIX. */
  readonly resolve?: (
    command: string,
    env: NodeJS.ProcessEnv | undefined,
    home: string,
  ) => string | undefined;
}

export interface BareCommandPlan {
  /** What to pass as `execFileSync`/`spawnSync`'s first argument. */
  readonly file: string;
  /** What to pass as its second. Empty on the shell path — see `viaShell`. */
  readonly args: readonly string[];
  /**
   * Spread LAST over the caller's own options, so the Windows cwd anchor wins
   * over a cwd the caller merely inherited.
   */
  readonly options: { readonly shell?: true; readonly cwd?: string };
  /** Whether a command interpreter is in the middle of this spawn. */
  readonly viaShell: boolean;
  /** What the bare name resolved to on Windows, when anything did. */
  readonly resolved: string | undefined;
}

/**
 * Build the spawn a bare command name needs on this platform.
 *
 * POSIX is unchanged and deliberately so: the name goes through as-is, with no
 * shell and no cwd of our own. Windows takes one of two paths — the resolved
 * executable directly when that is possible, and a quoted `cmd.exe` line when
 * the name only resolves to a batch shim.
 *
 * Throws {@link BareCommandUnsupportedError} when the shell path is the only
 * one available and the argv cannot survive it. That is a refusal, not a
 * fallback: the alternative is a shell line assembled from content the caller
 * does not control.
 */
export function planBareCommand(
  command: string,
  args: readonly string[],
  deps: BareCommandDeps = {},
): BareCommandPlan {
  const platform = deps.platform ?? process.platform;
  if (platform !== 'win32') {
    return { file: command, args, options: {}, viaShell: false, resolved: undefined };
  }

  const home = deps.home ?? homedir();
  const resolve = deps.resolve ?? resolveWindowsCommand;
  const resolved = resolve(command, deps.env, home);

  // A real executable needs no interpreter, so it gets none: no re-parsed argv,
  // no 8 KiB ceiling, and no cmd.exe left sitting in the process tree holding a
  // detached child.
  if (resolved !== undefined && isDirectlyExecutable(resolved)) {
    return { file: resolved, args, options: { cwd: home }, viaShell: false, resolved };
  }

  const hazard = cmdLineHazard(command, args);
  if (hazard !== undefined) {
    // Two different situations reach the shell path, and the refusal must not
    // conflate them: a name that resolved to something no interpreter-free
    // spawn can run, and a name that resolved to NOTHING — where the shell was
    // only ever going to report the miss. Saying "resolves only to a batch
    // shim" in the second case asserts something false about a machine where
    // the command is simply not installed.
    const why =
      resolved === undefined
        ? `${command} did not resolve to an executable, so it could only be run through cmd.exe`
        : `${command} resolves only to a batch shim, which must be run through cmd.exe`;
    throw new BareCommandUnsupportedError(`${why}, and ${hazard}`);
  }

  // The pre-joined line is passed as the FILE with no args, so Node has nothing
  // to concatenate unescaped (DEP0190) — the quoting above is the only quoting.
  return {
    file: quoteCommandLine(command, args),
    args: [],
    options: { shell: true, cwd: home },
    viaShell: true,
    resolved,
  };
}
