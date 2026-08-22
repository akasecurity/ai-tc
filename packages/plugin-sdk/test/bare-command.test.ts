import { homedir } from 'node:os';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  BARE_COMMAND_ERROR_CODE,
  BareCommandUnsupportedError,
  CMD_LINE_MAX,
  cmdLineHazard,
  isBareCommandUnsupported,
  isDirectlyExecutable,
  planBareCommand,
  quoteCommandLine,
  quoteForCmd,
  resolveWindowsCommand,
  systemWhere,
} from '../src/bare-command.ts';

// A stand-in home, distinct from the real one so an assertion about the anchor
// cannot pass merely because the runner happens to sit under $HOME.
const HOME = '/anchor/home';

// Resolution seams. The real one shells out to `where.exe`, which exists on no
// runner this suite runs on, so every win32 case supplies its own — the point
// under test is what the PLAN does with an answer, not how the answer is found.
const resolvesTo = (path: string) => (): string => path;
const resolvesNothing = (): undefined => undefined;

// A stand-in for the Antigravity judge prompt: multi-line, high-entropy, and
// nothing a detection rule matches — this repo is public, so a fixture must not
// be credential-shaped even where the code under test treats it as one.
const RAW_PROMPT = ['# Rubric', '', 'zQ7fLp2XvB9nR4tKmH6sWdY3jC8gAe5U', '', '## Hits'].join('\n');

describe('planBareCommand — POSIX is left alone', () => {
  it('passes the bare name through with no shell and no cwd of its own', () => {
    const plan = planBareCommand('claude', ['-p', '--output-format', 'json'], {
      platform: 'linux',
      home: HOME,
    });

    expect(plan).toEqual({
      file: 'claude',
      args: ['-p', '--output-format', 'json'],
      options: {},
      viaShell: false,
      resolved: undefined,
    });
  });

  it('never refuses an argv POSIX can carry, however hostile to cmd.exe', () => {
    // Every character cmd.exe cannot survive is inert in a POSIX argv, because
    // no shell ever sees it. Refusing here would break the platform that works.
    const plan = planBareCommand('agy', ['-p', RAW_PROMPT], { platform: 'darwin', home: HOME });

    expect(plan.args).toEqual(['-p', RAW_PROMPT]);
    expect(plan.viaShell).toBe(false);
  });
});

describe('planBareCommand — Windows, resolved to a real executable', () => {
  it('spawns the absolute path with no interpreter in the middle', () => {
    const plan = planBareCommand('aka', ['dashboard', '--port', '5000'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\Program Files\aka\aka.exe`),
    });

    expect(plan.file).toBe(String.raw`C:\Program Files\aka\aka.exe`);
    expect(plan.args).toEqual(['dashboard', '--port', '5000']);
    expect(plan.viaShell).toBe(false);
    expect(plan.options.shell).toBeUndefined();
  });

  it('carries an argv cmd.exe could never carry, because cmd.exe is not involved', () => {
    // This is the whole reason the direct path exists: an argv handed straight
    // to CreateProcess is never re-parsed, so a raw-bearing argument crosses it
    // intact. A plan that routed this through a shell would be an injection.
    // The `-p <prompt>` spelling below is a hostile-argv FIXTURE, not a product
    // call — no judge in this repo puts its prompt on argv any more.
    const plan = planBareCommand('agy', ['-p', RAW_PROMPT, '--output-format', 'json'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\agy\agy.exe`),
    });

    expect(plan.args).toEqual(['-p', RAW_PROMPT, '--output-format', 'json']);
    expect(plan.viaShell).toBe(false);
  });

  it('anchors the spawn at home even though no shell is involved', () => {
    // Windows searches the working directory before PATH for libuv's own lookup
    // too, so dropping the anchor here would still let a planted binary win.
    const plan = planBareCommand('aka', ['--help'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\aka\aka.exe`),
    });

    expect(plan.options.cwd).toBe(HOME);
  });
});

describe('planBareCommand — Windows, only a batch shim to reach', () => {
  it('routes through a shell, quoting the line itself rather than handing Node args', () => {
    // Node concatenates [file, ...args] unescaped when `shell` is set — it says
    // so in DEP0190 — so the quoting has to happen here and the args array has
    // to be empty, or Node re-joins on top of it.
    const plan = planBareCommand('claude', ['-p', '--output-format', 'json'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\Users\dev\AppData\Roaming\npm\claude.cmd`),
    });

    expect(plan.viaShell).toBe(true);
    expect(plan.options.shell).toBe(true);
    expect(plan.args).toEqual([]);
    expect(plan.file).toBe('"claude" "-p" "--output-format" "json"');
  });

  it('anchors the spawn at home, so a planted claude.cmd in the cwd is not reached', () => {
    const plan = planBareCommand('claude', ['-p'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\npm\claude.cmd`),
    });

    expect(plan.options.cwd).toBe(HOME);
  });

  it('still routes through a shell when nothing resolved, so the shell reports it', () => {
    const plan = planBareCommand('aka', ['--help'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesNothing,
    });

    expect(plan.viaShell).toBe(true);
    expect(plan.resolved).toBeUndefined();
  });

  it('treats .bat exactly as .cmd', () => {
    const plan = planBareCommand('codex', ['exec'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\tools\codex.BAT`),
    });

    expect(plan.viaShell).toBe(true);
  });

  it('routes the EXTENSIONLESS npm launcher through the shell too', () => {
    // What `where aka` actually answers first on a machine with a global npm
    // install: the Bourne script npm writes for Git Bash, not the `.cmd` beside
    // it. CreateProcessW cannot load it, so the plan must not take the direct
    // path — cmd.exe applies PATHEXT and reaches the `.cmd` itself.
    const plan = planBareCommand('aka', ['dashboard'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\Users\dev\AppData\Roaming\npm\aka`),
    });

    expect(plan.viaShell).toBe(true);
    expect(plan.file).toBe('"aka" "dashboard"');
    // Still RESOLVED, though: the caller's "is it installed?" question was
    // answered yes, and only the way to reach it changed.
    expect(plan.resolved).toBe(String.raw`C:\Users\dev\AppData\Roaming\npm\aka`);
  });
});

describe('planBareCommand — refusing an argv cmd.exe cannot carry', () => {
  // Each entry is a character that survives nothing, paired with the phrase the
  // refusal must use for it. Driven as a table so a hazard silently dropped from
  // the list fails here rather than being discovered on a user's machine.
  const hazards: readonly (readonly [string, string, string])[] = [
    ['double quote', 'a"b', 'a double quote'],
    ['percent sign', 'a%PATH%b', 'a percent sign'],
    ['exclamation mark', 'a!PATH!b', 'an exclamation mark'],
    ['carriage return', 'a\rb', 'a carriage return'],
    ['line break', 'a\nb', 'a line break'],
    ['NUL byte', 'a\0b', 'a NUL byte'],
  ];

  it.each(hazards)('refuses %s', (_name, value, phrase) => {
    const call = (): unknown =>
      planBareCommand('agy', ['-p', value], {
        platform: 'win32',
        home: HOME,
        resolve: resolvesTo(String.raw`C:\agy\agy.cmd`),
      });

    expect(call).toThrow(BareCommandUnsupportedError);
    const err = errorFrom(call);
    expect(isBareCommandUnsupported(err)).toBe(true);
    expect((err as BareCommandUnsupportedError).reason).toContain(phrase);
  });

  it('refuses a line over cmd.exe’s ceiling', () => {
    const long = 'a'.repeat(CMD_LINE_MAX);
    const err = errorFrom(() =>
      planBareCommand('agy', ['-p', long], {
        platform: 'win32',
        home: HOME,
        resolve: resolvesTo(String.raw`C:\agy\agy.cmd`),
      }),
    );

    expect(isBareCommandUnsupported(err)).toBe(true);
    expect((err as BareCommandUnsupportedError).reason).toContain(String(CMD_LINE_MAX));
  });

  it('counts the interpreter prefix Node adds, not just the line it quotes', () => {
    // Node spawns `<COMSPEC> /d /s /c "<line>"`, and the 8,191 ceiling applies
    // to the whole of that. A check measuring only `<line>` passes just under
    // the ceiling and cmd.exe then TRUNCATES — silently, which is the one
    // outcome this refusal exists to prevent. So the boundary is asserted from
    // BELOW: a line that fits with room to spare is still allowed, and one that
    // fits only without the prefix is not.
    const quotedOverhead = quoteCommandLine('agy', ['-p', '']).length;
    const justUnder = 'a'.repeat(CMD_LINE_MAX - quotedOverhead - 200);
    const onlyFitsBare = 'a'.repeat(CMD_LINE_MAX - quotedOverhead);

    expect(cmdLineHazard('agy', ['-p', justUnder])).toBeUndefined();
    expect(cmdLineHazard('agy', ['-p', onlyFitsBare])).toContain(String(CMD_LINE_MAX));
    // The control that keeps the case above honest: without the prefix the
    // second line measures at or under the ceiling, so a checker that ignored
    // the prefix would report no hazard for it.
    expect(quoteCommandLine('agy', ['-p', onlyFitsBare]).length).toBeLessThanOrEqual(CMD_LINE_MAX);
  });

  it('says the name did not resolve, rather than claiming a batch shim that is not there', () => {
    // Nothing resolved here, so "resolves only to a batch shim" would assert
    // something false about a machine where the command is simply absent — and
    // the dashboard launcher shows this reason to the user verbatim.
    const err = errorFrom(() =>
      planBareCommand('agy', ['-p', RAW_PROMPT], {
        platform: 'win32',
        home: HOME,
        resolve: resolvesNothing,
      }),
    );

    expect(isBareCommandUnsupported(err)).toBe(true);
    const { reason } = err as BareCommandUnsupportedError;
    expect(reason).toContain('agy did not resolve to an executable');
    expect(reason).not.toContain('batch shim');
    // The hazard itself is still named — the wording changed, not the answer.
    expect(reason).toContain('a line break');
  });

  it('names the argv INDEX and the character class, and echoes no part of the value', () => {
    // The refused argument on the one host that reaches this branch IS the
    // raw-bearing judge prompt, and this reason reaches the parent command's
    // stderr. An exact match is the assertion, not an absence check: an absence
    // check passes on an empty string, and this one cannot.
    const err = errorFrom(() =>
      planBareCommand('agy', ['-p', RAW_PROMPT, '--output-format', 'json'], {
        platform: 'win32',
        home: HOME,
        resolve: resolvesTo(String.raw`C:\agy\agy.cmd`),
      }),
    );

    expect(isBareCommandUnsupported(err)).toBe(true);
    expect((err as BareCommandUnsupportedError).reason).toBe(
      'agy resolves only to a batch shim, which must be run through cmd.exe, and ' +
        'argument 2 contains a line break, which a Windows command line cannot carry',
    );
  });

  it('reports the command name as such rather than as an argument', () => {
    expect(cmdLineHazard('bad"name', [])).toContain('the command name');
    expect(cmdLineHazard('agy', ['ok', 'bad"arg'])).toContain('argument 2');
  });

  it('carries a recognisable code, so a caller can tell a refusal from a spawn failure', () => {
    const err = errorFrom(() =>
      planBareCommand('agy', ['-p', RAW_PROMPT], {
        platform: 'win32',
        home: HOME,
        resolve: resolvesTo(String.raw`C:\agy\agy.cmd`),
      }),
    );

    expect((err as { code?: unknown }).code).toBe(BARE_COMMAND_ERROR_CODE);
    expect(isBareCommandUnsupported(new Error('something else'))).toBe(false);
    expect(isBareCommandUnsupported(undefined)).toBe(false);
  });

  it('never refuses when the executable resolved directly — the hazard is cmd.exe’s', () => {
    // The control for the table above. Without it, a planner that refused every
    // Windows argv would satisfy every refusal case in this describe block.
    const plan = planBareCommand('agy', ['-p', 'a"b%c!d\ne'], {
      platform: 'win32',
      home: HOME,
      resolve: resolvesTo(String.raw`C:\agy\agy.exe`),
    });

    expect(plan.args).toEqual(['-p', 'a"b%c!d\ne']);
  });
});

describe('quoteForCmd', () => {
  it('keeps an argument with spaces as one argument', () => {
    expect(quoteForCmd(String.raw`C:\Users\John Smith\Temp\out.txt`)).toBe(
      String.raw`"C:\Users\John Smith\Temp\out.txt"`,
    );
  });

  it('doubles a trailing backslash run so the closing quote is not escaped away', () => {
    // The child's own argument parser reads \" as an escaped quote, so a single
    // trailing backslash would swallow the quote and then the next argument.
    // Written with escapes rather than String.raw: a raw literal cannot END in a
    // backslash, which is exactly the shape under test.
    expect(quoteForCmd('C:\\dir\\')).toBe('"C:\\dir\\\\"');
    expect(quoteForCmd('C:\\dir\\\\')).toBe('"C:\\dir\\\\\\\\"');
  });

  it('leaves an interior backslash alone', () => {
    expect(quoteForCmd(String.raw`C:\dir\file`)).toBe(String.raw`"C:\dir\file"`);
  });

  it('quotes an empty argument so it survives as an argument at all', () => {
    expect(quoteForCmd('')).toBe('""');
  });

  it('leaves the metacharacters that are literal inside quotes untouched', () => {
    // & | < > ^ ( ) are inert inside a double-quoted cmd.exe argument, which is
    // what keeps the refusal list as short as it is. Escaping them here as well
    // would corrupt the value the child receives.
    expect(quoteForCmd('a&b|c<d>e^f(g)h')).toBe('"a&b|c<d>e^f(g)h"');
  });

  it('joins the whole line one quoted argument at a time', () => {
    expect(quoteCommandLine('codex', ['exec', String.raw`C:\tmp\a b\out.txt`])).toBe(
      String.raw`"codex" "exec" "C:\tmp\a b\out.txt"`,
    );
  });

  // The trailing run is found by counting backwards, and the alternative that
  // reads more naturally — /\\*$/ — is QUADRATIC on the one input shape this
  // function is most likely to be handed a lot of: a long backslash run that is
  // not at the end. Unanchored, the pattern restarts at every position and
  // consumes the whole remaining run before `$` fails.
  //
  // Nothing upstream bounds the length. cmdLineHazard's 8,191-character ceiling
  // looks like one and is not: it is derived FROM the quoted line, so the
  // quoting is already paid for by the time the refusal fires.
  it('scales linearly in the length of a backslash run it cannot match', () => {
    // A RATIO, not a budget. The quotient cancels the runner — half the machine
    // halves both sides — where an absolute ceiling on a shared CI box measures
    // preemption. Copying the value is genuinely linear, so a linear
    // implementation doubles (~2) and a backtracking one quadruples (~4); 3
    // separates them with room on both sides.
    const cost = (n: number): number => {
      const value = '\\'.repeat(n) + 'a';
      // Fastest of 5. Noise only ever ADDS time, so the minimum is the estimator
      // a loaded runner cannot inflate — a p95 here would measure the neighbours.
      let best = Infinity;
      for (let i = 0; i < 5; i += 1) {
        const started = process.cpuUsage();
        quoteForCmd(value);
        const spent = process.cpuUsage(started);
        best = Math.min(best, spent.user + spent.system);
      }
      return best;
    };

    // Warm the function so the first measured call is not paying for its own
    // compilation, which would land on whichever size ran first.
    cost(1_000);

    const small = cost(50_000);
    const large = cost(100_000);

    // The backstop, asserted unconditionally. A ratio is blind to a constant
    // factor and division needs something to divide, so this carries the case
    // on its own: copying 100k characters is microseconds, while the
    // backtracking form measured ~3,500,000us at this size. Four orders of
    // magnitude of headroom, and still 7x under the defect.
    expect(large).toBeLessThan(500_000);

    // The scaling half, which catches a regression that stays under the
    // backstop. Skipped only where the clock is too coarse to divide — and
    // measuring below the floor at 100k is itself incompatible with
    // backtracking, so nothing is waved through by the branch.
    const FLOOR_US = 200;
    if (large >= FLOOR_US) expect(large / Math.max(small, 1)).toBeLessThan(3);
  });
});

describe('isDirectlyExecutable', () => {
  it('accepts what CreateProcess can load as an image, case-insensitively', () => {
    expect(isDirectlyExecutable(String.raw`C:\x\aka.exe`)).toBe(true);
    expect(isDirectlyExecutable(String.raw`C:\x\aka.EXE`)).toBe(true);
    expect(isDirectlyExecutable(String.raw`C:\x\aka.com`)).toBe(true);
  });

  it('rejects the shims an interpreter has to run, case-insensitively', () => {
    expect(isDirectlyExecutable(String.raw`C:\x\claude.cmd`)).toBe(false);
    expect(isDirectlyExecutable(String.raw`C:\x\claude.CMD`)).toBe(false);
    expect(isDirectlyExecutable(String.raw`C:\x\claude.Bat`)).toBe(false);
    expect(isDirectlyExecutable(String.raw`C:\x\claude.ps1`)).toBe(false);
  });

  it('rejects the EXTENSIONLESS launcher an npm global install writes', () => {
    // The case an allowlist exists for. `where aka` prints this line BEFORE
    // `aka.cmd` on a machine with a global npm install, so a denylist of
    // `.cmd`/`.bat` takes it, calls it directly executable, and hands a Bourne
    // script to CreateProcessW — which fails ENOEXEC, a DIFFERENT code from the
    // ENOENT `akaMissing` tests for. The launcher then reports the CLI as
    // installed and starts nothing at all.
    expect(isDirectlyExecutable(String.raw`C:\Users\dev\AppData\Roaming\npm\aka`)).toBe(false);
  });

  it('reads the extension as WINDOWS does, whatever host this runs on', () => {
    // node:path's default extname is the host's, and POSIX extname treats `\`
    // as an ordinary character — so this path's extension is `.dev\npm\aka`
    // there, and any classifier built on it answers about a string that is not
    // an extension. Every case in this file runs on such a host.
    expect(isDirectlyExecutable(String.raw`C:\Users\a.dev\npm\aka`)).toBe(false);
    expect(isDirectlyExecutable(String.raw`C:\Users\a.dev\npm\aka.exe`)).toBe(true);
  });
});

describe('resolveWindowsCommand', () => {
  it('answers undefined rather than throwing when where.exe is not there', () => {
    // The POSIX runners this suite runs on have no `where.exe`, so this is the
    // fallback path: a resolver that threw would take the whole plan with it.
    expect(resolveWindowsCommand('definitely-not-a-real-command', undefined, homedir())).toBe(
      undefined,
    );
  });

  it('is what planBareCommand reaches for when no seam is supplied', () => {
    // Nothing resolves on this host, so the plan must land on the shell branch —
    // which is only reachable through the default resolver having been called.
    const plan = planBareCommand('definitely-not-a-real-command', ['--help'], {
      platform: 'win32',
      home: homedir(),
    });

    expect(plan.viaShell).toBe(true);
    expect(plan.resolved).toBeUndefined();
  });
});

describe('systemWhere — the resolver is not itself decided by a search order', () => {
  const SYSTEM32_WHERE = 'C:\\Windows\\System32\\where.exe';

  // systemWhere reads process.env when the caller passes none, so a stub that
  // outlived its test would decide the answer for every case below it — and on
  // a Windows runner it would be overriding a real SystemRoot.
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('names where.exe absolutely so a planted copy cannot answer for it', () => {
    // The point of the whole module is that Windows searches the cwd first. A
    // resolver spawned by bare name is subject to that rule too, so the file it
    // runs is pinned rather than searched for.
    expect(systemWhere({ SystemRoot: 'C:\\Windows' })).toBe(SYSTEM32_WHERE);
  });

  it('finds SystemRoot whatever case the environment spelled it in', () => {
    // `{ ...process.env }` is a plain object: Node's case-insensitive env proxy
    // does not survive the spread, and `judgeEnv` passes exactly such a copy. A
    // lookup for the canonical spelling alone would miss a valid environment and
    // silently fall back to the bare name.
    for (const key of ['SystemRoot', 'SYSTEMROOT', 'systemroot', 'SystemROOT']) {
      expect(systemWhere({ [key]: 'C:\\Windows' }), key).toBe(SYSTEM32_WHERE);
    }
  });

  it('falls back to the bare name rather than building a nonsense path', () => {
    // Each of these would produce a path that resolves to nothing if joined
    // blindly — `undefined` is what routes the caller back to the bare name,
    // which is where this started and is no worse than it was.
    expect(systemWhere({})).toBe(undefined);
    expect(systemWhere({ SystemRoot: '' })).toBe(undefined);
    expect(systemWhere({ SystemRoot: '   ' })).toBe(undefined);
    expect(systemWhere({ SystemRoot: undefined })).toBe(undefined);
  });

  it('reads process.env when the caller passes none, since that is what the spawn inherits', () => {
    // The three plugin dashboard launchers call planBareCommand with no deps,
    // so an absent env used to route them straight back to the bare name — the
    // callers a user triggers from a slash command in an arbitrary directory,
    // left un-hardened while the consent-gated judges were not. A caller that
    // passes no env gets a child inheriting THIS process's, so resolving
    // against process.env describes the lookup the spawn actually performs.
    vi.stubEnv('SystemRoot', 'C:\\Windows');
    expect(systemWhere(undefined)).toBe(SYSTEM32_WHERE);
  });

  it('still yields the bare name when neither the caller nor the process says', () => {
    // The fallback is to process.env, not to a guess: an environment that names
    // no SystemRoot is the one case that legitimately reaches `?? 'where'`.
    vi.stubEnv('SystemRoot', '');
    expect(systemWhere(undefined)).toBe(undefined);
  });

  it('prefers an explicit env over process.env rather than merging them', () => {
    // A caller that passes an env is describing the child's environment
    // exactly; reading the ambient one as well would resolve against a
    // variable the spawn will not have.
    vi.stubEnv('SystemRoot', 'C:\\Ambient');
    expect(systemWhere({ SystemRoot: 'C:\\Windows' })).toBe(SYSTEM32_WHERE);
    expect(systemWhere({})).toBe(undefined);
  });

  it('is reached by resolveWindowsCommand rather than being dead code', () => {
    // Nothing is asserted about the RESULT here — this suite runs on POSIX,
    // where no `where.exe` exists either way. What is asserted is that passing a
    // SystemRoot does not throw and does not change the fallback answer, i.e.
    // the absolute-path branch is executed rather than skipped.
    expect(
      resolveWindowsCommand(
        'definitely-not-a-real-command',
        { SystemRoot: 'C:\\Windows' },
        homedir(),
      ),
    ).toBe(undefined);
  });
});

// The error a thunk threw, captured OUTSIDE its own catch: a `try { fn();
// throw new Error('expected') } catch (e) { … }` asserts on the test's own
// guard error whenever the subject stops throwing.
function errorFrom(fn: () => unknown): unknown {
  try {
    fn();
  } catch (err) {
    return err;
  }
  return undefined;
}
