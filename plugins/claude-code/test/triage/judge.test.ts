import type * as ChildProcess from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { TriageHit } from '@akasecurity/schema';
import { afterAll, afterEach, describe, expect, it, vi } from 'vitest';

import type { JudgeDeps } from '../../src/triage/judge.ts';
import {
  judgeEnv,
  parseVerdict,
  runJudge,
  spawnClaude,
  toJudgePayload,
} from '../../src/triage/judge.ts';

// No test in this file may reach a live model. EVERY child-process entry point
// node exposes is routed to one throwing spy, not just the execFileSync
// spawnClaude happens to use today: a guard bound to one function name goes
// vacuously green the moment the implementation reaches for spawnSync instead,
// which is the opposite of what a fail-closed guard is for.
const liveSpawn = vi.hoisted(() =>
  // Typed with the args it may receive (rather than declaring them) so the
  // recorded calls stay inspectable for the wiring test below.
  vi.fn<(...args: unknown[]) => never>(() => {
    throw new Error('a unit test must never spawn a live model');
  }),
);
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof ChildProcess>()),
  exec: liveSpawn,
  execFile: liveSpawn,
  execFileSync: liveSpawn,
  execSync: liveSpawn,
  fork: liveSpawn,
  spawn: liveSpawn,
  spawnSync: liveSpawn,
}));

// The guard for every test EXCEPT the one deliberate probe below, which drives
// spawnClaude into the spy on purpose to pin its call shape and clears the spy
// in a `finally` the moment it has asserted. Splitting the two is what lets the
// wiring be tested at all: a bare "never called" forbids the one test that
// proves the judge env reaches execFileSync.
afterAll(() => {
  expect(liveSpawn).not.toHaveBeenCalled();
});

afterEach(() => {
  vi.unstubAllEnvs();
});

// Temp dirs a test created itself (as opposed to ones judgeEnv minted), removed
// after each case whether or not the assertion under test passed.
const OWNED: string[] = [];
function ownedDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aka-judge-test-'));
  OWNED.push(dir);
  return dir;
}
afterEach(() => {
  while (OWNED.length > 0) rmSync(OWNED.pop() ?? '', { recursive: true, force: true });
});

// A raw value is absent from an error only if no RUN of it survives: a branch
// that echoed a truncated value would still hand a live credential's prefix to
// the parent command's stderr, and a whole-value `not.toContain` stays green on
// exactly that. Mirrors expectNoEchoOf in web-ui/test/actions/exceptions.test.ts.
const ECHO_RUN = 8;
function expectNoEchoOf(message: string | undefined, value: string): void {
  expect(message).toBeDefined();
  const haystack = message ?? '';
  for (let i = 0; i + ECHO_RUN <= value.length; i += 1) {
    expect(haystack).not.toContain(value.slice(i, i + ECHO_RUN));
  }
  if (value.length < ECHO_RUN) expect(haystack).not.toContain(value);
}

// Every value the env holds under `name`, whatever its casing. Windows' env
// block is case-INSENSITIVE but case-PRESERVING: `process.env.PATH` reads it,
// yet spreading process.env into a plain object (which judgeEnv does) can yield
// the key as `Path` there, so a bare `env.PATH` assertion reads undefined on a
// Windows runner. Matching every casing keeps the assertion about the value.
function envValues(env: NodeJS.ProcessEnv, name: string): (string | undefined)[] {
  return Object.keys(env)
    .filter((key) => key.toLowerCase() === name.toLowerCase())
    .map((key) => env[key]);
}

// A `claude -p --output-format json` envelope with `result` set to `text`.
const envelope = (text: string): string => JSON.stringify({ result: text, is_error: false });

const VERDICT_FENCE = [
  '```json',
  '{"perCategory":[{"category":"secret","action":"block","reasoning":"real","genuineCount":2,"fpCount":2,"fpIds":[]}],"notes":""}',
  '```',
].join('\n');

describe('parseVerdict', () => {
  it('unwraps the --output-format json envelope and parses the fenced verdict', () => {
    const rec = parseVerdict(envelope(`reasoning here...\n${VERDICT_FENCE}`));
    expect(rec.perCategory[0]?.action).toBe('block');
  });

  it('uses the LAST json fence when the result carries an earlier illustrative one', () => {
    const result = [
      'Here is the shape I will use:',
      '```json',
      '{"perCategory":[{"category":"secret","action":"warn","reasoning":"illustrative","genuineCount":0,"fpCount":0,"fpIds":[]}],"notes":""}',
      '```',
      'Now the real verdict:',
      VERDICT_FENCE,
    ].join('\n');
    expect(parseVerdict(envelope(result)).perCategory[0]?.reasoning).toBe('real');
  });

  it('throws when the envelope reports an error', () => {
    expect(() => parseVerdict(JSON.stringify({ is_error: true, result: 'boom' }))).toThrow();
  });

  it('never echoes the subprocess output in a failure (raw stays inside the judge)', () => {
    const raw = 'AKIAIOSFODNN7EXAMPLE';
    // A malformed envelope, a non-JSON envelope, and an unparseable result — all
    // carrying the raw value. None of the thrown messages may contain it.
    const cases = [
      JSON.stringify({ is_error: true, result: `failed near ${raw}` }),
      `not json at all ${raw}`,
      JSON.stringify({ is_error: false, result: `no fence here, just ${raw}` }),
    ];
    for (const stdout of cases) {
      try {
        parseVerdict(stdout);
        throw new Error('expected parseVerdict to throw');
      } catch (err) {
        expect((err as Error).message).not.toContain(raw);
      }
    }
  });
});

// The env judgeEnv() builds IS the transcript-suppression control: it is the
// only thing keeping the raw hits on stdin out of ~/.claude/projects, where the
// product's own scanner would later find them. Every branch is pinned here, and
// the platform is injected rather than read, so the darwin branch runs on every
// runner — CI has no macOS machine, and a `if (process.platform === 'darwin')`
// guard would mean these assertions execute nowhere.
describe('judgeEnv', () => {
  // Take the env, assert against it, then remove any dir it minted.
  function withEnv(platform: NodeJS.Platform, assert: (env: NodeJS.ProcessEnv) => void): void {
    const env = judgeEnv(platform);
    try {
      assert(env);
    } finally {
      if (platform === 'darwin' && env.CLAUDE_CONFIG_DIR) {
        rmSync(env.CLAUDE_CONFIG_DIR, { recursive: true, force: true });
      }
    }
  }

  it('sets both suppression vars on every platform', () => {
    // Cleared first so the assertion is about judgeEnv rather than about
    // whatever the developer running this happens to export.
    vi.stubEnv('CLAUDE_CODE_SKIP_PROMPT_HISTORY', undefined);
    vi.stubEnv('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', undefined);
    for (const platform of ['darwin', 'linux', 'win32'] as const) {
      withEnv(platform, (env) => {
        // The transcript suppressor: no prompt history written, auth preserved.
        expect(env.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');
        // Telemetry-off. Not a transcript guard, but part of the pinned pair.
        expect(env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC).toBe('1');
      });
    }
  });

  it('overrides a parent env that disables them', () => {
    // The override wins only because the spread comes FIRST in judgeEnv's
    // object literal. Move it to the end — the kind of tidy-up that reads as
    // harmless — and a parent carrying `0` wins instead: the child writes a
    // transcript, and the raw hits riding stdin land in ~/.claude/projects for
    // the product's own scanner to find. A parent that carries neither key (the
    // normal case, and CI) cannot catch that reorder, so seed both disabled.
    vi.stubEnv('CLAUDE_CODE_SKIP_PROMPT_HISTORY', '0');
    vi.stubEnv('CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', '0');
    for (const platform of ['darwin', 'linux', 'win32'] as const) {
      withEnv(platform, (env) => {
        expect(env.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');
        expect(env.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC).toBe('1');
      });
    }
  });

  it('does not override HOME — Linux keeps credentials under $HOME', () => {
    // Isolating HOME would look like stronger containment and would in fact
    // break auth on Linux, so the deliberate decision is pinned: whatever the
    // parent carries passes through byte-for-byte on every platform, including
    // the one that also gets a throwaway CLAUDE_CONFIG_DIR.
    const home = ownedDir();
    vi.stubEnv('HOME', home);
    for (const platform of ['darwin', 'linux', 'win32'] as const) {
      withEnv(platform, (env) => {
        expect(env.HOME).toBe(home);
        expect(env.HOME).not.toBe(env.CLAUDE_CONFIG_DIR);
      });
    }
  });

  it('inherits the rest of the parent env (PATH and auth reach the child)', () => {
    // The subprocess must find `claude` and authenticate — the isolation is of
    // the transcript, not of the environment. A future "harden it by building a
    // clean env" would break the spawn and is a regression, not an improvement.
    vi.stubEnv('AKA_JUDGE_ENV_PROBE', 'inherited');
    vi.stubEnv('PATH', '/probe/bin');
    withEnv('linux', (env) => {
      expect(env.AKA_JUDGE_ENV_PROBE).toBe('inherited');
      expect(envValues(env, 'PATH')).toContain('/probe/bin');
    });
  });

  it('mints a fresh, empty CLAUDE_CONFIG_DIR per call on darwin', () => {
    const first = judgeEnv('darwin').CLAUDE_CONFIG_DIR;
    const second = judgeEnv('darwin').CLAUDE_CONFIG_DIR;
    try {
      expect(first).toBeTruthy();
      expect(second).toBeTruthy();
      // Fresh per call: two concurrent judges never share config state.
      expect(first).not.toBe(second);
      for (const dir of [first, second]) {
        if (dir === undefined) throw new Error('darwin judgeEnv minted no CLAUDE_CONFIG_DIR');
        expect(statSync(dir).isDirectory()).toBe(true);
        expect(readdirSync(dir)).toEqual([]);
      }
    } finally {
      for (const dir of [first, second]) {
        if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
      }
    }
  });

  it('replaces an inherited CLAUDE_CONFIG_DIR on darwin rather than writing into it', () => {
    const real = ownedDir();
    vi.stubEnv('CLAUDE_CONFIG_DIR', real);
    withEnv('darwin', (env) => {
      expect(env.CLAUDE_CONFIG_DIR).toBeTruthy();
      expect(env.CLAUDE_CONFIG_DIR).not.toBe(real);
    });
    // The user's own config dir is untouched by the swap.
    expect(existsSync(real)).toBe(true);
  });

  it('leaves CLAUDE_CONFIG_DIR alone off darwin (the mkdtemp is darwin-only)', () => {
    // The non-darwin path deliberately does nothing here: an inherited value
    // passes through, and an absent one stays absent. Setting one off darwin
    // would point the child at an empty config dir and break its auth.
    const inherited = ownedDir();
    for (const platform of ['linux', 'win32'] as const) {
      vi.stubEnv('CLAUDE_CONFIG_DIR', inherited);
      expect(judgeEnv(platform).CLAUDE_CONFIG_DIR).toBe(inherited);

      vi.stubEnv('CLAUDE_CONFIG_DIR', undefined);
      expect(judgeEnv(platform).CLAUDE_CONFIG_DIR).toBeUndefined();
    }
  });
});

// -------------------------------------------------------------------------
// spawnClaude: what the production seam actually hands the child process
// -------------------------------------------------------------------------

// runJudge's tests assert what deps.spawn RECEIVES. This asserts what
// spawnClaude PASSES ON — the other half of the same boundary, and the half
// nothing covered. Drop `env` from the execFileSync options and every runJudge
// test stays green while the real child inherits the parent env instead: no
// suppression vars, a transcript written, raw secrets at rest in
// ~/.claude/projects. The journey harness drives this seam for real through a
// PATH shim, but reaching the shim does not depend on the env, so only a direct
// assertion on the call shape pins it.
describe('spawnClaude', () => {
  it('passes the judge env and the prompt on stdin to execFileSync', () => {
    const env = judgeEnv('linux');
    const argv = ['-p', '--no-session-persistence', '--output-format', 'json'] as const;
    try {
      // The spy throws by design; the call it recorded is what is under test.
      expect(() => spawnClaude(argv, env, 'RUBRIC + raw hits')).toThrow();

      const [call] = liveSpawn.mock.calls;
      if (call === undefined) throw new Error('spawnClaude reached no child-process function');
      const [file, args, opts] = call as [
        string,
        readonly string[],
        { env?: NodeJS.ProcessEnv; input?: string },
      ];

      expect(file).toBe('claude');
      expect(args).toEqual([...argv]);
      // Identity, not shape: the env judgeEnv built is the object handed over,
      // so no copy can drop a key on the way.
      expect(opts.env).toBe(env);
      expect(opts.env?.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');
      expect(opts.env?.CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC).toBe('1');
      // The prompt rides stdin and never argv — argv has an ARG_MAX ceiling and
      // is visible on the process list.
      expect(opts.input).toBe('RUBRIC + raw hits');
      expect(args.join(' ')).not.toContain('RUBRIC');
    } finally {
      // The one sanctioned call: cleared so the afterAll guard still speaks for
      // every other test in this file.
      liveSpawn.mockClear();
    }
  });
});

const hit: TriageHit = {
  ruleId: 'core-secret/aws',
  category: 'secret',
  severity: 'high',
  maskedMatch: 'A***Z',
  rawMatch: 'AKIAIOSFODNN7EXAMPLE',
  context: 'export KEY=AKIAIOSFODNN7EXAMPLE # prod',
  confidence: 0.9,
};

describe('runJudge', () => {
  it('spawns claude -p with --no-session-persistence + --output-format json, and the prompt on stdin', () => {
    let seenArgv: readonly string[] = [];
    let seenEnv: NodeJS.ProcessEnv = {};
    let seenStdin = '';
    const rec = runJudge([hit], {
      spawn: (argv, env, stdin) => {
        seenArgv = argv;
        seenEnv = env;
        seenStdin = stdin;
        return envelope(VERDICT_FENCE);
      },
      loadRubric: () => 'RUBRIC BODY',
    });

    expect(seenArgv).toEqual(['-p', '--no-session-persistence', '--output-format', 'json']);
    // rawMatch rides on stdin — the rubric judges the actual value;
    // SKIP_PROMPT_HISTORY + --no-session-persistence keep it out of any
    // transcript, and stdin (unlike argv) keeps it off the process list and out
    // of ARG_MAX. filePath is dropped and context is masked before it crosses
    // (covered below), so rawMatch is the only raw field that leaves.
    expect(seenStdin).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(seenStdin).toContain('RUBRIC BODY');
    expect(seenEnv.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');

    expect(rec.perCategory[0]?.action).toBe('block');
  });

  it('drops filePath from the judge payload (it encodes the OS username and project dirs)', () => {
    let seenStdin = '';
    runJudge([{ ...hit, filePath: '/Users/alicesecret/projects/topsecret/session.jsonl' }], {
      spawn: (_argv, _env, stdin) => {
        seenStdin = stdin;
        return envelope(VERDICT_FENCE);
      },
      loadRubric: () => 'RUBRIC',
    });
    expect(seenStdin).not.toContain('alicesecret');
    expect(seenStdin).not.toContain('topsecret');
    expect(seenStdin).not.toContain('filePath');
  });

  it('masks a secret that appears only in the context window; rawMatch stays legible', () => {
    // A second, distinct AWS key living ONLY in the surrounding context — not the
    // finding's own value. It must not cross to the model.
    const contextOnlySecret = ['AKIA', 'ZYXWVUTSRQPONMLK'].join('');
    let seenStdin = '';
    runJudge([{ ...hit, context: `aws_a=${hit.rawMatch} aws_b=${contextOnlySecret}` }], {
      spawn: (_argv, _env, stdin) => {
        seenStdin = stdin;
        return envelope(VERDICT_FENCE);
      },
      loadRubric: () => 'RUBRIC',
    });
    expect(seenStdin).toContain(hit.rawMatch);
    expect(seenStdin).not.toContain(contextOnlySecret);
    // Positive check: masking stays SELECTIVE, not a blanket redaction. If
    // maskText fell back to its fail-secure `[REDACTED]` path, the two assertions
    // above would still hold while the window the judge relies on was gone — so
    // pin that the non-secret structure of the context survives.
    expect(seenStdin).toContain('aws_a=');
  });

  it('does not mutate the source hit (dropped fields survive for the writeback path)', () => {
    // deriveSurfacedSecretFindings reads filePath/context off the ORIGINAL hits
    // after runJudge, and dedupe/writeback key on valueFingerprint/keyVersion;
    // toJudgePayload must project a copy, never mutate the dropped fields in place.
    const src: TriageHit = {
      ...hit,
      filePath: '/Users/x/p/session.jsonl',
      valueFingerprint: 'fp-hmac',
      keyVersion: 3,
    };
    toJudgePayload(src);
    expect(src.filePath).toBe('/Users/x/p/session.jsonl');
    expect(src.valueFingerprint).toBe('fp-hmac');
    expect(src.keyVersion).toBe(3);
    expect(src.context).toBe(hit.context);
  });

  it('passes the prompt on stdin, never in argv', () => {
    let seenArgv: readonly string[] = [],
      seenStdin = '';
    const rec = runJudge(
      [
        {
          ruleId: 'r',
          category: 'secret',
          severity: 'high',
          maskedMatch: 'A***E',
          rawMatch: 'AKIAREALKEY',
          context: 'x',
          confidence: 0.9,
          id: '0',
          valueFingerprint: 'fp1',
          keyVersion: 1,
        },
      ],
      {
        spawn: (argv, _env, stdin) => {
          seenArgv = argv;
          seenStdin = stdin;
          return JSON.stringify({
            is_error: false,
            result: '```json\n{"perCategory":[],"notes":"ok"}\n```',
          });
        },
        loadRubric: () => 'RUBRIC',
      },
    );
    expect(seenArgv).toEqual(['-p', '--no-session-persistence', '--output-format', 'json']);
    expect(seenArgv.join(' ')).not.toContain('AKIAREALKEY');
    expect(seenStdin).toContain('AKIAREALKEY'); // raw rides stdin, isolated subprocess only
    expect(rec.notes).toBe('ok');
  });

  // Every field on the TriageHit schema is either DISCLOSED (crosses to the model
  // API, named in the consent copy) or DROPPED by toJudgePayload before egress —
  // there is no third bucket. Deriving both sets from TriageHit.shape makes this
  // fail closed: a new schema field is a red test until it is classified, so it
  // cannot silently widen the payload past what the user was told.
  const DISCLOSED = [
    'category',
    'confidence',
    'context',
    'id',
    'maskedMatch',
    'rawMatch',
    'ruleId',
    'severity',
  ] as const;
  const DROPPED = ['filePath', 'valueFingerprint', 'keyVersion'] as const;

  it('classifies every TriageHit field as disclosed or dropped — no third bucket', () => {
    expect([...DISCLOSED, ...DROPPED].sort()).toEqual(Object.keys(TriageHit.shape).sort());
  });

  it('sends exactly the disclosed fields — drops filePath, valueFingerprint, keyVersion', () => {
    // A fully-populated hit: id + valueFingerprint + keyVersion are set on every
    // real hit reaching runJudge (backfill.ts:132-134), and filePath when known.
    const full: TriageHit = {
      ...hit,
      id: '7',
      filePath: '/Users/dev/.claude/projects/acme-api/session.jsonl',
      valueFingerprint: 'HMAC-of-the-secret',
      keyVersion: 1,
    };
    let seenStdin = '';
    runJudge([full], {
      spawn: (_argv, _env, stdin) => {
        seenStdin = stdin;
        return envelope(VERDICT_FENCE);
      },
      loadRubric: () => 'RUBRIC',
    });

    // The hits ride as JSONL inside the prompt's last fenced block.
    const fenced = /```\n([\s\S]*?)\n```\n?$/.exec(seenStdin);
    if (fenced?.[1] === undefined) throw new Error('no fenced hit block on stdin');
    const lines = fenced[1].split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    const [hitLine] = lines;
    if (hitLine === undefined) throw new Error('no hit line on stdin');

    const sent = JSON.parse(hitLine) as Record<string, unknown>;
    expect(Object.keys(sent).sort()).toEqual([...DISCLOSED].sort());

    // id rides verbatim — the rubric requires the model to echo it in fpIds.
    expect(sent.id).toBe('7');
    // rawMatch is the sole raw field — it rides legibly (the rubric judges the
    // value). context is re-masked: the raw secret no longer appears in the
    // window, but the non-secret scaffold survives (selective, not blanked).
    expect(sent.rawMatch).toBe(hit.rawMatch);
    expect(sent.context).not.toContain(hit.rawMatch);
    expect(sent.context).toContain('export KEY=');
    // The dropped provenance/correlator fields never reach the model.
    expect(seenStdin).not.toContain('/Users/dev/.claude/projects/acme-api/session.jsonl');
    expect(seenStdin).not.toContain('HMAC-of-the-secret');
    expect(seenStdin).not.toContain('filePath');
    expect(seenStdin).not.toContain('valueFingerprint');
  });

  it('re-throws a spawn failure as raw-free metadata (execFileSync puts the prompt in .message)', () => {
    // execFileSync throws an error whose .message is `Command failed: claude … <argv>`,
    // and argv carries the raw hits in the prompt. Simulate that exact shape and
    // assert the raw value never rides the re-thrown error out to the parent stderr.
    const spawn = (argv: readonly string[]): string => {
      const err = new Error(`Command failed: claude ${argv.join(' ')}`) as Error & {
        status?: number;
        stdout?: string;
        stderr?: string;
      };
      err.status = 1;
      err.stdout = `partial output leaking ${hit.rawMatch}`;
      err.stderr = 'boom';
      throw err;
    };
    try {
      runJudge([hit], { spawn, loadRubric: () => 'RUBRIC' });
      throw new Error('expected runJudge to throw');
    } catch (err) {
      const message = (err as Error).message;
      // Run-by-run, not whole: a branch echoing a truncated value still hands a
      // live credential's prefix to the parent's stderr.
      expectNoEchoOf(message, hit.rawMatch);
      expect(message).not.toContain('export KEY=');
      // still useful: it names the failure + surfaces the raw-free exit status
      expect(message).toContain('judge subprocess failed');
      expect(message).toContain('exit 1');
      // and the raw-bearing spawn error is NOT chained as `cause` — a future
      // `{ cause: err }` would re-expose the prompt via util.inspect/loggers.
      expect((err as Error).cause).toBeUndefined();
    }
  });
});

// -------------------------------------------------------------------------
// The darwin config dir's lifecycle: minted by judgeEnv, removed in `finally`
// -------------------------------------------------------------------------

// A dir left behind is a dir the judge's config — and whatever the CLI wrote
// into it — survives in. The platform is injected so both branches run on every
// runner. Each case captures the dir the child actually saw, asserts it exists
// DURING the call, and asserts it is gone after: an absence check alone would
// pass just as well against a dir that was never created.
describe('runJudge — darwin CLAUDE_CONFIG_DIR lifecycle', () => {
  const rubric = (): string => 'RUBRIC';

  // Run the judge on darwin with `outcome` deciding what the fake spawn does,
  // and report the config dir the child was handed plus whether it existed then.
  function runDarwin(outcome: (env: NodeJS.ProcessEnv) => string): {
    dir: string;
    existedDuringCall: boolean;
    threw: unknown;
  } {
    let dir = '';
    let existedDuringCall = false;
    let threw: unknown;
    const spawn = (_argv: readonly string[], env: NodeJS.ProcessEnv): string => {
      dir = env.CLAUDE_CONFIG_DIR ?? '';
      existedDuringCall = dir !== '' && existsSync(dir);
      return outcome(env);
    };
    try {
      runJudge([hit], { spawn, loadRubric: rubric, platform: 'darwin' });
    } catch (err) {
      threw = err;
    }
    return { dir, existedDuringCall, threw };
  }

  it('removes the dir after a successful judgment', () => {
    const { dir, existedDuringCall, threw } = runDarwin(() => envelope(VERDICT_FENCE));
    expect(threw).toBeUndefined();
    expect(existedDuringCall).toBe(true);
    expect(existsSync(dir)).toBe(false);
  });

  it('removes the dir when the spawn throws', () => {
    const { dir, existedDuringCall, threw } = runDarwin(() => {
      throw Object.assign(new Error('Command failed: claude'), { status: 1 });
    });
    expect(threw).toBeInstanceOf(Error);
    expect(existedDuringCall).toBe(true);
    expect(existsSync(dir)).toBe(false);
  });

  it('removes the dir when the verdict is unparseable', () => {
    // The parse throws AFTER the spawn returns — a different path out of the
    // try than the spawn failure, and one a `catch`-based cleanup would miss.
    const { dir, existedDuringCall, threw } = runDarwin(() => 'not a json envelope');
    expect(threw).toBeInstanceOf(Error);
    expect(existedDuringCall).toBe(true);
    expect(existsSync(dir)).toBe(false);
  });

  it('removes the dir even when the subprocess wrote into it', () => {
    // `recursive: true` matters: the real CLI writes config into this dir, and a
    // plain unlink would fail on a non-empty directory and leak it.
    const { dir, threw } = runDarwin((env) => {
      writeFileSync(join(env.CLAUDE_CONFIG_DIR ?? '', 'config.json'), '{"leftover":true}');
      return envelope(VERDICT_FENCE);
    });
    expect(threw).toBeUndefined();
    expect(existsSync(dir)).toBe(false);
  });

  it('replaces, and does not remove, an inherited CLAUDE_CONFIG_DIR on darwin', () => {
    // The darwin-plus-inherited combination, driven through runJudge so the
    // `finally` actually runs. judgeEnv's own test pins the replacement and the
    // lifecycle test above pins that an inherited dir survives OFF darwin —
    // but the interaction is what makes the removal safe, and asserting the two
    // halves separately leaves the pair unpinned. On darwin the removal is
    // unconditional, so it is judgeEnv REPLACING the inherited value that keeps
    // `rmSync` off the user's real config dir; couple them here.
    const real = ownedDir();
    writeFileSync(join(real, 'settings.json'), '{"theme":"dark"}');
    vi.stubEnv('CLAUDE_CONFIG_DIR', real);

    const { dir, existedDuringCall, threw } = runDarwin(() => envelope(VERDICT_FENCE));

    expect(threw).toBeUndefined();
    // The child got a throwaway, never the inherited dir.
    expect(dir).not.toBe(real);
    expect(existedDuringCall).toBe(true);
    // The throwaway is gone; the user's own config dir and its contents are not.
    expect(existsSync(dir)).toBe(false);
    expect(existsSync(join(real, 'settings.json'))).toBe(true);
  });

  it('a cleanup fault never replaces the error the judge is throwing', (ctx) => {
    if (process.platform === 'win32') {
      ctx.skip('removability here is decided by POSIX mode bits');
    }
    // A directory its owner cannot write to cannot have its children unlinked,
    // so a recursive remove of the parent fails with a real EACCES from the
    // real syscall. Root ignores mode bits, and a cleanup that SUCCEEDS leaves
    // the error unreplaced too — so this test passes for the wrong reason
    // without first proving the fault takes for whoever is running it.
    const lock = (parent: string): string => {
      const locked = join(parent, 'locked');
      mkdirSync(locked);
      writeFileSync(join(locked, 'child'), 'x');
      chmodSync(locked, 0o500);
      return locked;
    };

    const probe = ownedDir();
    const probeLocked = lock(probe);
    let faultTakes = false;
    try {
      rmSync(probe, { recursive: true, force: true });
    } catch {
      faultTakes = true;
    }
    if (!faultTakes) ctx.skip('this user can remove a write-protected directory');
    chmodSync(probeLocked, 0o700);

    let locked = '';
    const { dir, threw } = runDarwin((env) => {
      locked = lock(env.CLAUDE_CONFIG_DIR ?? '');
      throw Object.assign(new Error(`Command failed: claude ${hit.rawMatch}`), { status: 7 });
    });
    try {
      // The fs error from the failed removal did NOT displace the raw-free one
      // the caller has to act on — apply-suppressions prints exactly this
      // message to the parent's stderr.
      expect((threw as Error).message).toBe('claude -p judge subprocess failed (exit 7)');
      expectNoEchoOf((threw as Error).message, hit.rawMatch);
      // The positive control: the dir survived, so the cleanup really did fail
      // rather than this passing against a removal that quietly worked.
      expect(existsSync(dir)).toBe(true);
    } finally {
      if (locked !== '') chmodSync(locked, 0o700);
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('never removes an inherited CLAUDE_CONFIG_DIR off darwin', () => {
    // Off darwin judgeEnv mints nothing, so CLAUDE_CONFIG_DIR is whatever the
    // parent carried — a real config dir the user may point at their own Claude
    // install. The platform check gating the removal is what stops the cleanup
    // recursively deleting it; drop it and this run destroys their config.
    const real = ownedDir();
    writeFileSync(join(real, 'settings.json'), '{"theme":"dark"}');

    for (const platform of ['linux', 'win32'] as const) {
      vi.stubEnv('CLAUDE_CONFIG_DIR', real);
      let seen = '';
      // Both exits from the try — clean return and spawn failure — reach the
      // same `finally`, so both are checked.
      runJudge([hit], {
        spawn: (_argv, env) => {
          seen = env.CLAUDE_CONFIG_DIR ?? '';
          return envelope(VERDICT_FENCE);
        },
        loadRubric: rubric,
        platform,
      });
      expect(seen).toBe(real);
      expect(existsSync(join(real, 'settings.json'))).toBe(true);

      expect(() =>
        runJudge([hit], {
          spawn: () => {
            throw new Error('boom');
          },
          loadRubric: rubric,
          platform,
        }),
      ).toThrow();
      expect(existsSync(join(real, 'settings.json'))).toBe(true);
    }
  });
});

// -------------------------------------------------------------------------
// spawnFailureMeta: what a failed spawn is allowed to say
// -------------------------------------------------------------------------

// A spawn error carries the raw hits in `.stdout`/`.stderr` (and historically in
// `.message`, which echoed the argv the prompt used to ride). The re-thrown
// error must carry ONLY exit status, signal, and node error code — the three
// fields that describe how the process died and nothing about what it was
// handling. Each case seeds all three raw-bearing fields and asserts none
// survives.
describe('runJudge — spawn failure metadata', () => {
  // A rejected spawn shaped like execFileSync's: the raw hits in every field it
  // really populates, plus whichever metadata this case is pinning.
  function failWith(meta: Record<string, unknown>): Error {
    let caught: unknown;
    try {
      runJudge([hit], {
        spawn: (argv, _env, stdin) => {
          throw Object.assign(
            // execFileSync's own message shape, and the pre-stdin regression:
            // the whole prompt echoed back through argv.
            new Error(`Command failed: claude ${argv.join(' ')} ${stdin}`),
            {
              stdout: `partial output ${hit.rawMatch}`,
              stderr: `stderr trailer ${hit.context}`,
              ...meta,
            },
          );
        },
        loadRubric: () => 'RUBRIC',
      });
    } catch (err) {
      caught = err;
    }
    if (!(caught instanceof Error)) throw new Error('expected runJudge to throw an Error');
    return caught;
  }

  const CASES: { name: string; meta: Record<string, unknown>; expected: string }[] = [
    { name: 'an exit status', meta: { status: 2 }, expected: 'exit 2' },
    { name: 'a terminating signal', meta: { signal: 'SIGKILL' }, expected: 'signal SIGKILL' },
    {
      name: 'a node error code (claude not on PATH)',
      meta: { code: 'ENOENT' },
      expected: 'ENOENT',
    },
    {
      name: 'all three at once',
      meta: { status: 143, signal: 'SIGTERM', code: 'ETIMEDOUT' },
      expected: 'exit 143, signal SIGTERM, ETIMEDOUT',
    },
    {
      name: 'nothing usable',
      meta: { status: null, signal: null },
      expected: 'unknown error',
    },
  ];

  for (const { name, meta, expected } of CASES) {
    it(`surfaces ${name} and nothing else`, () => {
      const err = failWith(meta);
      expect(err.message).toBe(`claude -p judge subprocess failed (${expected})`);
      // The raw value and the surrounding transcript window both stay inside,
      // run by run: a truncated echo is still a live credential's prefix.
      expectNoEchoOf(err.message, hit.rawMatch);
      expectNoEchoOf(err.message, hit.context);
      // Nor may the raw-bearing original ride out attached: util.inspect and
      // most loggers print `cause`, which would undo the whole strip.
      expect(err.cause).toBeUndefined();
      // A whitelist, not a blacklist of `stdout`/`stderr`: a fresh Error has no
      // own enumerable keys at all, so this catches ANY property a future
      // "attach the original for debugging" bolts on, whatever it is named.
      expect(Object.keys(err)).toEqual([]);
    });
  }

  it('does not fall back to the live spawn when deps.spawn is missing', () => {
    // The seam is required, not defaulted. A future `deps.spawn ?? spawnClaude`
    // would turn any caller that forgot to inject into a live egress. It fails
    // as the programming error it is rather than as a subprocess that never
    // ran, and the spawn-family spy proves nothing was spawned.
    const err = (() => {
      try {
        runJudge([hit], { loadRubric: () => 'RUBRIC' } as unknown as JudgeDeps);
      } catch (e) {
        return e as Error;
      }
      throw new Error('expected runJudge to throw');
    })();
    expect(err).toBeInstanceOf(TypeError);
    expect(err.message).toBe('runJudge requires deps.spawn — there is no live-spawn fallback');
    expectNoEchoOf(err.message, hit.rawMatch);
    expect(liveSpawn).not.toHaveBeenCalled();
  });
});
