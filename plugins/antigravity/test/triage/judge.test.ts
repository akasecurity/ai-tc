import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import type { BareCommandUnsupportedError } from '@akasecurity/plugin-sdk/bare-command';
import { isBareCommandUnsupported, planBareCommand } from '@akasecurity/plugin-sdk/bare-command';
import { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { JudgeDeps } from '../../src/triage/judge.ts';
import {
  cleanupConversation,
  judgeEnv,
  parseVerdict,
  runJudge,
  toJudgePayload,
} from '../../src/triage/judge.ts';
import { errorFrom, expectNoEchoOf } from '../helpers/no-echo.ts';

const VERDICT_FENCE = [
  '```json',
  '{"perCategory":[{"category":"secret","action":"block","reasoning":"real","genuineCount":2,"fpCount":2,"fpIds":[]}],"notes":""}',
  '```',
].join('\n');

// The prompt `agy` is run with — the `content` of the single NDJSON `user`
// event written to the child's stdin. On this host the prompt rides stdin, the
// same shape the Claude Code and Codex judges use; nothing raw-bearing is on
// argv, which is what this reader would notice if it moved back.
// The lenient reader the fixture uses: the `user` event's content, or undefined
// for anything else. Kept separate from the strict `promptOf` below because
// fakeSpawn runs INSIDE runJudge's own try/catch — a throw from there is
// re-thrown as `agy judge subprocess failed (unknown error)`, so a fixture
// precondition that fired would be reported as a spawn fault rather than as the
// NDJSON regression it is.
const contentOf = (stdin: string): string | undefined => {
  for (const line of stdin.split('\n')) {
    if (line.trim() === '') continue;
    let event: { event?: unknown; message?: { content?: unknown } };
    try {
      event = JSON.parse(line) as typeof event;
    } catch {
      continue;
    }
    if (event.event === 'user' && typeof event.message?.content === 'string') {
      return event.message.content;
    }
  }
  return undefined;
};

// The strict reader, called by tests DIRECTLY (never through the spawn seam) so
// its diagnostics survive: exactly one NDJSON line, a `user` event, string
// content. The single-line check is the wire property that a Windows command
// line could never have carried, so it is asserted rather than assumed.
const promptOf = (stdin: string): string => {
  const lines = stdin.split('\n').filter((line) => line.trim() !== '');
  // Exactly one: NDJSON is one object per line, and a prompt that leaked its own
  // line breaks out of the JSON string would arrive here as several.
  if (lines.length !== 1) {
    throw new Error(`expected one NDJSON event on stdin, saw ${String(lines.length)}`);
  }
  const [line] = lines;
  if (line === undefined) throw new Error('no NDJSON event on stdin');
  const event = JSON.parse(line) as { event?: unknown; message?: { content?: unknown } };
  if (event.event !== 'user') throw new Error('stdin event was not a `user` event');
  const content = event.message?.content;
  if (typeof content !== 'string') throw new Error('stdin user event carried no string content');
  return content;
};

// The NDJSON stream a real `agy --output-format stream-json` prints: an `init`
// event, then the terminal `result` event carrying the final assistant message.
const streamJson = (lastMessage: string, conversationId = 'conv-judge'): string =>
  [
    JSON.stringify({ event: 'init', conversation_id: conversationId, init: { cwd: '/w' } }),
    JSON.stringify({
      event: 'step_update',
      step_update: { conversation_id: conversationId, step_index: 0, state: 'done' },
    }),
    JSON.stringify({
      event: 'result',
      result: {
        conversation_id: conversationId,
        status: 'ok',
        response: lastMessage,
        num_turns: 1,
      },
    }),
    '',
  ].join('\n');

// A minimal stream carrying ONLY the terminal result event and no conversation
// id anywhere — neither a result id nor an init one to fall back to — which is
// the shape that forces cleanup onto its directory-diff fallback.
const streamJsonWithoutId = (lastMessage: string): string =>
  `${JSON.stringify({ event: 'result', result: { status: 'ok', response: lastMessage } })}\n`;

// A fake spawn that plays the subprocess's one observable role: printing the
// `--output-format stream-json` event stream on stdout. `conversationId`
// controls what the run claims to have created, so cleanup can be driven from a
// test.
const fakeSpawn =
  (
    lastMessage: string,
    seen?: {
      argv?: readonly string[];
      env?: NodeJS.ProcessEnv;
      // `string | undefined`, not `string`: contentOf is the LENIENT reader, so
      // a stdin that carried no `user` event records as undefined here and the
      // reading test fails on its own assertion rather than on a fixture throw.
      prompt?: string | undefined;
      stdin?: string;
    },
    conversationId = 'conv-judge',
  ) =>
  (argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string): string => {
    if (seen) {
      seen.argv = argv;
      seen.env = env;
      seen.stdin = stdin;
      seen.prompt = contentOf(stdin);
    }
    return streamJson(lastMessage, conversationId);
  };

// Every runJudge call must be pointed at a throwaway home. The judge deletes
// the conversation its own run created, and an unset `home` resolves to the
// REAL ~/.gemini/antigravity/brain on whatever machine runs this suite.
const tempHome = (): string => mkdtempSync(join(tmpdir(), 'aka-judge-home-'));

// Seed a conversation directory under a throwaway home's brain root.
const seedConversation = (home: string, id: string): string => {
  const dir = join(home, '.gemini', 'antigravity', 'brain', id);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'transcript.jsonl'), '{"actor":"user"}\n');
  return dir;
};

describe('parseVerdict', () => {
  it('parses the fenced verdict out of the last message', () => {
    const rec = parseVerdict(`reasoning here...\n${VERDICT_FENCE}`);
    expect(rec.perCategory[0]?.action).toBe('block');
  });

  it('uses the LAST json fence when the message carries an earlier illustrative one', () => {
    const message = [
      'Here is the shape I will use:',
      '```json',
      '{"perCategory":[{"category":"secret","action":"warn","reasoning":"illustrative","genuineCount":0,"fpCount":0,"fpIds":[]}],"notes":""}',
      '```',
      'Now the real verdict:',
      VERDICT_FENCE,
    ].join('\n');
    expect(parseVerdict(message).perCategory[0]?.reasoning).toBe('real');
  });

  it('throws on an empty last message', () => {
    expect(() => parseVerdict('')).toThrow();
    expect(() => parseVerdict('  \n ')).toThrow();
  });

  it('never echoes the subprocess output in a failure (raw stays inside the judge)', () => {
    const raw = 'AKIAIOSFODNN7EXAMPLE';
    // An unparseable message and a non-JSON fence — both carrying the raw
    // value. Neither thrown message may contain it.
    const cases = [`no fence here, just ${raw}`, '```json\nnot json ' + raw + '\n```'];
    for (const lastMessage of cases) {
      // Captured OUTSIDE the catch. The `try { parseVerdict(…); throw new
      // Error('expected …') } catch (err) { … }` shape this replaced caught the
      // test's OWN guard error and asserted against a message that never held a
      // secret — green while parseVerdict stopped throwing at all.
      const err = errorFrom(() => parseVerdict(lastMessage));
      // Name the refusal first: without it the case proves only that SOME error
      // said nothing, not that the unparseable branch was the one reached.
      expect(err?.message).toBe('agy judge returned an unparseable TriageRecommendation');
      // Run-by-run, not whole: a branch echoing a truncated value still hands a
      // live credential's prefix to the parent's stderr.
      expectNoEchoOf(err?.message, raw);
    }
  });
});

describe('judgeEnv', () => {
  it('inherits the host environment (PATH survives so `agy` resolves)', () => {
    // Nothing about session persistence is controlled by env on this host —
    // the CLI documents no ephemeral mode at all, so the conversation is
    // removed after the fact instead. The env is a plain inherit; PATH must
    // survive so `agy` resolves and its auth is found.
    const env = judgeEnv();
    expect(env.PATH).toBeTruthy();
  });
});

describe('runJudge', () => {
  const hit: TriageHit = {
    ruleId: 'core-secret/aws',
    category: 'secret',
    severity: 'high',
    maskedMatch: 'A***Z',
    rawMatch: 'AKIAIOSFODNN7EXAMPLE',
    context: 'export KEY=AKIAIOSFODNN7EXAMPLE # prod',
    confidence: 0.9,
  };

  it('runs `agy --input-format stream-json --output-format stream-json` and reads the verdict from the result event', () => {
    const seen: {
      argv?: readonly string[];
      env?: NodeJS.ProcessEnv;
      prompt?: string;
      stdin?: string;
    } = {};
    const rec = runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC BODY',
      home: mkdtempSync(join(tmpdir(), 'aka-judge-home-')),
    });

    const argv = seen.argv ?? [];
    // The streaming stdin input is what takes the prompt off argv. The two
    // formats are paired because the host documents that pairing — a streaming
    // input against a non-streaming output emits its one envelope only as the
    // process exits.
    expect(argv).toContain('--input-format');
    expect(argv[argv.indexOf('--input-format') + 1]).toBe('stream-json');
    expect(argv).toContain('--output-format');
    expect(argv[argv.indexOf('--output-format') + 1]).toBe('stream-json');
    // `-p` is the argv-borne entrypoint and is mutually exclusive with the
    // streaming input: the host documents passing both as an error.
    expect(argv).not.toContain('-p');
    // There is no `exec` subcommand on this host and no --ephemeral to pass.
    expect(argv).not.toContain('exec');
    expect(argv).not.toContain('--ephemeral');

    // The strict wire shape, read here rather than inside the spawn seam: exactly
    // one NDJSON line carrying a `user` event. A prompt that leaked its own line
    // breaks out of the JSON string would arrive as several, and this is where
    // that is reported as itself instead of as a spawn failure.
    expect(promptOf(seen.stdin ?? '')).toBe(seen.prompt);

    // rawMatch rides in the prompt — the rubric judges the actual value.
    // filePath is dropped and context is masked before it crosses (covered
    // below), so rawMatch is the only raw field that leaves.
    expect(seen.prompt).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(seen.prompt).toContain('RUBRIC BODY');
    // The subprocess env is the inherited host env, untouched — exactly what
    // judgeEnv() snapshots.
    expect(seen.env).toEqual(judgeEnv());

    expect(rec.perCategory[0]?.action).toBe('block');
  });

  it('keeps the raw hits OFF argv — they ride stdin, as on the other two hosts', () => {
    // The property that makes a Windows `agy.cmd` shim reachable at all, and
    // that keeps the raw hits out of `ps` and out of any failed command line an
    // error message echoes. It is asserted from BOTH sides on purpose: a spawn
    // seam that stopped being handed the prompt would leave the absence check
    // passing over an argv that never carried it.
    const seen: { argv?: readonly string[]; prompt?: string; stdin?: string } = {};
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
        spawn: fakeSpawn('```json\n{"perCategory":[],"notes":"ok"}\n```', seen),
        loadRubric: () => 'RUBRIC',
        home: mkdtempSync(join(tmpdir(), 'aka-judge-home-')),
      },
    );
    // Positive control first, on the bytes the absence check then reads: the
    // prompt really did carry the raw value, and it really did travel on stdin.
    expect(seen.prompt).toContain('AKIAREALKEY');
    expect(seen.stdin).toContain('AKIAREALKEY');
    // ...and none of it reached argv.
    expectNoEchoOf((seen.argv ?? []).join(' '), 'AKIAREALKEY');
    expect(rec.notes).toBe('ok');
  });

  // Every field on the TriageHit schema is either DISCLOSED (crosses to the model
  // inside the prompt) or DROPPED (stripped by toJudgePayload before egress).
  // The consent copy in the setup skill enumerates the disclosed set field by
  // field, so a new schema field must be placed in one bucket deliberately —
  // and, if disclosed, added to that copy.
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
    // real hit reaching runJudge, and filePath when known.
    const full: TriageHit = {
      ...hit,
      id: '7',
      filePath:
        '/Users/dev/.gemini/antigravity/brain/conv-x/.system_generated/logs/transcript.jsonl',
      valueFingerprint: 'HMAC-of-the-secret',
      keyVersion: 1,
    };
    const seen: { prompt?: string } = {};
    runJudge([full], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });

    // The hits ride as JSONL inside the prompt's last fenced block, and the
    // prompt itself rides stdin.
    const fenced = /```\n([\s\S]*?)\n```\n?$/.exec(seen.prompt ?? '');
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
    const sentContext = sent.context;
    if (typeof sentContext !== 'string') throw new Error('projected hit carried no context');
    // The positive control comes first, on the SAME bytes: an absence assertion
    // over an empty window would pass while proving nothing.
    expect(sentContext).toContain('export KEY=');
    expectNoEchoOf(sentContext, hit.rawMatch);
    // The dropped provenance/correlator fields never reach the model.
    expect(seen.prompt).not.toContain(
      '/Users/dev/.gemini/antigravity/brain/conv-x/.system_generated/logs/transcript.jsonl',
    );
    expect(seen.prompt).not.toContain('HMAC-of-the-secret');
    expect(seen.prompt).not.toContain('filePath');
    expect(seen.prompt).not.toContain('valueFingerprint');
  });

  it('drops filePath from the judge payload (it encodes the OS username and project dirs)', () => {
    const seen: { prompt?: string } = {};
    runJudge([{ ...hit, filePath: '/Users/alicesecret/projects/topsecret/rollout.jsonl' }], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });
    expect(seen.prompt).not.toContain('alicesecret');
    expect(seen.prompt).not.toContain('topsecret');
    expect(seen.prompt).not.toContain('filePath');
  });

  it('masks a secret that appears only in the context window; rawMatch stays legible', () => {
    // A second, distinct AWS key living ONLY in the surrounding context — not the
    // finding's own value. It must not cross to the model.
    const contextOnlySecret = ['AKIA', 'ZYXWVUTSRQPONMLK'].join('');
    const seen: { prompt?: string } = {};
    runJudge([{ ...hit, context: `aws_a=${hit.rawMatch} aws_b=${contextOnlySecret}` }], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });
    expect(seen.prompt).toContain(hit.rawMatch);
    expectNoEchoOf(seen.prompt, contextOnlySecret);
    // Positive check: masking stays SELECTIVE, not a blanket redaction. If
    // maskText fell back to its fail-secure `[REDACTED]` path, the two assertions
    // above would still hold while the window the judge relies on was gone — so
    // pin that the non-secret structure of the context survives.
    expect(seen.prompt).toContain('aws_a=');
  });

  it('does not mutate the source hit (dropped fields survive for the writeback path)', () => {
    // deriveSurfacedSecretFindings reads filePath/context off the ORIGINAL hits
    // after runJudge, and dedupe/writeback key on valueFingerprint/keyVersion;
    // toJudgePayload must project a copy, never mutate the dropped fields in place.
    const src: TriageHit = {
      ...hit,
      filePath: '/Users/x/p/rollout.jsonl',
      valueFingerprint: 'fp-hmac',
      keyVersion: 3,
    };
    toJudgePayload(src);
    expect(src.filePath).toBe('/Users/x/p/rollout.jsonl');
    expect(src.valueFingerprint).toBe('fp-hmac');
    expect(src.keyVersion).toBe(3);
    expect(src.context).toBe(hit.context);
  });

  it('fails loud (and raw-free) when the subprocess prints nothing', () => {
    // A spawn that exits cleanly but prints no envelope — the verdict is
    // unreadable and must not pass silently.
    const err = errorFrom(() =>
      runJudge([hit], { spawn: () => '', loadRubric: () => 'RUBRIC', home: tempHome() }),
    );
    expect(err).toBeDefined();
    expect(err?.message).toContain('produced no output');
    expectNoEchoOf(err?.message, hit.rawMatch);
  });

  it.each([
    ['not JSON at all', 'was not valid JSON'],
    ['[1,2,3]', 'was not a JSON object'],
    // Parseable events, but none of them terminal — a stream that stopped at
    // `init` must not be read as a verdict-free pass.
    ['{"event":"init","conversation_id":"c"}', 'carried no result event'],
    ['{"event":"result","result":"not-an-object"}', 'result event carried no result object'],
    ['{"event":"result","result":{"status":"ok"}}', 'carried no response string'],
  ])('fails loud (and raw-free) on a malformed event stream: %s', (stdout, expected) => {
    const err = errorFrom(() =>
      runJudge([hit], { spawn: () => stdout, loadRubric: () => 'RUBRIC', home: tempHome() }),
    );
    expect(err).toBeDefined();
    expect(err?.message).toContain(expected);
    expectNoEchoOf(err?.message, hit.rawMatch);
  });

  it.each([
    ['single-line', false],
    ['pretty-printed', true],
  ])('still reads a %s whole-stdout envelope — the pre-streaming shape (P4)', (_label, pretty) => {
    // The shape `--output-format json` printed, and what this module read until
    // the prompt moved to stdin. Line-by-line parsing cannot see it: a
    // pretty-printed one fails every line ("was not valid JSON") and a
    // single-line one parses to an event with no `event` key ("carried no
    // result event"). Both were readable before this change, so both stay
    // readable — the fallback widens what parses and narrows nothing.
    const home = tempHome();
    const dir = seedConversation(home, 'conv-legacy');
    const envelope = {
      conversation_id: 'conv-legacy',
      status: 'ok',
      response: VERDICT_FENCE,
    };
    const rec = runJudge([hit], {
      spawn: () => (pretty ? JSON.stringify(envelope, null, 2) : JSON.stringify(envelope)),
      loadRubric: () => 'RUBRIC',
      home,
    });
    expect(rec.perCategory[0]?.action).toBe('block');
    // ...and the id came off the legacy envelope too, so cleanup still runs.
    expect(existsSync(dir)).toBe(false);
  });

  it('keeps a verdict a later result event could not improve on (Q2)', () => {
    // "Last USABLE result event wins" means usable, not merely an object. A
    // second result event carrying `{status:'error'}` used to overwrite the
    // verdict and throw `carried no response string`, failing a whole history
    // chunk on output that contained a readable answer.
    const home = tempHome();
    const dir = seedConversation(home, 'conv-A');
    const rec = runJudge([hit], {
      spawn: () =>
        [
          JSON.stringify({
            event: 'result',
            result: { conversation_id: 'conv-A', response: VERDICT_FENCE },
          }),
          JSON.stringify({ event: 'result', result: { status: 'error' } }),
          '',
        ].join('\n'),
      loadRubric: () => 'RUBRIC',
      home,
    });
    expect(rec.perCategory[0]?.action).toBe('block');
    // ...and the id survived with it, so the conversation is still cleaned up.
    expect(existsSync(dir)).toBe(false);
  });

  it('re-throws a spawn failure as raw-free metadata (its captured streams echo raw)', () => {
    // The prompt rides stdin now, so execFileSync's own message no longer
    // carries the hits — but the child's captured .stdout/.stderr still can,
    // since both are the model's own output and `agy`'s run logging echoes
    // prompt content. Simulate a failure whose every field leaks, including a
    // message shaped like the old argv-bearing one, and assert that none of it
    // rides the re-thrown error out to the parent stderr.
    const spawn = (): string => {
      const err = new Error(
        `Command failed: agy --input-format stream-json ... ${hit.rawMatch} ...`,
      ) as Error & { status?: number; stdout?: string; stderr?: string };
      err.status = 1;
      err.stdout = `partial output leaking ${hit.rawMatch}`;
      err.stderr = `run logging leaking ${hit.context}`;
      throw err;
    };
    const err = errorFrom(() =>
      runJudge([hit], { spawn, loadRubric: () => 'RUBRIC', home: tempHome() }),
    );
    expect(err).toBeDefined();
    const message = err?.message ?? '';
    // still useful: it names the failure + surfaces the raw-free exit status.
    // Asserted BEFORE the absences, which would otherwise be read off bytes
    // nothing has shown to be live.
    expect(message).toContain('judge subprocess failed');
    expect(message).toContain('exit 1');
    // The raw value and the surrounding transcript window both stay inside, run
    // by run: a truncated echo is still a live credential's prefix.
    expectNoEchoOf(message, hit.rawMatch);
    expectNoEchoOf(message, hit.context);
    // and the raw-bearing spawn error is NOT chained as `cause` — a future
    // `{ cause: err }` would re-expose the prompt via util.inspect/loggers.
    expect(err?.cause).toBeUndefined();
  });

  it('runs on Windows when `agy` resolves to a real executable', () => {
    // A bare name that resolves to a real executable is spawned by absolute path
    // with no interpreter in the middle. Driven against the REAL argv this judge
    // builds, so it cannot drift from what the product actually spawns.
    const seen: { argv?: readonly string[]; stdin?: string } = {};
    runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });
    const argv = seen.argv ?? [];

    const plan = planBareCommand('agy', argv, {
      platform: 'win32',
      home: '/anchor/home',
      resolve: () => String.raw`C:\Program Files\Antigravity\agy.exe`,
    });

    expect(plan.viaShell).toBe(false);
    expect(plan.file).toBe(String.raw`C:\Program Files\Antigravity\agy.exe`);
    expect(plan.args).toEqual(argv);
    // The direct path re-parses nothing, so it would carry a raw-bearing argv
    // just as happily — which is exactly why the assertion has to be made rather
    // than inferred from the branch. Positive control first, on the bytes the
    // absence check then reads.
    expect(seen.stdin ?? '').toContain(hit.rawMatch);
    expectNoEchoOf([plan.file, ...plan.args].join(' '), hit.rawMatch);
    // Still anchored: Windows searches the working directory before PATH for
    // libuv's own lookup too, so the direct path needs the anchor as much as the
    // shelled one does.
    expect(plan.options.cwd).toBe('/anchor/home');
  });

  it('reaches a Windows `agy.cmd` shim through cmd.exe rather than refusing it', () => {
    // The property that replaced this plugin's Windows judge gate. While the
    // prompt rode argv, the planner REFUSED this plan outright — a multi-line,
    // multi-KiB, transcript-derived argument cannot cross cmd.exe's parser — and
    // the wizard-journey suite, whose stub can only ever BE a `.cmd`, was skipped
    // on the Windows leg because of it.
    //
    // Driven against the REAL planner and the REAL argv `runJudge` builds, so it
    // fails the day anything raw-bearing moves back onto argv rather than
    // restating a rule in prose.
    const seen: { argv?: readonly string[]; stdin?: string } = {};
    runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });
    const argv = seen.argv ?? [];

    // The positive control, on the same bytes: the prompt is genuinely large,
    // multi-line and raw-bearing — it is just not on argv. Without this, an argv
    // that crosses cmd.exe proves nothing, since an EMPTY prompt would cross too.
    expect(seen.stdin ?? '').toContain(hit.rawMatch);
    expect(promptOf(seen.stdin ?? '')).toContain('\n');

    const refusal = errorFrom(() =>
      planBareCommand('agy', argv, {
        platform: 'win32',
        home: '/anchor/home',
        resolve: () => String.raw`C:\Users\dev\AppData\Roaming\npm\agy.cmd`,
      }),
    );
    expect(
      isBareCommandUnsupported(refusal),
      'the judge argv can no longer cross cmd.exe, so an `agy.cmd` shim is out of ' +
        'reach on Windows again — the wizard-journey suite will fail there rather ' +
        'than skip. Put every raw-bearing byte back on stdin.',
    ).toBe(false);
    expect(refusal).toBeUndefined();

    const plan = planBareCommand('agy', argv, {
      platform: 'win32',
      home: '/anchor/home',
      resolve: () => String.raw`C:\Users\dev\AppData\Roaming\npm\agy.cmd`,
    });
    // A `.cmd` is unreachable without an interpreter, so the plan takes one —
    // anchored at the user's home, or a stray `agy.cmd` in the working directory
    // would win the search.
    expect(plan.viaShell).toBe(true);
    expect(plan.options.cwd).toBe('/anchor/home');
    // Not-refused is only half the property, and on its own it is satisfiable by
    // a raw value SHORT and metachar-free enough for the planner to accept — at
    // which point the secret crosses cmd.exe and lands in the Windows process
    // list with every assertion above still green. So read the line cmd.exe is
    // actually handed, and require the raw value to be absent from it.
    expectNoEchoOf([plan.file, ...plan.args].join(' '), hit.rawMatch);
  });

  it('surfaces a planner refusal as its own raw-free reason, not as bare metadata', () => {
    // The judge's own argv is fixed flags and cannot be refused (above), but the
    // branch that reports a refusal is still what a user would read if anything
    // ever put a hostile argument back on it — so it stays covered, driven by a
    // refusal the REAL planner produced rather than a hand-written string.
    const refusal = errorFrom(() =>
      planBareCommand('agy', ['--flag', `carries a "quote" and a ${hit.rawMatch}`], {
        platform: 'win32',
        home: '/anchor/home',
        resolve: () => String.raw`C:\Users\dev\AppData\Roaming\npm\agy.cmd`,
      }),
    );
    // The positive control for everything below: a planner that stopped refusing
    // leaves `refusal` undefined, and the absence checks would then hold over an
    // error that never carried a value in the first place.
    expect(isBareCommandUnsupported(refusal)).toBe(true);
    const reason = (refusal as BareCommandUnsupportedError).reason;

    const err = errorFrom(() =>
      runJudge([hit], {
        spawn: () => {
          // Narrowed by the assertion above; `expect` does not narrow for TS.
          throw refusal as BareCommandUnsupportedError;
        },
        loadRubric: () => 'RUBRIC',
        home: tempHome(),
      }),
    );

    // A planner refusal is the one spawn failure here that is actionable, so it
    // reaches the user as its reason rather than flattened to "unknown error".
    expect(err?.message).toBe(`agy judge subprocess failed (${reason})`);
    expect(reason).toContain('cmd.exe');
    // And that reason names an argv index and a character class, never the
    // value — even though the argument it refused carried one.
    expectNoEchoOf(err?.message, hit.rawMatch);
    expectNoEchoOf(reason, hit.rawMatch);
  });

  describe('judge-conversation cleanup', () => {
    it('removes the conversation the run reported', () => {
      const home = tempHome();
      const dir = seedConversation(home, 'conv-judge');
      expect(existsSync(dir)).toBe(true);
      runJudge([hit], {
        spawn: fakeSpawn(VERDICT_FENCE, undefined, 'conv-judge'),
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(dir)).toBe(false);
    });

    it("leaves a user's other conversations untouched", () => {
      const home = tempHome();
      const mine = seedConversation(home, 'conv-judge');
      const theirs = seedConversation(home, 'conv-user-work');
      runJudge([hit], {
        spawn: fakeSpawn(VERDICT_FENCE, undefined, 'conv-judge'),
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(mine)).toBe(false);
      expect(existsSync(theirs)).toBe(true);
    });

    it('removes a single new conversation when the run reported no id', () => {
      const home = tempHome();
      seedConversation(home, 'conv-pre-existing');
      let created = '';
      runJudge([hit], {
        // No conversation_id anywhere in the stream, and the run creates its
        // conversation as a real `agy` would — attribution falls back to the diff.
        spawn: () => {
          created = seedConversation(home, 'conv-new');
          return streamJsonWithoutId(VERDICT_FENCE);
        },
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(created)).toBe(false);
    });

    it('leaves an AMBIGUOUS new conversation alone rather than risk deleting the user’s', () => {
      // Two conversations appear during the run: the judge's and one the user
      // started concurrently in another terminal. Nothing here can tell them
      // apart, and deleting the wrong one is unrecoverable — so neither goes.
      const home = tempHome();
      let a = '';
      let b = '';
      runJudge([hit], {
        spawn: () => {
          a = seedConversation(home, 'conv-a');
          b = seedConversation(home, 'conv-b');
          return streamJsonWithoutId(VERDICT_FENCE);
        },
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(a)).toBe(true);
      expect(existsSync(b)).toBe(true);
    });

    it('falls back to the init event’s id when the result event carries none', () => {
      // The streaming output announces the conversation up front, so a result
      // event that dropped the id is still attributable — which matters because
      // the alternative is the directory diff, and an ambiguous diff leaves a
      // raw-bearing judge transcript on disk for the next backfill to re-ingest.
      const home = tempHome();
      const mine = seedConversation(home, 'conv-from-init');
      const theirs = seedConversation(home, 'conv-user-work');
      runJudge([hit], {
        spawn: () =>
          [
            JSON.stringify({ event: 'init', conversation_id: 'conv-from-init', init: {} }),
            JSON.stringify({ event: 'result', result: { status: 'ok', response: VERDICT_FENCE } }),
            '',
          ].join('\n'),
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(mine)).toBe(false);
      // The control: attribution was the init id, not "remove whatever is here".
      expect(existsSync(theirs)).toBe(true);
    });

    it('keeps the id of the result event whose payload it actually used', () => {
      // A second, malformed result event must not clear the id taken from the
      // first. The response is still read off event #1, so attribution has to
      // stay bound to event #1 too — otherwise cleanup drops to the ambiguous
      // directory diff and leaves a raw-bearing judge transcript on disk for the
      // next backfill to re-ingest.
      const home = tempHome();
      const mine = seedConversation(home, 'conv-A');
      const theirs = seedConversation(home, 'conv-user-work');
      const rec = runJudge([hit], {
        spawn: () =>
          [
            JSON.stringify({
              event: 'result',
              result: { conversation_id: 'conv-A', status: 'ok', response: VERDICT_FENCE },
            }),
            JSON.stringify({ event: 'result', result: 'not-an-object' }),
            '',
          ].join('\n'),
        loadRubric: () => 'RUBRIC',
        home,
      });
      // Positive control: the verdict really did come from event #1, so the
      // attribution assertion below is about a run that produced a result.
      expect(rec.perCategory[0]?.action).toBe('block');
      expect(existsSync(mine)).toBe(false);
      // ...and it was attributed, not swept by "remove whatever appeared".
      expect(existsSync(theirs)).toBe(true);
    });

    it('removes the conversation named by init even when the stream never parses', () => {
      // P1. The id is taken from a scan that cannot throw, so a stream too
      // malformed to yield a verdict is still ATTRIBUTED. Fold the scan back
      // into the throwing `parseEnvelope` call and this leaks: `runJudge` skips
      // the assignment, cleanup drops to the directory diff, and the diff
      // declines to act because two conversations appeared at once.
      const home = tempHome();
      let mine = '';
      let theirs = '';
      const err = errorFrom(() =>
        runJudge([hit], {
          spawn: () => {
            // Created DURING the run, as a real `agy` would, and alongside a
            // session the user started in another terminal — which is what makes
            // the diff ambiguous and the init id the only thing that can attribute.
            mine = seedConversation(home, 'conv-from-init');
            theirs = seedConversation(home, 'conv-user-work');
            return [
              JSON.stringify({ event: 'init', conversation_id: 'conv-from-init' }),
              JSON.stringify({ event: 'result', result: 'not-an-object' }),
              '',
            ].join('\n');
          },
          loadRubric: () => 'RUBRIC',
          home,
        }),
      );
      // Positive control: the stream really was rejected, so this is the
      // throwing path and not a quiet success.
      expect(err?.message).toContain('carried no result object');
      expect(existsSync(mine)).toBe(false);
      // ...and the user's own concurrent session was left alone.
      expect(existsSync(theirs)).toBe(true);
    });

    it('keeps an id already seen when a later event carries none', () => {
      // P2. A second result event with a well-formed payload but no id must not
      // clear the id taken from the first: every turn of a streaming session is
      // one conversation, so an id seen anywhere stays valid for cleanup.
      const home = tempHome();
      let mine = '';
      let theirs = '';
      const rec = runJudge([hit], {
        spawn: () => {
          mine = seedConversation(home, 'conv-A');
          theirs = seedConversation(home, 'conv-user-work');
          return [
            JSON.stringify({
              event: 'result',
              result: { conversation_id: 'conv-A', response: VERDICT_FENCE },
            }),
            JSON.stringify({ event: 'result', result: { response: VERDICT_FENCE } }),
            '',
          ].join('\n');
        },
        loadRubric: () => 'RUBRIC',
        home,
      });
      // Positive control: this path SUCCEEDS — it is not the throwing case above,
      // which is what makes it a distinct guard rather than a restatement.
      expect(rec.perCategory[0]?.action).toBe('block');
      expect(existsSync(mine)).toBe(false);
      expect(existsSync(theirs)).toBe(true);
    });

    // Q1. `conversationDir` is `join(brainRoot, id)` and `join` normalizes, so an
    // id that walks upward escapes the store and is then removed recursively and
    // forcibly. Measured before the guard: `'../../..'` deleted the whole temp
    // HOME — creds and user documents included — and `runJudge` still RETURNED,
    // because the remove's catch reports nothing.
    //
    // The first two rows are the ones a `basename(id) === id` check lets
    // through, which is why the guard is a segment test instead: `basename('.')`
    // is `'.'` and `basename('..')` is `'..'`, so both satisfy it. The backslash
    // row is the platform half — POSIX `basename` returns it unchanged while
    // `win32.join` resolves it to a grandparent, and this plugin runs on Windows.
    it.each([
      ['.', 'the brain root itself — every conversation the user has'],
      ['..', 'the whole Antigravity directory'],
      ['../../..', 'the user’s HOME'],
      ['../../../..', 'the filesystem root'],
      ['..\\..', 'a grandparent, on Windows only'],
      ['/etc', 'an absolute path'],
      ['a/b', 'a nested path'],
    ])('refuses to attribute a conversation id that is not a path segment: %s', (id) => {
      const home = tempHome();
      // One sentinel per level a traversing id reaches, because an assertion
      // that only watches the OUTERMOST level is satisfied by a guard that stops
      // `../../..` and lets `.` through — measured: with a `basename(id) === id`
      // check in place this whole case stayed green, because `.` removes the
      // brain root and `..` the Antigravity directory, and neither is outside
      // `.gemini`. Each row below has to be caught at the level it actually hits.
      const sibling = seedConversation(home, 'conv-someone-elses'); //   .
      const antigravity = join(home, '.gemini', 'antigravity', 'usage.json'); //  ..
      const precious = join(home, '.gemini', 'precious.json'); //       ../..
      writeFileSync(antigravity, 'USAGE');
      writeFileSync(precious, 'CREDS');

      const rec = runJudge([hit], {
        spawn: () =>
          `${JSON.stringify({
            event: 'result',
            result: { conversation_id: id, response: VERDICT_FENCE },
          })}\n`,
        loadRubric: () => 'RUBRIC',
        home,
      });

      // Positive control: the run really did complete, so cleanup really did run
      // with this id rather than the case passing because nothing happened.
      expect(rec.perCategory[0]?.action).toBe('block');
      expect(existsSync(sibling)).toBe(true);
      expect(existsSync(antigravity)).toBe(true);
      expect(existsSync(precious)).toBe(true);
      expect(existsSync(home)).toBe(true);
    });

    it('rejects an unusable id at the delete site too, and still tries the diff', () => {
      // Q1, second site. `cleanupConversation` is exported, so its id argument is
      // a caller's to choose. Rejecting there DROPS the id rather than returning,
      // so the diff still runs — which is what makes this guard observably
      // different from the adoption one and keeps each testable on its own.
      const home = tempHome();
      const precious = join(home, '.gemini', 'precious.json');
      mkdirSync(join(home, '.gemini'), { recursive: true });
      writeFileSync(precious, 'CREDS');
      const appeared = seedConversation(home, 'conv-new');

      cleanupConversation('../../..', new Set(), home);

      expect(existsSync(precious)).toBe(true);
      // ...and the diff attributed the one conversation that did appear.
      expect(existsSync(appeared)).toBe(false);
    });

    it('adopts the id of the result event that supplied the verdict', () => {
      // Q2-b. `??=` is right for init/step_update but must not outrank a result
      // event that carries the verdict actually used: that event names the
      // conversation which produced it, and cleaning up the other one leaves the
      // raw-bearing transcript behind.
      const home = tempHome();
      let used = '';
      let stale = '';
      runJudge([hit], {
        spawn: () => {
          stale = seedConversation(home, 'conv-first');
          used = seedConversation(home, 'conv-that-answered');
          return [
            JSON.stringify({ event: 'init', conversation_id: 'conv-first' }),
            JSON.stringify({
              event: 'result',
              result: { conversation_id: 'conv-that-answered', response: VERDICT_FENCE },
            }),
            '',
          ].join('\n');
        },
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(used)).toBe(false);
      expect(existsSync(stale)).toBe(true);
    });

    it('recovers the id from a failed spawn’s captured stdout', () => {
      // Q3. `agy` printed its init line — so the conversation exists — and then
      // died. The id is in the error's stdout; without reading it, attribution
      // falls to the diff, which declines here because a second conversation
      // appeared, and the raw-bearing transcript survives.
      const home = tempHome();
      let mine = '';
      let theirs = '';
      const err = errorFrom(() =>
        runJudge([hit], {
          spawn: () => {
            mine = seedConversation(home, 'conv-init');
            theirs = seedConversation(home, 'conv-user-work');
            throw Object.assign(new Error(`Command failed: agy ... ${hit.rawMatch}`), {
              status: 1,
              stdout: `${JSON.stringify({ event: 'init', conversation_id: 'conv-init' })}\n`,
              stderr: `run logging ${hit.rawMatch}`,
            });
          },
          loadRubric: () => 'RUBRIC',
          home,
        }),
      );
      // Positive control: this is the failing path, reported raw-free.
      expect(err?.message).toBe('agy judge subprocess failed (exit 1)');
      expectNoEchoOf(err?.message, hit.rawMatch);
      expect(existsSync(mine)).toBe(false);
      expect(existsSync(theirs)).toBe(true);
    });

    it('still removes the conversation when the verdict itself fails to parse', () => {
      // The cleanup is in a finally: a run that errors after the transcript was
      // written must not leave the raw-bearing conversation on disk.
      const home = tempHome();
      const dir = seedConversation(home, 'conv-judge');
      const err = errorFrom(() =>
        runJudge([hit], {
          spawn: fakeSpawn('no fence in this message', undefined, 'conv-judge'),
          loadRubric: () => 'RUBRIC',
          home,
        }),
      );
      expect(err).toBeDefined();
      expect(err?.message).toContain('unparseable');
      expect(existsSync(dir)).toBe(false);
    });
  });

  it('does not fall back to the live spawn when deps.spawn is missing', () => {
    // The seam is required, not defaulted. A future `deps.spawn ?? spawnAgy`
    // would turn any caller that forgot to inject into a live egress. It fails
    // as the programming error it is — a TypeError before the rubric is read
    // or any raw hit is assembled into a prompt.
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
    const scratch = mkdtempSync(join(tmpdir(), 'aka-judge-fault-probe-'));
    const probeLocked = lock(scratch);
    let faultTakes = false;
    try {
      rmSync(scratch, { recursive: true, force: true });
    } catch {
      faultTakes = true;
    }
    if (!faultTakes) ctx.skip('this user can remove a write-protected directory');
    chmodSync(probeLocked, 0o700);
    rmSync(scratch, { recursive: true, force: true });

    // A brain root the judge cannot unlink from: the conversation subdir
    // survives the cleanup, so rmSync throws a real EACCES from a real syscall.
    const home = tempHome();
    seedConversation(home, 'conv-judge');
    const brain = join(home, '.gemini', 'antigravity', 'brain');
    const conversation = join(brain, 'conv-judge');
    chmodSync(brain, 0o500);

    const threw = errorFrom(() =>
      runJudge([hit], {
        spawn: () => {
          throw Object.assign(new Error(`Command failed: agy ... ${hit.rawMatch}`), {
            status: 7,
          });
        },
        loadRubric: () => 'RUBRIC',
        home,
      }),
    );
    try {
      // The fs error from the failed removal did NOT displace the raw-free one
      // the caller has to act on — apply-suppressions prints exactly this
      // message to the parent's stderr.
      expect(threw).toBeDefined();
      expect(threw?.message).toBe('agy judge subprocess failed (exit 7)');
      expectNoEchoOf(threw?.message, hit.rawMatch);
      // The positive control: the conversation survived, so the cleanup really
      // did fail rather than this passing against a removal that quietly worked.
      expect(existsSync(conversation)).toBe(true);
    } finally {
      chmodSync(brain, 0o700);
      rmSync(home, { recursive: true, force: true });
    }
  });
});

describe('the judge spawn is planned, not hand-built', () => {
  // The wizard-journey suites run on the Windows leg only because this spawn
  // reaches a `.cmd` shim through the planner, and only anchor at the user's
  // home because the plan's options reach the spawn. Neither is visible from a
  // POSIX run, so both are pinned here as source facts — the regression has to
  // be noticed on the leg the author is actually on, which is not Windows.
  //
  // Each half is load-bearing and none is enough alone. Measured: a revert that
  // kept `import { planBareCommand }` and built a plain `{ file, args, options }`
  // object in its place satisfied a bare `includes('planBareCommand')`, and a
  // spawn that drops `...plan.options` keeps every planner test green while
  // silently losing the cwd anchor a planted `%COMMAND%.cmd` needs.
  const JUDGE = join(
    dirname(fileURLToPath(import.meta.url)),
    '..',
    '..',
    'src',
    'triage',
    'judge.ts',
  );
  const source = readFileSync(JUDGE, 'utf8');
  const stale =
    'judge.ts no longer builds its spawn from planBareCommand, so a Windows `.cmd` ' +
    'shim is unreachable again and/or the home-directory anchor is gone. Restore it, ' +
    'or re-gate the wizard-journey suites on Windows and rewrite this case to say why.';

  it('feeds the prompt on stdin rather than argv', () => {
    // The source fact behind every raw-off-argv assertion above: `input` is what
    // execFileSync writes to the child's stdin and then closes, and closing stdin
    // is what ends an `--input-format stream-json` session. A spawn that dropped
    // it would hang the child rather than fail, and no in-process fake can see
    // that — the seam takes the string either way.
    expect(
      /input:\s*stdin/.test(source),
      'spawnAgy no longer writes the prompt to the child’s stdin. Restore it: the ' +
        'prompt back on argv is a `ps`-visible raw exposure and puts an `agy.cmd` ' +
        'shim out of reach on Windows.',
    ).toBe(true);
  });

  it('calls the planner rather than merely importing it', () => {
    expect(/\bplanBareCommand\(/.test(source), stale).toBe(true);
  });

  it('spawns the plan’s own file', () => {
    expect(source.includes('execFileSync(plan.file'), stale).toBe(true);
  });

  it('spreads the plan’s options, which is what carries the Windows cwd anchor', () => {
    expect(source.includes('...plan.options'), stale).toBe(true);
  });
});
