import { existsSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { judgeEnv, parseVerdict, runJudge } from '../../src/triage/judge.ts';

const VERDICT_FENCE = [
  '```json',
  '{"perCategory":[{"category":"secret","action":"block","reasoning":"real","genuineCount":2,"fpCount":2,"fpIds":[]}],"notes":""}',
  '```',
].join('\n');

// The path `codex exec` writes the final assistant message to — named on argv
// right after --output-last-message.
const outFileOf = (argv: readonly string[]): string => {
  const i = argv.indexOf('--output-last-message');
  const path = i >= 0 ? argv[i + 1] : undefined;
  if (path === undefined) throw new Error('no --output-last-message path on argv');
  return path;
};

// A fake spawn that plays the subprocess's one observable role: writing the
// last-message file at the argv-named path.
const fakeSpawn =
  (lastMessage: string, seen?: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; stdin?: string }) =>
  (argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string): void => {
    if (seen) {
      seen.argv = argv;
      seen.env = env;
      seen.stdin = stdin;
    }
    writeFileSync(outFileOf(argv), lastMessage);
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
      try {
        parseVerdict(lastMessage);
        throw new Error('expected parseVerdict to throw');
      } catch (err) {
        expect((err as Error).message).not.toContain(raw);
      }
    }
  });
});

describe('judgeEnv', () => {
  it('inherits the host environment (PATH survives so `codex` resolves)', () => {
    // Session persistence is suppressed by --ephemeral on argv, not by any
    // env var, so the env is a plain inherit — PATH must survive.
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

  it('spawns codex exec with --ephemeral + --skip-git-repo-check, the prompt on stdin, and the verdict from the last-message file', () => {
    const seen: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; stdin?: string } = {};
    const rec = runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC BODY',
    });

    const argv = seen.argv ?? [];
    expect(argv[0]).toBe('exec');
    // --ephemeral is the session-persistence guard: without it the judge
    // session (prompt = rubric + raw hits) lands under ~/.codex/sessions,
    // where AKA's own backfill would re-ingest the raw findings.
    expect(argv).toContain('--ephemeral');
    expect(argv).toContain('--skip-git-repo-check');
    expect(argv).toContain('--output-last-message');
    // `-` = read the prompt from stdin, keeping raw off argv.
    expect(argv.at(-1)).toBe('-');

    // The full raw hit (rawMatch + context) rides on stdin — that is the
    // point; --ephemeral keeps it out of any persisted session, and stdin
    // (unlike argv) keeps it off the process list and out of ARG_MAX.
    expect(seen.stdin).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(seen.stdin).toContain('RUBRIC BODY');
    // The subprocess env is the inherited host env (PATH + CODEX_HOME auth),
    // untouched — exactly what judgeEnv() snapshots.
    expect(seen.env).toEqual(judgeEnv());

    expect(rec.perCategory[0]?.action).toBe('block');
  });

  it('passes the prompt on stdin, never in argv, and cleans up the temp output dir', () => {
    const seen: { argv?: readonly string[]; stdin?: string } = {};
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
      },
    );
    const argv = seen.argv ?? [];
    expect(argv.join(' ')).not.toContain('AKIAREALKEY');
    expect(seen.stdin).toContain('AKIAREALKEY'); // raw rides stdin, isolated subprocess only
    expect(rec.notes).toBe('ok');
    // The mkdtemp dir holding the last-message file is removed after the run.
    expect(existsSync(dirname(outFileOf(argv)))).toBe(false);
  });

  // The consent copy in the setup skill and both READMEs enumerates what
  // crosses to the model API field by field. runJudge serializes the whole
  // TriageHit, so a new field on that schema silently widens the payload past
  // what the user was told. Pin the exact key set: adding one here is a
  // deliberate act that forces the disclosure copy to be updated with it.
  it('sends exactly the disclosed TriageHit fields — no undisclosed payload', () => {
    const seen: { stdin?: string } = {};
    runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
    });

    // The hits ride as JSONL inside the prompt's last fenced block.
    const fenced = /```\n([\s\S]*?)\n```\n?$/.exec(seen.stdin ?? '');
    if (fenced?.[1] === undefined) throw new Error('no fenced hit block on stdin');
    const lines = fenced[1].split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    const [hitLine] = lines;
    if (hitLine === undefined) throw new Error('no hit line on stdin');

    const sent = JSON.parse(hitLine) as Record<string, unknown>;
    expect(Object.keys(sent).sort()).toEqual([
      'category',
      'confidence',
      'context',
      'maskedMatch',
      'rawMatch',
      'ruleId',
      'severity',
    ]);
    // The three the disclosure calls out by name: the secret itself, the
    // surrounding transcript window, and (when present) the source path.
    expect(sent.rawMatch).toBe(hit.rawMatch);
    expect(sent.context).toBe(hit.context);

    const seenWithPath: { stdin?: string } = {};
    runJudge([{ ...hit, filePath: '/Users/dev/.codex/sessions/2026/01/01/rollout-x.jsonl' }], {
      spawn: fakeSpawn(VERDICT_FENCE, seenWithPath),
      loadRubric: () => 'RUBRIC',
    });
    expect(seenWithPath.stdin).toContain('/Users/dev/.codex/sessions/2026/01/01/rollout-x.jsonl');
  });

  it('fails loud (and raw-free) when the subprocess writes no last-message file', () => {
    // A spawn that exits cleanly but never writes the file — the verdict is
    // unreadable and must not pass silently.
    try {
      runJudge([hit], { spawn: () => undefined, loadRubric: () => 'RUBRIC' });
      throw new Error('expected runJudge to throw');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain('no last-message file');
      expect(message).not.toContain(hit.rawMatch);
    }
  });

  it('re-throws a spawn failure as raw-free metadata (execFileSync captures raw-bearing output)', () => {
    // execFileSync throws an error whose captured .stdout/.stderr can carry raw
    // content (`codex exec` logs the run, which can echo the prompt). Simulate
    // that shape and assert the raw value never rides the re-thrown error out
    // to the parent stderr.
    const spawn = (): void => {
      const err = new Error(`Command failed: codex exec`) as Error & {
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
      expect(message).not.toContain(hit.rawMatch);
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
