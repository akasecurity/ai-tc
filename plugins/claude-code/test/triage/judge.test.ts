import { rmSync } from 'node:fs';

import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { judgeEnv, parseVerdict, runJudge } from '../../src/triage/judge.ts';

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

describe('judgeEnv', () => {
  it('sets CLAUDE_CODE_SKIP_PROMPT_HISTORY=1 (and a fresh CLAUDE_CONFIG_DIR on darwin)', () => {
    const env = judgeEnv();
    try {
      expect(env.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');
      if (process.platform === 'darwin') expect(env.CLAUDE_CONFIG_DIR).toBeTruthy();
    } finally {
      if (env.CLAUDE_CONFIG_DIR) rmSync(env.CLAUDE_CONFIG_DIR, { recursive: true, force: true });
    }
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
