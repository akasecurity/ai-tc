import { rmSync } from 'node:fs';

import type { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { judgeEnv, parseVerdict, runJudge } from './judge.ts';

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

  it('spawns claude -p with --no-session-persistence + --output-format json, raw prompt, and parses', () => {
    let seenArgv: readonly string[] = [];
    let seenEnv: NodeJS.ProcessEnv = {};
    const rec = runJudge([hit], {
      spawn: (argv, env) => {
        seenArgv = argv;
        seenEnv = env;
        return envelope(VERDICT_FENCE);
      },
      loadRubric: () => 'RUBRIC BODY',
    });

    expect(seenArgv[0]).toBe('-p');
    expect(seenArgv).toContain('--no-session-persistence');
    expect(seenArgv).toContain('--output-format');
    expect(seenArgv).toContain('json');
    // The full raw hit (rawMatch + context) rides in the prompt — that is the
    // point; SKIP_PROMPT_HISTORY + --no-session-persistence keep it out of any
    // transcript.
    expect(seenArgv.at(-1)).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(seenArgv.at(-1)).toContain('RUBRIC BODY');
    expect(seenEnv.CLAUDE_CODE_SKIP_PROMPT_HISTORY).toBe('1');

    expect(rec.perCategory[0]?.action).toBe('block');
  });
});
