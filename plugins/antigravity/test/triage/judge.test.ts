import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { JudgeDeps } from '../../src/triage/judge.ts';
import { judgeEnv, parseVerdict, runJudge, toJudgePayload } from '../../src/triage/judge.ts';

const VERDICT_FENCE = [
  '```json',
  '{"perCategory":[{"category":"secret","action":"block","reasoning":"real","genuineCount":2,"fpCount":2,"fpIds":[]}],"notes":""}',
  '```',
].join('\n');

// The path `antigravity exec` writes the final assistant message to — named on argv
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
  (
    lastMessage: string,
    seen?: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; stdin?: string },
  ) =>
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
  it('inherits the host environment (PATH survives so `antigravity` resolves)', () => {
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

  it('spawns antigravity exec with --ephemeral + --skip-git-repo-check, the prompt on stdin, and the verdict from the last-message file', () => {
    const seen: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; stdin?: string } = {};
    const rec = runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC BODY',
    });

    const argv = seen.argv ?? [];
    expect(argv[0]).toBe('exec');
    // --ephemeral is the session-persistence guard: without it the judge
    // session (prompt = rubric + raw hits) lands under ~/.gemini/sessions,
    // where AKA's own backfill would re-ingest the raw findings.
    expect(argv).toContain('--ephemeral');
    expect(argv).toContain('--skip-git-repo-check');
    expect(argv).toContain('--output-last-message');
    // `-` = read the prompt from stdin, keeping raw off argv.
    expect(argv.at(-1)).toBe('-');

    // rawMatch rides on stdin — the rubric judges the actual value;
    // --ephemeral keeps it out of any persisted session, and stdin (unlike
    // argv) keeps it off the process list and out of ARG_MAX. filePath is
    // dropped and context is masked before it crosses (covered below), so
    // rawMatch is the only raw field that leaves.
    expect(seen.stdin).toContain('AKIAIOSFODNN7EXAMPLE');
    expect(seen.stdin).toContain('RUBRIC BODY');
    // The subprocess env is the inherited host env (PATH + GEMINI_HOME auth),
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
      filePath: '/Users/dev/.antigravity/sessions/2026/01/01/rollout-x.jsonl',
      valueFingerprint: 'HMAC-of-the-secret',
      keyVersion: 1,
    };
    const seen: { stdin?: string } = {};
    runJudge([full], {
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
    expect(seen.stdin).not.toContain('/Users/dev/.antigravity/sessions/2026/01/01/rollout-x.jsonl');
    expect(seen.stdin).not.toContain('HMAC-of-the-secret');
    expect(seen.stdin).not.toContain('filePath');
    expect(seen.stdin).not.toContain('valueFingerprint');
  });

  it('drops filePath from the judge payload (it encodes the OS username and project dirs)', () => {
    const seen: { stdin?: string } = {};
    runJudge([{ ...hit, filePath: '/Users/alicesecret/projects/topsecret/rollout.jsonl' }], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
    });
    expect(seen.stdin).not.toContain('alicesecret');
    expect(seen.stdin).not.toContain('topsecret');
    expect(seen.stdin).not.toContain('filePath');
  });

  it('masks a secret that appears only in the context window; rawMatch stays legible', () => {
    // A second, distinct AWS key living ONLY in the surrounding context — not the
    // finding's own value. It must not cross to the model.
    const contextOnlySecret = ['AKIA', 'ZYXWVUTSRQPONMLK'].join('');
    const seen: { stdin?: string } = {};
    runJudge([{ ...hit, context: `aws_a=${hit.rawMatch} aws_b=${contextOnlySecret}` }], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
    });
    expect(seen.stdin).toContain(hit.rawMatch);
    expect(seen.stdin).not.toContain(contextOnlySecret);
    // Positive check: masking stays SELECTIVE, not a blanket redaction. If
    // maskText fell back to its fail-secure `[REDACTED]` path, the two assertions
    // above would still hold while the window the judge relies on was gone — so
    // pin that the non-secret structure of the context survives.
    expect(seen.stdin).toContain('aws_a=');
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
    // content (`antigravity exec` logs the run, which can echo the prompt). Simulate
    // that shape and assert the raw value never rides the re-thrown error out
    // to the parent stderr.
    const spawn = (): void => {
      const err = new Error(`Command failed: antigravity exec`) as Error & {
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

  it('does not fall back to the live spawn when deps.spawn is missing', () => {
    // The seam is required, not defaulted. A future `deps.spawn ?? spawnCodex`
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
    expect(err.message).not.toContain(hit.rawMatch);
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

    let outDir = '';
    let locked = '';
    const threw = (() => {
      try {
        runJudge([hit], {
          spawn: (argv) => {
            outDir = dirname(outFileOf(argv));
            locked = lock(outDir);
            throw Object.assign(new Error(`Command failed: antigravity ${hit.rawMatch}`), {
              status: 7,
            });
          },
          loadRubric: () => 'RUBRIC',
        });
      } catch (e) {
        return e as Error;
      }
      throw new Error('expected runJudge to throw');
    })();
    try {
      // The fs error from the failed removal did NOT displace the raw-free one
      // the caller has to act on — apply-suppressions prints exactly this
      // message to the parent's stderr.
      expect(threw.message).toBe('antigravity exec judge subprocess failed (exit 7)');
      expect(threw.message).not.toContain(hit.rawMatch);
      // The positive control: the dir survived, so the cleanup really did fail
      // rather than this passing against a removal that quietly worked.
      expect(existsSync(outDir)).toBe(true);
    } finally {
      if (locked !== '') chmodSync(locked, 0o700);
      rmSync(outDir, { recursive: true, force: true });
    }
  });
});
