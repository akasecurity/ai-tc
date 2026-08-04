import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { TriageHit } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import type { JudgeDeps } from '../../src/triage/judge.ts';
import { judgeEnv, parseVerdict, runJudge, toJudgePayload } from '../../src/triage/judge.ts';

const VERDICT_FENCE = [
  '```json',
  '{"perCategory":[{"category":"secret","action":"block","reasoning":"real","genuineCount":2,"fpCount":2,"fpIds":[]}],"notes":""}',
  '```',
].join('\n');

// The prompt `agy` is run with — argv position right after -p. On this host the
// prompt rides argv rather than stdin, because the CLI documents no stdin input.
const promptOf = (argv: readonly string[]): string => {
  const i = argv.indexOf('-p');
  const prompt = i >= 0 ? argv[i + 1] : undefined;
  if (prompt === undefined) throw new Error('no -p prompt on argv');
  return prompt;
};

// A fake spawn that plays the subprocess's one observable role: printing the
// `--output-format json` envelope on stdout. `conversationId` controls what the
// run claims to have created, so cleanup can be driven from a test.
const fakeSpawn =
  (
    lastMessage: string,
    seen?: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; prompt?: string },
    conversationId = 'conv-judge',
  ) =>
  (argv: readonly string[], env: NodeJS.ProcessEnv): string => {
    if (seen) {
      seen.argv = argv;
      seen.env = env;
      seen.prompt = promptOf(argv);
    }
    return JSON.stringify({
      conversation_id: conversationId,
      status: 'ok',
      response: lastMessage,
    });
  };

// Capture the error OUTSIDE the catch. The `try { call(); throw new Error(...) }
// catch (e) { assert on e }` shape asserts on the test's OWN guard error when
// the call stops throwing, so a raw-absence check passes vacuously. Returning
// undefined for a call that did not throw is what makes toBeDefined() catch it.
const errorFrom = (fn: () => unknown): Error | undefined => {
  try {
    fn();
    return undefined;
  } catch (e) {
    return e as Error;
  }
};

// Every runJudge call must be pointed at a throwaway home. The judge deletes
// the conversation its own run created, and an unset `home` resolves to the
// REAL ~/.gemini/antigravity-cli/brain on whatever machine runs this suite.
const tempHome = (): string => mkdtempSync(join(tmpdir(), 'aka-judge-home-'));

// Seed a conversation directory under a throwaway home's brain root.
const seedConversation = (home: string, id: string): string => {
  const dir = join(home, '.gemini', 'antigravity-cli', 'brain', id);
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

  it('runs `agy -p <prompt> --output-format json` and reads the verdict from the envelope', () => {
    const seen: { argv?: readonly string[]; env?: NodeJS.ProcessEnv; prompt?: string } = {};
    const rec = runJudge([hit], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC BODY',
      home: mkdtempSync(join(tmpdir(), 'aka-judge-home-')),
    });

    const argv = seen.argv ?? [];
    // -p is the documented headless entrypoint; there is no `exec` subcommand
    // on this host and no --ephemeral/--output-last-message to pass.
    expect(argv[0]).toBe('-p');
    expect(argv).toContain('--output-format');
    expect(argv[argv.indexOf('--output-format') + 1]).toBe('json');
    expect(argv).not.toContain('exec');
    expect(argv).not.toContain('--ephemeral');

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

  it('carries the raw hits in ARGV — the documented regression this host forces', () => {
    // The Codex/Claude judges keep raw off argv by feeding the prompt on stdin.
    // `agy` documents no stdin input, so raw DOES ride argv here and is visible
    // to `ps` for the life of the run. Pin it as a deliberate, disclosed
    // property rather than letting it flip silently: if the host ever grows a
    // stdin or prompt-file input, this test is what says the consent copy and
    // the module header have to be revisited too.
    const seen: { argv?: readonly string[]; prompt?: string } = {};
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
    expect((seen.argv ?? []).join(' ')).toContain('AKIAREALKEY');
    expect(seen.prompt).toContain('AKIAREALKEY');
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
        '/Users/dev/.gemini/antigravity-cli/brain/conv-x/.system_generated/logs/transcript.jsonl',
      valueFingerprint: 'HMAC-of-the-secret',
      keyVersion: 1,
    };
    const seen: { prompt?: string } = {};
    runJudge([full], {
      spawn: fakeSpawn(VERDICT_FENCE, seen),
      loadRubric: () => 'RUBRIC',
      home: tempHome(),
    });

    // The hits ride as JSONL inside the prompt's last fenced block.
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
    expect(sent.context).not.toContain(hit.rawMatch);
    expect(sent.context).toContain('export KEY=');
    // The dropped provenance/correlator fields never reach the model.
    expect(seen.prompt).not.toContain(
      '/Users/dev/.gemini/antigravity-cli/brain/conv-x/.system_generated/logs/transcript.jsonl',
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
    expect(seen.prompt).not.toContain(contextOnlySecret);
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
    expect(err?.message).not.toContain(hit.rawMatch);
  });

  it.each([
    ['not JSON at all', 'was not valid JSON'],
    ['[1,2,3]', 'was not a JSON object'],
    ['{"conversation_id":"c"}', 'carried no response string'],
  ])('fails loud (and raw-free) on a malformed envelope: %s', (stdout, expected) => {
    const err = errorFrom(() =>
      runJudge([hit], { spawn: () => stdout, loadRubric: () => 'RUBRIC', home: tempHome() }),
    );
    expect(err).toBeDefined();
    expect(err?.message).toContain(expected);
    expect(err?.message).not.toContain(hit.rawMatch);
  });

  it('re-throws a spawn failure as raw-free metadata (the error echoes raw-bearing argv)', () => {
    // On this host the prompt rides ARGV, so execFileSync's own error message
    // ("Command failed: agy -p <the whole prompt>") carries every raw hit
    // outright — as can its captured .stdout/.stderr. Simulate that shape and
    // assert none of it rides the re-thrown error out to the parent stderr.
    const spawn = (): string => {
      const err = new Error(
        `Command failed: agy -p RUBRIC ... ${hit.rawMatch} ... --output-format json`,
      ) as Error & { status?: number; stdout?: string; stderr?: string };
      err.status = 1;
      err.stdout = `partial output leaking ${hit.rawMatch}`;
      err.stderr = 'boom';
      throw err;
    };
    const err = errorFrom(() =>
      runJudge([hit], { spawn, loadRubric: () => 'RUBRIC', home: tempHome() }),
    );
    expect(err).toBeDefined();
    const message = err?.message ?? '';
    expect(message).not.toContain(hit.rawMatch);
    expect(message).not.toContain('export KEY=');
    // still useful: it names the failure + surfaces the raw-free exit status
    expect(message).toContain('judge subprocess failed');
    expect(message).toContain('exit 1');
    // and the raw-bearing spawn error is NOT chained as `cause` — a future
    // `{ cause: err }` would re-expose the prompt via util.inspect/loggers.
    expect(err?.cause).toBeUndefined();
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
        // No conversation_id in the envelope, and the run creates its
        // conversation as a real `agy` would — attribution falls back to the diff.
        spawn: () => {
          created = seedConversation(home, 'conv-new');
          return JSON.stringify({ status: 'ok', response: VERDICT_FENCE });
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
          return JSON.stringify({ status: 'ok', response: VERDICT_FENCE });
        },
        loadRubric: () => 'RUBRIC',
        home,
      });
      expect(existsSync(a)).toBe(true);
      expect(existsSync(b)).toBe(true);
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

    // A brain root the judge cannot unlink from: the conversation subdir
    // survives the cleanup, so rmSync throws a real EACCES from a real syscall.
    const home = tempHome();
    seedConversation(home, 'conv-judge');
    const brain = join(home, '.gemini', 'antigravity-cli', 'brain');
    const conversation = join(brain, 'conv-judge');
    chmodSync(brain, 0o500);

    const threw = errorFrom(() =>
      runJudge([hit], {
        spawn: () => {
          throw Object.assign(new Error(`Command failed: agy -p ... ${hit.rawMatch}`), {
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
      expect(threw?.message).not.toContain(hit.rawMatch);
      // The positive control: the conversation survived, so the cleanup really
      // did fail rather than this passing against a removal that quietly worked.
      expect(existsSync(conversation)).toBe(true);
    } finally {
      chmodSync(brain, 0o700);
      rmSync(home, { recursive: true, force: true });
    }
  });
});
