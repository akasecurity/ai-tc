/**
 * aka-setup, model-judge consent DECLINED — proven end-to-end against the REAL
 * built script chain (the scripts/*.js the skill actually shells out to).
 *
 * The distinct model-judge consent (step 3 of skills/setup/SKILL.md) is what
 * authorizes the only egress in the product: apply-suppressions' `agy`
 * judge. The adapter's unit tests inject the gate as a plain boolean, so the
 * wiring that reads the real settings.json
 * (apply-suppressions.ts: `loadConfig().settings.modelJudgeConsent`) is never
 * exercised in the refusing direction. Inverting that boolean, or reading the
 * wrong field, would leave every other test green.
 *
 * This leg closes that gap at the process boundary. Historical access IS
 * granted (so the backfill really reads the seeded rollout and produces hits —
 * the refusal is not a vacuous empty scan), the model-judge consent is NOT, and
 * the preview then has to skip the judge:
 *
 *   onboard.js --historical full → backfill.js --triage
 *            → apply-suppressions.js (preview, no consent)
 *
 * The load-bearing assertion is `judgeWasInvoked()`: the harness puts a stub
 * `agy` first on the child PATH which touches a sentinel when executed, so
 * this proves no judge subprocess ever ran — not merely that a mock went
 * uncalled. Nothing can reach the model API on this path.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bundledDetections } from '@akasecurity/plugin-sdk';
import { planBareCommand } from '@akasecurity/plugin-sdk/bare-command';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import {
  assertShimResolves,
  nodeOnlyPathEntries,
  SHIM_PROBE_ARG,
  shimmedPath,
  WINDOWS_SYSTEM_DIRS,
  WINDOWS_SYSTEM_ENV,
  writeCommandShim,
} from '../helpers/path-shim.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/journey -> plugins/antigravity
const SCRIPTS_DIR = join(HERE, '..', '..', 'scripts');

const DAY_MS = 24 * 60 * 60 * 1000;

// The seeded secret comes from the bundled rule's own `examples` fixture so no
// secret-shaped literal lives in this file (mirrors hooks/user-prompt-submit.test.ts).
const RULE_ID = 'secrets/twilio-key';
function ruleExample(): string {
  const example = bundledDetections()
    .flatMap((pack) => pack.rules)
    .find((rule) => rule.id === RULE_ID)?.examples?.[0];
  if (example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return example;
}
const SURFACED_KEY = ruleExample();

interface StepResult {
  stdout: string;
  stderr: string;
  status: number;
}

// Drives the built wizard scripts in frame order against a throwaway home. The
// scripts resolve ~/.aka and ~/.gemini via os.homedir(), which honors $HOME on
// POSIX, so pointing HOME at a temp dir isolates the whole chain — no
// script-level flag or process.env read is added to shipped code. The child env
// is built from scratch (never the host env): PATH carries only the stub-judge
// bin dir plus a dir holding node ALONE, so a real `agy` on the developer's
// PATH is not reachable through it, and the shebang still finds node. Node
// alone, never node's own bin dir: under nvm, or any prefix node shares with
// its global installs, that dir is where `npm i -g` puts a real `agy` too. That
// is a narrower claim than "the stub is the only resolvable judge" — PATH is
// not the whole of resolution (Windows searches the working and system
// directories first), and a stub that fails to land is answered by whatever
// is, not by an ENOENT. assertShimResolves in run() is what closes that gap.
class SetupJourney {
  readonly home: string;
  // The settings.json the onboarding writer records the consent into.
  readonly settingsPath: string;
  private readonly binDir: string;
  // The interpreter for the stub's shebang, and nothing that lives beside it.
  // Nested under the stub dir so it rides that dir's cleanup; being inside a
  // dir on PATH does not put it on PATH, so it is listed there by itself.
  // Empty on win32, where the `.cmd` shim names its interpreter outright and
  // nothing reads a shebang at all.
  private readonly nodeDirs: string[];
  private shimProven = false;

  constructor() {
    this.home = mkdtempSync(join(tmpdir(), 'aka-antigravity-journey-home-'));
    this.settingsPath = join(this.home, '.aka', 'settings', 'settings.json');
    this.binDir = mkdtempSync(join(tmpdir(), 'aka-antigravity-journey-bin-'));
    this.nodeDirs = nodeOnlyPathEntries(this.binDir);
    this.writeFakeJudge();
  }

  cleanup(): void {
    removeTrees([this.home, this.binDir]);
  }

  // Whether the stub `agy` judge was actually executed. The stub touches a
  // sentinel on every invocation, so a consent-gate test can assert the egress
  // never happened at the process boundary — not merely that a mocked function
  // went uncalled.
  judgeWasInvoked(): boolean {
    return existsSync(this.judgeSentinelPath);
  }

  // Raw-free metadata about the prompt the stub judge actually READ off its
  // stdin, or undefined when it never ran.
  //
  // `judgeWasInvoked()` alone cannot see this: the stub touches its sentinel
  // before reading anything, so a chain that spawned the judge and delivered it
  // NOTHING still reports an invocation, still parses a (hit-free) verdict, and
  // still saves a plan. Measured — deleting `input: stdin` from spawnAgy left
  // every case in this file green. Prompt delivery is exactly what the stdin
  // move put at risk, and the Windows leg (a `.cmd` launcher forwarding argv
  // with `%*`, stdin passing through it untouched) is the one this suite was
  // skipped on until that move, so it is the leg with no other coverage at all.
  //
  // Metadata rather than the prompt itself: the prompt carries the seeded raw
  // key, and a sentinel is not a place to write one.
  judgePromptShape(): { bytes: number; lines: number; hits: number } | undefined {
    if (!existsSync(this.judgeSentinelPath)) return undefined;
    const recorded = readFileSync(this.judgeSentinelPath, 'utf8');
    if (recorded === '') return undefined;
    return JSON.parse(recorded) as { bytes: number; lines: number; hits: number };
  }

  private get judgeSentinelPath(): string {
    return join(this.binDir, 'judge-invoked');
  }

  // Seed one scannable transcript under the real brain layout, carrying the
  // bundled rule's example key and timestamped inside the retention window but
  // before the scan starts, so the backfill has real history to calibrate from.
  //
  // The PATH here is verified against Antigravity's documentation. The RECORD
  // SHAPE is NOT: it is the Codex rollout line this package's parser still
  // decodes (see history/transcripts.ts's STATUS note), used here because this
  // suite's subject is the CONSENT GATE — whether the judge subprocess is
  // spawned at all — and that gate is indifferent to how the text was parsed
  // out. Do not read a green run here as coverage of Antigravity's real
  // transcript format; when the parser is ported against a live sample, this
  // fixture moves with it.
  seedRollout(): string {
    const logDir = join(
      this.home,
      '.gemini',
      'antigravity',
      'brain',
      'conv-2026-07-27-consent',
      '.system_generated',
      'logs',
    );
    mkdirSync(logDir, { recursive: true });
    const occurredAt = new Date(Date.now() - 3 * DAY_MS).toISOString();
    const line = JSON.stringify({
      source: 'USER_EXPLICIT',
      type: 'USER_INPUT',
      status: 'DONE',
      step_index: 0,
      created_at: occurredAt,
      content: `please deploy with this key: ${SURFACED_KEY}`,
    });
    // The untruncated file — the one the walk prefers when both are present.
    const rolloutPath = join(logDir, 'transcript_full.jsonl');
    writeFileSync(rolloutPath, `${line}\n`);
    return rolloutPath;
  }

  // Consent side effect — record the historical-review answer (`full` grants
  // the scan permission to READ prior rollouts).
  onboardHistorical(access: 'full' | 'session-only'): StepResult {
    return this.run('onboard.js', ['--historical', access]);
  }

  // Consent side effect — record the DISTINCT model-judge egress consent the
  // wizard collects (step 3) before piping findings into the judge.
  onboardModelJudge(): StepResult {
    return this.run('onboard.js', ['--model-judge-consent']);
  }

  // The backfill triage stream (JSONL + sentinel).
  backfillTriage(): StepResult {
    return this.run('backfill.js', ['--triage']);
  }

  // The calibration preview: judge (stubbed), plan, gate, frame JSON. Takes
  // the backfill stream on stdin.
  applyPreview(triageStream: string): StepResult {
    return this.run('apply-suppressions.js', [], triageStream);
  }

  private run(script: string, args: string[], input?: string): StepResult {
    const env: NodeJS.ProcessEnv = {
      HOME: this.home,
      // Windows resolves the home dir from USERPROFILE; keep both in lockstep.
      USERPROFILE: this.home,
      // Stub judge first on PATH so apply-suppressions' `agy` spawn hits
      // it, never a live model; a dir holding node ALONE second so the stub's
      // `#!/usr/bin/env node` shebang resolves — that shebang is the POSIX
      // branch of writeCommandShim. On Windows the stub is a .cmd naming an
      // absolute node, so there is no shebang to serve and the list is empty;
      // shimmedPath then yields the stub dir alone.
      //
      // Nothing else from the host environment reaches the chain — except the
      // Windows OS plumbing below, which is not "else" so much as the platform:
      // cmd.exe and where.exe live under System32, and Node reads the
      // interpreter's own location out of COMSPEC, so without them the chain
      // cannot spawn even its OWN stub and this suite would report "the judge
      // never ran" for a reason that is not the consent gate. Both are empty off
      // win32, and no `agy` lives in System32, so the stub stays the only
      // resolvable one.
      PATH: shimmedPath(this.binDir, [...this.nodeDirs, ...WINDOWS_SYSTEM_DIRS].join(delimiter)),
      ...WINDOWS_SYSTEM_ENV,
    };
    // Proven once per journey, before the first script runs. A shim that does
    // not land does NOT fail closed: resolution keeps walking PATH and finds a
    // real installed `agy`, so the chain would reach a live model and this
    // suite's load-bearing `judgeWasInvoked()` assertion would pass for the
    // wrong reason — nothing ran because nothing COULD run.
    //
    // spawnAgy builds its spawn with planBareCommand, so the probe READS that
    // plan's decisions rather than re-deriving them: on Windows `shell` is the
    // difference between resolving a .cmd and skipping it, and the plan also
    // anchors the spawn at the user's home, which is where `agy` is resolved
    // from there. On POSIX the plan sets neither and this is a no-op.
    if (!this.shimProven) {
      const plan = planBareCommand('agy', [SHIM_PROBE_ARG], { env });
      assertShimResolves('agy', env, {
        shell: plan.viaShell,
        ...(plan.options.cwd === undefined ? {} : { cwd: plan.options.cwd }),
      });
      this.shimProven = true;
    }
    // spawnSync (not execFileSync) so BOTH streams are captured on the success
    // path too — the stderr assertions below must see what a wizard transcript
    // would see, and execFileSync only surfaces stderr when the child fails.
    const result = spawnSync(process.execPath, [join(SCRIPTS_DIR, script), ...args], {
      env,
      encoding: 'utf8',
      ...(input !== undefined ? { input } : {}),
      maxBuffer: 64 * 1024 * 1024,
    });
    return {
      stdout: result.stdout,
      stderr: result.stderr,
      status: result.status ?? 1,
    };
  }

  // A controlled `agy` on PATH: apply-suppressions' judge spawns
  // `agy --input-format stream-json --output-format stream-json` and writes the
  // prompt to the child's stdin as one NDJSON `user` event (see triage/judge.ts's
  // spawnAgy). This stub reads that event off stdin, parses the hits out of the
  // prompt's trailing fenced block, and prints a deterministic, raw-free
  // TriageRecommendation inside a stream-json `result` event on stdout — the
  // first hit per (category, rule) surfaced (genuine), the rest marked routine
  // false positives. No live model is ever hit.
  private writeFakeJudge(): void {
    const body = `// Record that the judge actually ran, so a test can prove the consent gate
// stopped the egress at the process boundary (see judgeWasInvoked).
const SENTINEL = ${JSON.stringify(this.judgeSentinelPath)};
require('node:fs').writeFileSync(SENTINEL, '');
// fd 0 read synchronously: the parent writes the whole event and closes stdin,
// which is what ends an --input-format stream-json session.
const stdinRaw = require('node:fs').readFileSync(0, 'utf8');
let prompt = '';
for (const line of stdinRaw.split('\\n')) {
  if (!line.trim()) continue;
  let event;
  try { event = JSON.parse(line); } catch { continue; }
  if (event && event.event === 'user' && event.message && typeof event.message.content === 'string') {
    prompt = event.message.content;
  }
}
// Simulate agy's run logging on stderr, prompt content included. The parent's
// spawnAgy must swallow this stream entirely: the parent command's stderr flows
// into the wizard conversation, whose transcripts the backfill later scans.
process.stderr.write('JUDGE-STDERR-RUN-LOGGING ' + prompt);
const fences = [...String(prompt).matchAll(/\`\`\`[a-z]*\\n([\\s\\S]*?)\`\`\`/g)];
const block = fences.length ? fences[fences.length - 1][1] : '';
const byCategory = new Map();
let hitCount = 0;
for (const line of block.split('\\n')) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  let hit;
  try { hit = JSON.parse(trimmed); } catch { continue; }
  if (!hit || typeof hit.category !== 'string' || typeof hit.id !== 'string' || typeof hit.ruleId !== 'string') continue;
  hitCount += 1;
  const byRule = byCategory.get(hit.category) ?? new Map();
  const ids = byRule.get(hit.ruleId) ?? [];
  ids.push(hit.id);
  byRule.set(hit.ruleId, ids);
  byCategory.set(hit.category, byRule);
}
// Record what actually ARRIVED, so a test can prove the prompt crossed the
// process boundary rather than only that the process started. Metadata only —
// the prompt carries the seeded raw key.
//
// \`hits\` counts the hit lines PARSED OUT OF THE FENCED BLOCK, never matches
// over the whole prompt: the rubric itself carries a \`"ruleId"\` in its shape
// example, so a whole-prompt match is >= 1 with no hits delivered at all and
// the assertion that reads it would prove nothing.
require('node:fs').writeFileSync(SENTINEL, JSON.stringify({
  bytes: Buffer.byteLength(prompt, 'utf8'),
  lines: prompt.split('\\n').length,
  hits: hitCount,
}));
const perCategory = [];
for (const [category, byRule] of byCategory) {
  let genuineCount = 0;
  const fps = [];
  for (const ids of byRule.values()) {
    ids.sort();
    genuineCount += 1;
    fps.push(...ids.slice(1));
  }
  perCategory.push({
    category,
    action: 'warn',
    reasoning: 'canonical example key — routine placeholder, no live credential',
    genuineCount,
    fpCount: fps.length,
    fpIds: fps,
  });
}
const verdict = { perCategory, notes: 'looks routine' };
// --output-format stream-json: NDJSON, one typed event per line. The parent
// reads the verdict off the terminal \`result\` event's \`response\` field, and
// takes the conversation id it must then delete from either event.
process.stdout.write(JSON.stringify({
  event: 'init',
  conversation_id: 'conv-fake-judge',
  init: { cwd: process.cwd() },
}) + '\\n');
process.stdout.write(JSON.stringify({
  event: 'result',
  result: {
    conversation_id: 'conv-fake-judge',
    status: 'ok',
    num_turns: 1,
    response: '\`\`\`json\\n' + JSON.stringify(verdict) + '\\n\`\`\`',
  },
}) + '\\n');
`;
    // writeCommandShim owns the shebang, the mode bits and — on Windows — the
    // .cmd launcher that makes a bare `agy` resolvable at all.
    writeCommandShim(this.binDir, 'agy', body);
  }
}

describe('aka-setup journey — model-judge consent declined', () => {
  const journey = new SetupJourney();
  let triageStream = '';
  let preview: StepResult;

  beforeAll(() => {
    journey.seedRollout();
    // Historical access granted: the scan may READ local rollouts. That grant
    // deliberately does NOT carry model-judge consent — the two are separate.
    journey.onboardHistorical('full');
    triageStream = journey.backfillTriage().stdout;
    preview = journey.applyPreview(triageStream);
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('reads real history, so the skip is a refusal and not an empty scan', () => {
    // The backfill genuinely found the seeded key: there WAS something to judge.
    expect(triageStream).toContain(SURFACED_KEY);
  });

  it('exits clean — the refusal is a handled branch, not a crash', () => {
    expect(preview.status).toBe(0);
  });

  it('never spawns the judge subprocess — nothing reaches the model API', () => {
    expect(journey.judgeWasInvoked()).toBe(false);
  });

  it('says plainly that nothing was sent, without claiming a clean bill of health', () => {
    expect(preview.stdout).toContain(
      "I didn't send anything to the model — model-judge consent wasn't granted.",
    );
    // The scan-ran-clean copy would report a clean result for a judgment that
    // never ran. Hits existed; they were simply never rated.
    expect(preview.stdout).not.toContain('nothing needs your attention');
  });

  it('still emits a parseable zero-count frame so the wizard can degrade', () => {
    // The wizard reaches this pipe expecting a frame; a bare line would leave it
    // mid-flow with nothing to read.
    const frame = /<<<AKA_FRAME_JSON\s*([\s\S]*?)\s*AKA_FRAME_JSON>>>/.exec(preview.stdout);
    expect(frame?.[1]).toBeDefined();
    const parsed = JSON.parse(frame?.[1] ?? '{}') as { counts?: { total?: number } };
    expect(parsed.counts?.total).toBe(0);
  });

  it('writes no calibration plan — there is no judged result to confirm', () => {
    expect(preview.stdout).not.toContain('Plan saved to:');
  });

  it('records the historical grant but no model-judge consent in settings.json', () => {
    const settings = JSON.parse(readFileSync(journey.settingsPath, 'utf8')) as {
      historicalAccess?: string;
      modelJudgeConsent?: unknown;
    };
    // The two grants are independent: reading history was allowed, sending was not.
    expect(settings.historicalAccess).toBe('full');
    expect(settings.modelJudgeConsent).toBeUndefined();
  });
});

// The control for the leg above. `judgeWasInvoked() === false` only means
// something if the sentinel would have been written had the judge run — so
// drive the identical chain WITH consent and assert the spawn is detected.
// Without this, a broken sentinel would make the no-consent assertion
// vacuously green.
describe('aka-setup journey — model-judge consent granted (control)', () => {
  const journey = new SetupJourney();
  // Captured mid-chain: the sentinel's state after the historical grant but
  // BEFORE the model-judge consent, which is the moment that distinguishes the
  // two grants.
  let invokedBeforeConsent = true;
  let preview: StepResult;

  beforeAll(() => {
    journey.seedRollout();
    journey.onboardHistorical('full');
    invokedBeforeConsent = journey.judgeWasInvoked();

    journey.onboardModelJudge();
    preview = journey.applyPreview(journey.backfillTriage().stdout);
  });

  afterAll(() => {
    journey.cleanup();
  });

  it('does spawn the judge once consent is recorded', () => {
    // Historical access alone does not authorize the egress...
    expect(invokedBeforeConsent).toBe(false);
    // ...the distinct model-judge consent does.
    expect(journey.judgeWasInvoked()).toBe(true);
  });

  it('calibrates a plan from the judged verdict — the consented path completes', () => {
    expect(preview.status).toBe(0);
    expect(preview.stdout).toContain('Plan saved to:');
  });

  it('delivers the whole prompt to the judge on stdin, not merely spawning it', () => {
    // The control the assertion above cannot be: a plan is still saved when the
    // judge receives NOTHING, because a hit-free verdict parses fine. So read
    // what actually crossed the process boundary.
    //
    // This is the only case here that fails if stdin delivery breaks, and it is
    // the reason the whole file can run on Windows now: the prompt is multi-line
    // and several KiB — the two properties that made it uncarriable on a Windows
    // command line — so it exercises exactly what moving it to stdin bought.
    const shape = journey.judgePromptShape();
    expect(shape).toBeDefined();
    // The rubric plus the fenced hit block: several KiB, not a truncated
    // fragment and not an empty read.
    expect(shape?.bytes ?? 0).toBeGreaterThan(1_000);
    // Multi-line, which a Windows command line cannot carry at all — so this
    // also pins that the NDJSON escaping round-tripped rather than splitting the
    // prompt across events.
    expect(shape?.lines ?? 0).toBeGreaterThan(10);
    // ...and the hits themselves arrived, not just the rubric.
    expect(shape?.hits ?? 0).toBeGreaterThan(0);
  });

  it("swallows the judge subprocess's stderr — run logging never reaches the transcript", () => {
    // The stub antigravity writes its run logging (prompt included, so it carries the
    // raw hit) to stderr. spawnAgy pipes and discards both child streams, so
    // none of it may surface on the parent apply command's stdout or stderr.
    expect(preview.stderr).not.toContain('JUDGE-STDERR-RUN-LOGGING');
    expect(preview.stderr).not.toContain(SURFACED_KEY);
    expect(preview.stdout).not.toContain('JUDGE-STDERR-RUN-LOGGING');
  });
});
