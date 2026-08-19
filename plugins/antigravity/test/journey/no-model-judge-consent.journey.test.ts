/**
 * aka-setup, model-judge consent DECLINED — proven end-to-end against the REAL
 * built script chain (the scripts/*.js the skill actually shells out to).
 *
 * The distinct model-judge consent (step 3 of skills/setup/SKILL.md) is what
 * authorizes the only egress in the product: apply-suppressions' `agy -p`
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
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { bundledDetections } from '@akasecurity/plugin-sdk';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { judgeArgvUnsupported } from '../helpers/judge-argv-unsupported.ts';
import {
  assertShimResolves,
  nodeOnlyPathEntries,
  shimmedPath,
  writeCommandShim,
} from '../helpers/path-shim.ts';

// See judge-argv-unsupported.ts: this host takes the judge prompt in ARGV, which
// cannot cross cmd.exe — so the stub, which can only be a .cmd on Windows, is
// unreachable there and `judgeWasInvoked()` cannot be driven either way.
const describeJudgeArgv = describe.skipIf(judgeArgvUnsupported);

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
    rmSync(this.home, { recursive: true, force: true });
    rmSync(this.binDir, { recursive: true, force: true });
  }

  // Whether the stub `agy` judge was actually executed. The stub touches a
  // sentinel on every invocation, so a consent-gate test can assert the egress
  // never happened at the process boundary — not merely that a mocked function
  // went uncalled.
  judgeWasInvoked(): boolean {
    return existsSync(this.judgeSentinelPath);
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
      // shimmedPath then yields the stub dir alone. Nothing else from the host
      // environment reaches the chain.
      PATH: shimmedPath(this.binDir, this.nodeDirs.join(delimiter)),
    };
    // Proven once per journey, before the first script runs. A shim that does
    // not land does NOT fail closed: resolution keeps walking PATH and finds a
    // real installed `agy`, so the chain would reach a live model and this
    // suite's load-bearing `judgeWasInvoked()` assertion would pass for the
    // wrong reason — nothing ran because nothing COULD run. spawnAgy uses no
    // `shell`, so the probe must not either.
    if (!this.shimProven) {
      assertShimResolves('agy', env);
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
  // `agy -p <prompt> --output-format json`, with the prompt in ARGV (this host
  // documents no stdin input — see triage/judge.ts's spawnAgy). This stub reads
  // the prompt off argv, parses the hits out of its trailing fenced block, and
  // prints a deterministic, raw-free TriageRecommendation inside the JSON
  // envelope on stdout — the first hit per (category, rule) surfaced (genuine),
  // the rest marked routine false positives. No live model is ever hit.
  private writeFakeJudge(): void {
    const body = `// Record that the judge actually ran, so a test can prove the consent gate
// stopped the egress at the process boundary (see judgeWasInvoked).
require('node:fs').writeFileSync(${JSON.stringify(this.judgeSentinelPath)}, '');
const args = process.argv.slice(2);
const promptIndex = args.indexOf('-p');
const prompt = promptIndex >= 0 ? args[promptIndex + 1] ?? '' : '';
// Simulate agy's run logging on stderr, prompt content included. The parent's
// spawnAgy must swallow this stream entirely: the parent command's stderr flows
// into the wizard conversation, whose transcripts the backfill later scans.
process.stderr.write('JUDGE-STDERR-RUN-LOGGING ' + prompt);
const fences = [...String(prompt).matchAll(/\`\`\`[a-z]*\\n([\\s\\S]*?)\`\`\`/g)];
const block = fences.length ? fences[fences.length - 1][1] : '';
const byCategory = new Map();
for (const line of block.split('\\n')) {
  const trimmed = line.trim();
  if (!trimmed) continue;
  let hit;
  try { hit = JSON.parse(trimmed); } catch { continue; }
  if (!hit || typeof hit.category !== 'string' || typeof hit.id !== 'string' || typeof hit.ruleId !== 'string') continue;
  const byRule = byCategory.get(hit.category) ?? new Map();
  const ids = byRule.get(hit.ruleId) ?? [];
  ids.push(hit.id);
  byRule.set(hit.ruleId, ids);
  byCategory.set(hit.category, byRule);
}
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
// --output-format json: a single envelope on stdout carrying the final
// assistant message, which is where the parent reads the verdict from.
process.stdout.write(JSON.stringify({
  conversation_id: 'conv-fake-judge',
  status: 'ok',
  response: '\`\`\`json\\n' + JSON.stringify(verdict) + '\\n\`\`\`',
}));
`;
    // writeCommandShim owns the shebang, the mode bits and — on Windows — the
    // .cmd launcher that makes a bare `agy` resolvable at all.
    writeCommandShim(this.binDir, 'agy', body);
  }
}

describeJudgeArgv('aka-setup journey — model-judge consent declined', () => {
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
describeJudgeArgv('aka-setup journey — model-judge consent granted (control)', () => {
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

  it("swallows the judge subprocess's stderr — run logging never reaches the transcript", () => {
    // The stub antigravity writes its run logging (prompt included, so it carries the
    // raw hit) to stderr. spawnAgy pipes and discards both child streams, so
    // none of it may surface on the parent apply command's stdout or stderr.
    expect(preview.stderr).not.toContain('JUDGE-STDERR-RUN-LOGGING');
    expect(preview.stderr).not.toContain(SURFACED_KEY);
    expect(preview.stdout).not.toContain('JUDGE-STDERR-RUN-LOGGING');
  });
});
