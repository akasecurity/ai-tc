/**
 * Shared /aka:setup journey harness — the scripted-reproducible executor behind
 * the setup journey e2e proofs. It drives the REAL wizard script
 * chain (the built scripts/*.js the prompt actually shells out to) in frame order
 * against a throwaway ~/.aka home, so a journey is proven end-to-end without ever
 * touching a developer's real store.
 *
 * The home override is the platform's own: each script resolves ~/.aka and
 * ~/.claude via os.homedir(), which honors $HOME on POSIX, so the harness points
 * the whole chain at a temp home by spawning each script with HOME set — no
 * script-level flag or process.env read is added to shipped code (the scripts
 * must not hard-resolve the home, and they don't).
 *
 * The one external dependency the chain has — the `claude -p` triage judge the
 * apply-suppressions preview spawns — is stubbed hermetically by putting a
 * controlled `claude` executable first on the child PATH (see writeFakeJudge).
 * Everything else is the real thing: the real backfill scan, the real store
 * writes, the real rendered frames.
 *
 * Later iterations extend THIS harness with their frames (the Not-now branch, the
 * empty states).
 */
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type {
  ActionTaken,
  BatchedRemediation,
  BuiltinPolicyId,
  CalibrationFrame,
  CalibrationPreview,
  MaskedSecretFinding,
  RemediationEntryContext,
  RemediationOption,
} from '@akasecurity/schema';

import { frameCalibration } from '../../src/calibration.ts';
import { readRegisteredCommands } from '../../src/command-registry.ts';
import { transcriptsDir } from '../../src/history/transcripts.ts';
import { presentBatchedRemediation } from '../../src/remediation/chain.ts';
import { loadSecretLeakFindings } from '../../src/remediation/findings.ts';
import { renderRemediationDecision } from '../../src/remediation/render.ts';
import { frameJsonBlock } from '../../src/setup-frame-json.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
// test/journey -> plugins/claude-code
export const PLUGIN_ROOT = join(HERE, '..', '..');
const SCRIPTS_DIR = join(PLUGIN_ROOT, 'scripts');
const MANIFEST_PATH = join(PLUGIN_ROOT, '.claude-plugin', 'plugin.json');

const DAY_MS = 24 * 60 * 60 * 1000;

// The host env, read once so the child spawns inherit PATH/node. The journey
// harness genuinely needs the host environment (to find node + the stub judge on
// PATH and to override HOME) — the one sanctioned reason to touch it.
// eslint-disable-next-line n/no-process-env -- test harness needs host PATH to spawn the real scripts
const HOST_ENV = process.env;

export interface StepResult {
  stdout: string;
  stderr: string;
  // The script's exit code (0 on a clean exit). A fail-open step must still exit 0
  // with its note on stdout — a non-zero status here means an error escaped.
  status: number;
}

// One AWS access-key id per canonical test secret. Composed at runtime so the
// repo's own secret scan doesn't flag this file (mirrors history/scan.test.ts).
export const SURFACED_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
export const ROUTINE_KEY = ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join('');

// Two more real, distinct-provider live keys — paired with SURFACED_KEY (aws) by
// seedMultiKeyTranscripts() below to spread THREE genuine keys across TWO
// transcript artifacts via the real detection engine, so a built-script drive can
// prove the M (transcripts) != N (keys) property the module-seam fixture already
// proves. Composed at runtime for the same reason as SURFACED_KEY/ROUTINE_KEY.
export const MULTI_KEY_STRIPE_KEY = ['sk', '_live_', 'aBcDeFgHiJkLmNoPqRsTuVwXyZmulti1'].join('');
export const MULTI_KEY_GITHUB_KEY = ['ghp_', 'aBcDeFgHiJkLmNoPqRsTuVwXyZ12multi901'].join('');

export class SetupJourney {
  readonly home: string;
  // The resolved ~/.aka/data store dir the scripts actually write to (base/data),
  // for opening the store to assert final state. NOT the base — opening the base
  // would create a fresh floor-seeded DB and read nothing the scripts wrote.
  readonly storeDir: string;
  // The settings.json the onboarding writer records the consent + prefs into.
  readonly settingsPath: string;
  private readonly binDir: string;

  constructor() {
    this.home = mkdtempSync(join(tmpdir(), 'aka-journey-home-'));
    this.storeDir = join(this.home, '.aka', 'data');
    this.settingsPath = join(this.home, '.aka', 'settings', 'settings.json');
    this.binDir = mkdtempSync(join(tmpdir(), 'aka-journey-bin-'));
    this.writeFakeJudge();
  }

  cleanup(): void {
    rmSync(this.home, { recursive: true, force: true });
    rmSync(this.binDir, { recursive: true, force: true });
  }

  // Seed a prior Claude Code transcript under the temp home carrying two leaked
  // AWS keys, timestamped inside the retention window but before the scan starts,
  // so the backfill has real history to calibrate from.
  seedTranscript(): string {
    const projectDir = join(this.home, '.claude', 'projects', '-Users-me-project');
    mkdirSync(projectDir, { recursive: true });
    const surfacedTs = new Date(Date.now() - 3 * DAY_MS).toISOString();
    const routineTs = new Date(Date.now() - 2 * DAY_MS).toISOString();
    const lines = [
      JSON.stringify({
        type: 'user',
        timestamp: surfacedTs,
        message: { role: 'user', content: `here is a prod key ${SURFACED_KEY}` },
      }),
      JSON.stringify({
        type: 'user',
        timestamp: routineTs,
        message: { role: 'user', content: `and an example placeholder ${ROUTINE_KEY}` },
      }),
    ];
    const transcriptPath = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptPath, lines.join('\n'));
    return transcriptPath;
  }

  // Seed TWO prior Claude Code transcripts under the temp home spreading THREE
  // live, distinct-provider keys across them — one artifact carries two (stripe +
  // aws), the other carries one (github) — timestamped inside the retention
  // window, so a real backfill scan surfaces the same M (transcripts) != N (keys)
  // shape RemediationDrive.seedSecretLeaks() proves at the module seam, but
  // through the real detection engine rather than a synthesized frame. Returns
  // the two transcript paths in seed order.
  seedMultiKeyTranscripts(): readonly [string, string] {
    const projectDir = join(this.home, '.claude', 'projects', '-Users-me-multi-key');
    mkdirSync(projectDir, { recursive: true });
    const line = (daysAgo: number, content: string): string =>
      JSON.stringify({
        type: 'user',
        timestamp: new Date(Date.now() - daysAgo * DAY_MS).toISOString(),
        message: { role: 'user', content },
      });

    const transcriptA = join(projectDir, 'session-0.jsonl');
    const transcriptB = join(projectDir, 'session-1.jsonl');
    writeFileSync(
      transcriptA,
      [
        line(6, `here is a stripe key ${MULTI_KEY_STRIPE_KEY}`),
        line(5, `here is a prod key ${SURFACED_KEY}`),
      ].join('\n'),
    );
    writeFileSync(transcriptB, line(4, `here is a github token ${MULTI_KEY_GITHUB_KEY}`));
    return [transcriptA, transcriptB];
  }

  // Seed a prior Claude Code transcript under the temp home carrying only benign
  // prose — messages that get examined but surface no findings — timestamped
  // inside the retention window but before the scan starts, so the backfill has
  // real history to examine yet streams zero hits (scan-clean, not no-history).
  seedCleanTranscript(): string {
    const projectDir = join(this.home, '.claude', 'projects', '-Users-me-clean');
    mkdirSync(projectDir, { recursive: true });
    const ts = new Date(Date.now() - 2 * DAY_MS).toISOString();
    const lines = [
      JSON.stringify({
        type: 'user',
        timestamp: ts,
        message: { role: 'user', content: 'lets refactor the parser and add a couple of tests' },
      }),
    ];
    const transcriptPath = join(projectDir, 'session.jsonl');
    writeFileSync(transcriptPath, lines.join('\n'));
    return transcriptPath;
  }

  // The kickoff intro card.
  intro(): StepResult {
    return this.run('intro.js', [MANIFEST_PATH]);
  }

  // Consent side effect — record the historical-review answer. `full` is
  // the Yes-scan leg (consent to look at prior activity).
  onboardHistorical(access: 'full' | 'session-only'): StepResult {
    return this.run('onboard.js', ['--historical', access]);
  }

  // Out-of-band posture write, e.g. a pack the user hardened before running the
  // wizard — used to prove the confirm write never downgrades it.
  onboardPosture(posture: Record<string, string>): StepResult {
    return this.run('onboard.js', ['--posture', JSON.stringify(posture)]);
  }

  // Frame 0.3b — the Not-now branch's start-light card: the full 8×4 default posture
  // matrix seeded with the conservative severity-floor defaults, its per-pack
  // rationale, and the re-tune hint. Reads no store and records no consent, so it
  // drives the No-history leg with no prior backfill or scan.
  startLight(): StepResult {
    return this.run('start-light.js', []);
  }

  // Frame 0.5 (Not-now leg) — the start-light posture write. Keeping the default
  // defaults is the `--floor` write (fills the store with the severity-floor
  // posture); an adjusted map is the `--posture` write. This is the Not-now
  // analog of the Yes-path confirm write — no scan, no suppressions.
  onboardStartLight(posture?: Record<string, string>): StepResult {
    return posture === undefined
      ? this.run('onboard.js', ['--floor'])
      : this.onboardPosture(posture);
  }

  // The backfill triage stream (JSONL + sentinel).
  backfillTriage(): StepResult {
    return this.run('backfill.js', ['--triage']);
  }

  // The backfill's human (default) output path — the scan summary when access was
  // granted, or the consent-gate note when it wasn't. The Not-now leg drives this
  // to prove the gate refuses to read without a 'full' grant.
  backfill(): StepResult {
    return this.run('backfill.js', []);
  }

  // The calibration preview: judge (stubbed), plan, gate, frame JSON,
  // and the persisted plan-file path. Takes the backfill stream on stdin.
  applyPreview(triageStream: string): StepResult {
    return this.run('apply-suppressions.js', [], triageStream);
  }

  // Apply the confirmed plan verbatim (establishes the floor-overlaid
  // 8-pack + suppressions in one transaction).
  applyConfirm(planPath: string): StepResult {
    return this.run('apply-suppressions.js', ['--confirmed', '--plan', planPath]);
  }

  // The installed summary + handoff-offer payload. `liveKeys` is the surfaced
  // live-key secret count (a subset of `surfaced`) that gates the remediation
  // chain-entry offer; it defaults to 0 so a non-secret-only run offers no
  // remediation.
  firstRun(surfaced: number, liveKeys = 0): StepResult {
    return this.run('firstrun.js', [
      '--surfaced',
      String(surfaced),
      '--live-keys',
      String(liveKeys),
    ]);
  }

  // The installed summary on the no-scan leg — firstrun.js with NO --surfaced
  // count. The Not-now leg ran no scan, so there is no surfaced count to thread:
  // the store-derived stats and the 'N worth a look' handoff degrade to the honest
  // empty-state and no handoff payload is emitted.
  firstRunNoScan(): StepResult {
    return this.run('firstrun.js', []);
  }

  // Replace the store the scripts read with an unreadable one, so the next
  // store-reading wizard step (calibration downgrade view / first-run stats)
  // hits the missing/corrupt/locked-store fault the fail-open path must absorb.
  // The bytes are not the "SQLite format 3\0" header, so the first PRAGMA on open
  // fails SQLITE_NOTADB — the exact read failure the fail-open path guards against.
  corruptStore(): void {
    rmSync(this.storeDir, { recursive: true, force: true });
    mkdirSync(this.storeDir, { recursive: true });
    writeFileSync(
      join(this.storeDir, 'aka.db'),
      'AKA corrupt-store fixture — not a database\n'.repeat(64),
    );
  }

  // A driver for the secret-leak remediation chain, bound to this throwaway
  // home + store. The remediation chain is entry-point-agnostic — it takes a
  // findings set plus an entry context and holds NO wizard state — so the drive
  // seeds the findings directly and never runs a wizard script.
  remediation(): RemediationDrive {
    return new RemediationDrive(this.home, this.storeDir);
  }

  // The PRODUCTION remediation entry's present mode — what
  // `commands/setup.md` runs when the user chooses "Review leaked keys" at frame
  // 0.6: the built `scripts/remediate.js`, fed the SAME calibration frame text
  // apply-suppressions.js's preview emitted at frame 0.4 (the `frameText` a
  // caller captured from `applyPreview()`'s stdout) on stdin. Prints the
  // batched remediation decision.
  remediationPresent(frameText: string): StepResult {
    return this.run('remediate.js', [], frameText);
  }

  // The PRODUCTION remediation entry's route mode: routes the
  // chosen remediation option through the built script, over the SAME calibration frame
  // text as the present call above. `posture` supplies `--posture <level>`, required by
  // the two redact options (`redact-only` / `redact-rotation-checklist`) and ignored by
  // `set-secret-redact` / `leave`. `cwd` overrides the script's working directory — the
  // deliverable resolver resolves the repo root from it, so a `redact-rotation-checklist`
  // drive must supply an isolated throwaway repo rather than inheriting the test
  // process's own cwd.
  remediationRoute(
    frameText: string,
    option: RemediationOption,
    posture?: BuiltinPolicyId,
    cwd?: string,
  ): StepResult {
    const args = ['--option', option, ...(posture === undefined ? [] : ['--posture', posture])];
    return this.run('remediate.js', args, frameText, cwd);
  }

  private run(script: string, args: string[], input?: string, cwd?: string): StepResult {
    const env: NodeJS.ProcessEnv = {
      ...HOST_ENV,
      HOME: this.home,
      // Windows resolves the home dir from USERPROFILE; keep both in lockstep.
      USERPROFILE: this.home,
      // Stub judge first on PATH so apply-suppressions' `claude -p` spawn hits it,
      // never a live model.
      PATH: `${this.binDir}:${HOST_ENV.PATH ?? ''}`,
    };
    try {
      const stdout = execFileSync(process.execPath, [join(SCRIPTS_DIR, script), ...args], {
        env,
        encoding: 'utf8',
        ...(input !== undefined ? { input } : {}),
        ...(cwd !== undefined ? { cwd } : {}),
        maxBuffer: 64 * 1024 * 1024,
      });
      return { stdout, stderr: '', status: 0 };
    } catch (err) {
      // A non-zero exit still carries the captured streams; surface them so the
      // test asserts against real script output rather than a bare throw.
      const e = err as { stdout?: string; stderr?: string; status?: number };
      return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
    }
  }

  // A controlled `claude` on PATH: the apply-suppressions preview spawns
  // `claude -p … <prompt>` for its triage judgment. This stub parses the hits out
  // of the prompt's trailing fenced block and returns a deterministic, raw-free
  // TriageRecommendation envelope — the first hit per (category, rule) surfaced
  // (genuine), the rest marked routine false positives — so a repeated hit under
  // the SAME rule (e.g. the SURFACED_KEY/ROUTINE_KEY aws-access-key pair) still
  // dismisses all but one, while distinct rules in the same category (e.g. aws +
  // stripe + github secrets) each surface their own genuine hit. No live model
  // is ever hit.
  private writeFakeJudge(): void {
    const src = `#!/usr/bin/env node
'use strict';
const argv = process.argv.slice(2);
const prompt = argv.length ? argv[argv.length - 1] : '';
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
const result = '\`\`\`json\\n' + JSON.stringify(verdict) + '\\n\`\`\`';
process.stdout.write(JSON.stringify({ result, is_error: false }));
`;
    const path = join(this.binDir, 'claude');
    writeFileSync(path, src);
    chmodSync(path, 0o755);
  }
}

// The raw leaked-key values the seeded transcript artifacts hold — the SAME
// real, distinct-provider keys seedMultiKeyTranscripts() uses (matching the real
// detection rules' regex + entropy shape), reused here so the built
// remediate.js's production redaction adapter (which re-scans each artifact
// through the real detection engine to recover a raw value, rather than
// trusting a caller-supplied one) can actually find and strike them. These are
// the RAW values redaction strikes on disk; the finding table renders only the
// masked form. One entry per REMEDIATION_LEAK_FIXTURES row, in the same order.
export const REMEDIATION_LEAK_RAW_KEYS: readonly string[] = [
  MULTI_KEY_STRIPE_KEY,
  SURFACED_KEY,
  MULTI_KEY_GITHUB_KEY,
];

// One seeded leak's provider identity, which of the two seeded transcript
// artifacts it was found in, and its exposure age. Three keys are spread across
// exactly TWO transcripts (M=2, N=3, M != N) so the resolved summary's
// per-transcript count is genuinely independent of the redacted-key count, and
// each leak gets a DISTINCT provider (its masked token is derived from the real
// raw value below via safeMaskedMatch — the SAME function the production
// redaction adapter uses to match a re-scanned hit back to its finding) so
// buildChecklistEntries (which groups by provider+maskedToken) produces three
// ordered entries rather than one collapsed row.
interface RemediationLeakFixture {
  readonly provider: string;
  readonly transcriptIndex: 0 | 1;
  readonly observedAt: string;
}

const REMEDIATION_LEAK_FIXTURES: readonly RemediationLeakFixture[] = [
  { provider: 'stripe', transcriptIndex: 0, observedAt: '2026-05-01T00:00:00Z' },
  { provider: 'aws', transcriptIndex: 0, observedAt: '2026-06-01T00:00:00Z' },
  { provider: 'github', transcriptIndex: 1, observedAt: '2026-01-01T00:00:00Z' },
];

// One seeded secret leak: the on-disk transcript artifact and the raw key it holds,
// paired with the raw-free masked summary the calibration frame carries for it.
// Kept as one object per leak so the displayed row and the file redaction acts on
// never drift.
export interface SeededSecretLeak {
  readonly filePath: string;
  readonly rawValue: string;
  readonly finding: MaskedSecretFinding;
}

// Drives the remediation chain's batched-decision presentation by DIRECT
// invocation: a findings set plus a RemediationEntryContext, no wizard state. It
// seeds the findings set NOT via the wizard — real transcript artifacts holding
// raw leaked keys under the throwaway home, plus a persisted calibration frame
// (the backfill's output) the loader reads — then wires the real DI core
// (findings loader, batched-decision core, decision layout) over the real local
// store. No module is mocked. The redact -> standing-posture -> resolved-deliverable
// spine downstream of the batched decision is driven through the BUILT
// remediate.js (see SetupJourney.remediationRoute()), fed persistedFrame on
// stdin — never a hand-assembled module composition.
export class RemediationDrive {
  readonly home: string;
  readonly storeDir: string;
  // The transcript artifact root the seeded leaks live under; the production
  // redaction adapter the built script uses scopes its re-scan to it
  // (transcriptsDir honors the throwaway home override).
  readonly transcriptRoot: string;
  leaks: SeededSecretLeak[] = [];
  // The seeded calibration frame and its persisted (backfill-output) text the
  // findings loader reads back — set by seedSecretLeaks(). Exposed so a caller
  // can feed the SAME text the loader reads to the built remediate.js on stdin.
  frame!: CalibrationFrame;
  persistedFrame = '';

  constructor(home: string, storeDir: string) {
    this.home = home;
    this.storeDir = storeDir;
    this.transcriptRoot = transcriptsDir(home);
  }

  // Seed three real leaked keys spread across exactly TWO transcript artifacts
  // under the home (REMEDIATION_LEAK_FIXTURES — one of the two artifacts holds two
  // of the three keys), and persist a calibration frame (the backfill's output)
  // whose masked per-finding summaries the loader reads. The frame ALSO records a
  // pii finding, so the secret-only exclusion the chain enforces is observable
  // over a mixed source. Each leak's raw value is a real, detectable key (the
  // same shape seedMultiKeyTranscripts() uses) so the built remediate.js's
  // production redaction adapter — which re-scans the artifact through the real
  // detection engine to recover a raw value, rather than trusting a
  // caller-supplied one — can actually find and strike it; its masked token is
  // derived via safeMaskedMatch, the SAME function that adapter uses to match a
  // re-scanned hit back to this finding.
  seedSecretLeaks(): void {
    const projectDir = join(this.transcriptRoot, '-Users-me-remediation');
    mkdirSync(projectDir, { recursive: true });
    const transcriptPaths: readonly [string, string] = [
      join(projectDir, 'session-0.jsonl'),
      join(projectDir, 'session-1.jsonl'),
    ];

    this.leaks = REMEDIATION_LEAK_FIXTURES.map((fixture, i) => {
      const rawValue = REMEDIATION_LEAK_RAW_KEYS[i];
      if (rawValue === undefined) {
        throw new Error('REMEDIATION_LEAK_RAW_KEYS must carry one entry per fixture row');
      }
      const filePath = transcriptPaths[fixture.transcriptIndex];
      return {
        filePath,
        rawValue,
        finding: {
          provider: fixture.provider,
          maskedToken: safeMaskedMatch(rawValue),
          where: { filePath },
          // Validity is unverifiable under the no-network OSS constraint, so the
          // honest default is 'unknown' — never a blanket 'still valid'.
          state: 'unknown',
          observedAt: fixture.observedAt,
        },
      };
    });

    // Write each transcript artifact with every raw key assigned to it — one
    // artifact carries two of the three leaked keys, since M (transcripts) !=
    // N (keys) here.
    const rawValuesByFile = new Map<string, string[]>();
    for (const leak of this.leaks) {
      const values = rawValuesByFile.get(leak.filePath) ?? [];
      values.push(leak.rawValue);
      rawValuesByFile.set(leak.filePath, values);
    }
    for (const [filePath, rawValues] of rawValuesByFile) {
      const lines = rawValues.map((v) => `{"content":"leaked ${v} in an old prompt"}`);
      writeFileSync(filePath, lines.join('\n'));
    }

    // The calibration preview the backfill recorded: the surfaced secret findings
    // AND a pii (customer-data) hit, so "only the secret findings enter" is a real
    // filter over a frame that genuinely records pii activity.
    const preview: CalibrationPreview = {
      categories: [
        { category: 'secret', genuineCount: this.leaks.length, fpCount: 0, egress: false },
        { category: 'pii', genuineCount: 1, fpCount: 0, egress: false },
      ],
      posture: {
        secret: 'warn',
        pii: 'warn',
        financial: 'warn',
        phi: 'warn',
        code_flaw: 'warn',
        custom: 'warn',
        code_context: 'monitor',
        config: 'monitor',
      },
    };
    this.frame = frameCalibration(
      preview,
      this.leaks.map((l) => l.finding),
    ).frame;
    this.persistedFrame = frameJsonBlock(this.frame);
  }

  // Read the surfaced secret findings from the seeded backfill frame through
  // the real loader (read, not synthesized). Exercises the frame's real read/parse
  // boundary, the same one a store/read failure surfaces at.
  loadFindings(): MaskedSecretFinding[] | undefined {
    return loadSecretLeakFindings(() => this.persistedFrame);
  }

  // Present the batched remediation decision directly with the supplied entry
  // context and no wizard state.
  present(entryContext: RemediationEntryContext): BatchedRemediation {
    return presentBatchedRemediation(this.loadFindings() ?? [], entryContext);
  }

  // The full decision layout over the masked findings, rendered against the REAL
  // installed command registry so the chaining line names only a registered
  // secret-scan continuation.
  renderLayout(findings: readonly MaskedSecretFinding[], moreCount: number): string {
    return renderRemediationDecision(findings, moreCount, readRegisteredCommands());
  }

  // The current contents of each seeded transcript artifact, in seed order — read
  // after a redaction route to assert the leaked keys are no longer readable.
  transcriptContents(): string[] {
    return this.leaks.map((l) => readFileSync(l.filePath, 'utf8'));
  }

  // The 'secret' posture read back from the policies store on a FRESH connection,
  // so a write's persistence is durable rather than a same-connection artifact.
  postureFromStore(): ActionTaken | undefined {
    const db = openLocalDatabase(this.storeDir);
    try {
      return db.policies.getCategoryAction('secret');
    } finally {
      db.close();
    }
  }
}

// Pull the persisted plan-file path the preview printed (`Plan saved to: <path>`).
export function planPathFromPreview(previewStdout: string): string {
  const line = previewStdout.split('\n').find((l) => l.startsWith('Plan saved to:'));
  if (line === undefined) throw new Error('preview did not print a plan-file path');
  return line.replace('Plan saved to:', '').trim();
}
