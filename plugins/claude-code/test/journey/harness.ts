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

import { openLocalDatabase } from '@akasecurity/persistence';
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
import {
  presentBatchedRemediation,
  type RemediationRouteOutcome,
  routeRemediationOption,
} from '../../src/remediation/chain.ts';
import { loadSecretLeakFindings } from '../../src/remediation/findings.ts';
import {
  presentStandingSecretPosture,
  type StandingPostureResult,
  type StandingSecretPostureStep,
  writeStandingSecretPosture,
} from '../../src/remediation/posture.ts';
import { type RedactionTarget, redactLeakedKeys } from '../../src/remediation/redact.ts';
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

  private run(script: string, args: string[], input?: string): StepResult {
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
  // TriageRecommendation envelope — the first hit per category surfaced (genuine),
  // the rest marked routine false positives — so no live model is ever hit.
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
  if (!hit || typeof hit.category !== 'string' || typeof hit.id !== 'string') continue;
  const ids = byCategory.get(hit.category) ?? [];
  ids.push(hit.id);
  byCategory.set(hit.category, ids);
}
const perCategory = [];
for (const [category, ids] of byCategory) {
  ids.sort();
  const fps = ids.slice(1);
  perCategory.push({
    category,
    action: 'warn',
    reasoning: 'canonical example key — routine placeholder, no live credential',
    genuineCount: ids.length - fps.length,
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

// The raw AWS access-key ids the seeded transcript artifacts leak. Composed at
// runtime so the repo's own secret scan does not flag this file (mirrors
// SURFACED_KEY/ROUTINE_KEY and the remediation scenario fixtures). These are the
// RAW values redaction strikes on disk; the finding table renders only the masked form.
export const REMEDIATION_LEAK_RAW_KEYS: readonly string[] = [
  ['AKIA', 'IOSFODNN7EXAMPLE'].join(''),
  ['AKIA', 'QZ7WXNTP4LMKD9VJ'].join(''),
  ['AKIA', '2E7HTNXKP4LMKD9V'].join(''),
];

// The masked preview each seeded finding carries into the frame — a masked form of
// a raw key, deliberately distinct from every raw value so the raw-free assertions
// are real, not tautologies.
const REMEDIATION_MASKED_TOKEN = 'AKIA****************';

// One seeded secret leak: the on-disk transcript artifact and the raw key it holds,
// paired with the raw-free masked summary the calibration frame carries for it.
// Kept as one object per leak so the displayed row and the file redaction acts on
// never drift.
export interface SeededSecretLeak {
  readonly filePath: string;
  readonly rawValue: string;
  readonly finding: MaskedSecretFinding;
}

// Drives the remediation chain by DIRECT invocation: a
// findings set plus a RemediationEntryContext, no wizard state. It seeds the
// findings set NOT via the wizard — real transcript artifacts holding raw leaked
// keys under the throwaway home, plus a persisted calibration frame (the backfill's
// output) the loader reads — then wires the real DI core (findings loader,
// batched-decision core, decision layout, option router bound to real redaction, and the
// standing-posture writer) over the real local store. No module is mocked.
export class RemediationDrive {
  readonly home: string;
  readonly storeDir: string;
  // The transcript artifact root the seeded leaks live under; redaction is scoped
  // to it (transcriptsDir honors the throwaway home override).
  readonly transcriptRoot: string;
  leaks: SeededSecretLeak[] = [];
  // The seeded calibration frame and its persisted (backfill-output) text the
  // findings loader reads back — set by seedSecretLeaks().
  frame!: CalibrationFrame;
  private persistedFrame = '';

  constructor(home: string, storeDir: string) {
    this.home = home;
    this.storeDir = storeDir;
    this.transcriptRoot = transcriptsDir(home);
  }

  // Seed three real transcript artifacts carrying raw leaked keys under the home,
  // and persist a calibration frame (the backfill's output) whose masked per-finding
  // summaries the loader reads. The frame ALSO records a pii finding, so the
  // secret-only exclusion the chain enforces is observable over a mixed source.
  seedSecretLeaks(): void {
    const projectDir = join(this.transcriptRoot, '-Users-me-remediation');
    mkdirSync(projectDir, { recursive: true });
    this.leaks = REMEDIATION_LEAK_RAW_KEYS.map((rawValue, i) => {
      const filePath = join(projectDir, `session-${String(i)}.jsonl`);
      writeFileSync(filePath, `{"content":"leaked ${rawValue} in an old prompt"}`);
      return {
        filePath,
        rawValue,
        finding: {
          provider: 'aws',
          maskedToken: REMEDIATION_MASKED_TOKEN,
          where: { filePath },
          // Validity is unverifiable under the no-network OSS constraint, so the
          // honest default is 'unknown' — never a blanket 'still valid'.
          state: 'unknown',
        },
      };
    });

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

  // Route a chosen remediation option through the real router, with the real redaction
  // mechanism bound over the seeded raw targets (scoped to the transcript root) and
  // the real standing-posture writer bound for the shortcut path. The
  // 'redact-rotation-checklist' route strikes the transcript artifacts; the
  // deliverable half (the resolved summary / rotation-checklist.md) does not exist yet, so the route
  // records the checklist request but writes no deliverable here.
  route(option: RemediationOption): RemediationRouteOutcome {
    return routeRemediationOption(option, {
      redact: () => redactLeakedKeys(this.targets(), { artifactRoots: [this.transcriptRoot] }),
      setStandingRedactPosture: () => this.writePosture('redact'),
    });
  }

  // The current contents of each seeded transcript artifact, in seed order — read
  // after a redaction route to assert the leaked keys are no longer readable.
  transcriptContents(): string[] {
    return this.leaks.map((l) => readFileSync(l.filePath, 'utf8'));
  }

  // The standing-posture palette (Redact / Warn / Block / Monitor).
  presentPosture(): StandingSecretPostureStep {
    return presentStandingSecretPosture();
  }

  // Persist the chosen standing 'secret' posture to the REAL policies store via
  // applyCategoryPosture. Opens the store fresh, writes, closes — so the
  // durable read below runs on a separate connection.
  writePosture(level: BuiltinPolicyId): StandingPostureResult {
    const db = openLocalDatabase(this.storeDir);
    try {
      return writeStandingSecretPosture(level, db.policies);
    } finally {
      db.close();
    }
  }

  // The 'secret' posture read back from the policies store on a FRESH connection,
  // so the write's persistence is durable rather than a same-connection artifact.
  postureFromStore(): ActionTaken | undefined {
    const db = openLocalDatabase(this.storeDir);
    try {
      return db.policies.getCategoryAction('secret');
    } finally {
      db.close();
    }
  }

  // Whether a rotation-checklist.md deliverable landed at the throwaway home root —
  // false through this iteration, since the deliverable writer does not exist yet.
  rotationChecklistExists(): boolean {
    return existsSync(join(this.home, 'rotation-checklist.md'));
  }

  // The redaction targets recovered from the seeded leaks: each finding's
  // where-found paired with the raw value redaction strikes on disk.
  private targets(): RedactionTarget[] {
    return this.leaks.map((l) => ({ where: l.finding.where, rawValue: l.rawValue }));
  }
}

// Pull the persisted plan-file path the preview printed (`Plan saved to: <path>`).
export function planPathFromPreview(previewStdout: string): string {
  const line = previewStdout.split('\n').find((l) => l.startsWith('Plan saved to:'));
  if (line === undefined) throw new Error('preview did not print a plan-file path');
  return line.replace('Plan saved to:', '').trim();
}
