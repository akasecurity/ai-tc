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
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

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

  // The installed summary + handoff-offer payload.
  firstRun(surfaced: number): StepResult {
    return this.run('firstrun.js', ['--surfaced', String(surfaced)]);
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

// Pull the persisted plan-file path the preview printed (`Plan saved to: <path>`).
export function planPathFromPreview(previewStdout: string): string {
  const line = previewStdout.split('\n').find((l) => l.startsWith('Plan saved to:'));
  if (line === undefined) throw new Error('preview did not print a plan-file path');
  return line.replace('Plan saved to:', '').trim();
}
