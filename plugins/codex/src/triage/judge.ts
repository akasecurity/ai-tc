/**
 * The ephemeral setup-wizard judge runner (Codex CLI).
 *
 * The FP/severity judgment is the one place the wizard feeds the model RAW
 * hits (rawMatch + surrounding context) — the locked rubric (the shared
 * @akasecurity/setup-wizard asset)
 * requires raw to judge accurately. To keep that raw out of the user's
 * scannable rollout store (~/.codex/sessions), the judgment runs as a
 * SEPARATE, transient `codex exec` subprocess that persists NO session file:
 *
 *   codex exec --ephemeral --skip-git-repo-check --output-last-message <file> -
 *
 * --ephemeral ("Run without persisting session files to disk", per the Codex
 * CLI itself) is REQUIRED, not cosmetic: AKA's own backfill scans
 * ~/.codex/sessions/**\/rollout-*.jsonl for leaked secrets, so a persisted
 * judge session — whose prompt carries every raw hit — would be re-ingested
 * as fresh findings on the next history scan. It suppresses only session
 * persistence, NOT network egress: the raw values still leave the machine to
 * the model API, because reaching the model is the point.
 *
 * The prompt (rubric + raw hits) rides on the child's stdin (the trailing `-`
 * argument tells `codex exec` to read the prompt from stdin), not argv: argv
 * is capped by the OS's ARG_MAX (~1MB on most platforms), and a large hit set
 * would fail the spawn with E2BIG. stdin has no such ceiling, and keeps the
 * raw hits off the process list and out of any argv-echoing error message.
 *
 * The verdict is read from the --output-last-message file (a fresh mkdtemp
 * under os.tmpdir, removed in a finally), never from stdout — `codex exec`
 * logs the whole run to stdout, which can echo raw content; that stream is
 * captured and discarded, never forwarded to the parent command.
 *
 * The subprocess inherits the host environment untouched — `codex` must be
 * found on PATH, and auth (CODEX_HOME / ~/.codex credentials) must survive.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { maskText } from '@akasecurity/plugin-sdk';
import type { TriageHit, TriageRecommendation } from '@akasecurity/schema';
import { parseRecommendation } from '@akasecurity/setup-wizard';

const TRIAGE_DIR = dirname(fileURLToPath(import.meta.url));
// src/triage/judge.ts -> packages/setup-wizard/assets/triage-rubric.md
const DEFAULT_RUBRIC_PATH = join(
  TRIAGE_DIR,
  '..',
  '..',
  '..',
  '..',
  'packages',
  'setup-wizard',
  'assets',
  'triage-rubric.md',
);

// -------------------------------------------------------------------------
// Pure parse: last message -> verdict
// -------------------------------------------------------------------------

// Extract + validate the fenced TriageRecommendation from the model's final
// message (the --output-last-message file's content) via the shared parser.
// An empty or unparseable message is a hard failure, never a silent pass —
// the caller must not act on a verdict we could not read.
export function parseVerdict(lastMessage: string): TriageRecommendation {
  // Never echo the subprocess output in an error: it may carry a raw hit the
  // model failed to strip, and this error propagates to the parent command's
  // stderr — outside the isolated judge process. Every failure reports only
  // raw-free metadata, never the content.
  if (lastMessage.trim() === '') {
    throw new Error('codex exec returned an empty last message');
  }
  try {
    return parseRecommendation(lastMessage);
  } catch {
    throw new Error('codex exec returned an unparseable TriageRecommendation');
  }
}

// -------------------------------------------------------------------------
// Subprocess env + spawn
// -------------------------------------------------------------------------

// Env for the ephemeral judge subprocess: the host environment, inherited
// untouched. `codex` must resolve on PATH and its auth (CODEX_HOME /
// ~/.codex credentials) must survive; session persistence is suppressed by
// the --ephemeral flag on argv, not by any env var.
export function judgeEnv(): NodeJS.ProcessEnv {
  return { ...process.env };
}

// Real subprocess spawn used in production wiring. Kept separate from runJudge
// so unit tests inject a fake and NEVER hit a live model. The prompt (which
// carries the raw hits) rides on stdin rather than argv — argv has an OS
// ceiling (ARG_MAX, ~1MB on most platforms) that a large hit set can exceed,
// failing the spawn with E2BIG; stdin has no such limit. BOTH of `codex exec`'s
// output streams (run logging that can echo raw content) are captured here and
// discarded — the verdict comes from the --output-last-message file instead.
// The stdio option is explicit because execFileSync's default writes the
// child's stderr through to the parent's stderr, which flows into the wizard
// conversation — the transcript --ephemeral exists to keep raw content out of.
export function spawnCodex(argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string): void {
  execFileSync('codex', [...argv], {
    env,
    input: stdin,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
}

// Raw-free description of a spawn failure. The prompt rides on stdin, not
// argv, so an execFileSync error's `.message` (which echoes argv) cannot
// carry the raw hits — but its captured stdout/stderr still might, and none
// of it may cross back to the parent command. This stays belt-and-suspenders:
// we surface ONLY the non-content metadata (exit status / signal / node error
// code), never `.message`, `.stdout`, or `.stderr`.
function spawnFailureMeta(err: unknown): string {
  const e = err as { status?: number | null; signal?: string | null; code?: string };
  const parts: string[] = [];
  if (typeof e.status === 'number') parts.push(`exit ${String(e.status)}`);
  if (typeof e.signal === 'string' && e.signal) parts.push(`signal ${e.signal}`);
  if (typeof e.code === 'string' && e.code) parts.push(e.code);
  return parts.length > 0 ? parts.join(', ') : 'unknown error';
}

// -------------------------------------------------------------------------
// runJudge
// -------------------------------------------------------------------------

export interface JudgeDeps {
  // Injected spawn seam: receives the argv AFTER `codex`, the subprocess env,
  // and the prompt (fed on stdin, not argv — see spawnCodex). The final
  // assistant message lands in the --output-last-message file named on argv;
  // tests inject a fake that writes a canned verdict there so no real
  // `codex exec` runs.
  spawn: (argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string) => void;
  // Override the rubric source (defaults to the shared package asset); injectable so
  // tests need not read the real file.
  loadRubric?: () => string;
}

// Build the judge prompt (rubric + raw hits as JSONL) and run it through the
// ephemeral subprocess, returning the parsed verdict. The RAW hits ride in the
// prompt on purpose (the rubric needs them); the prompt rides on stdin (not
// argv) so a large hit set never trips the OS's ARG_MAX and so raw can't leak
// via a spawn error's argv-echoing `.message`. --ephemeral is what keeps the
// prompt out of ~/.codex/sessions. Always removes the temp output dir.

// The minimized egress projection: what actually crosses to the model. The
// finding's own rawMatch must cross (the rubric judges the value), and the
// context window crosses only after re-masking, so any OTHER detectable secret
// in the window never leaves raw. filePath, valueFingerprint, and keyVersion
// are dropped before egress — a new TriageHit field is not disclosed to the
// model unless this projection and the consent copy are updated together.
// maskText is fail-secure: a masking fault over-redacts, never leaks.
// The spread is load-bearing: it drops the fields from a COPY, never off the
// source hit — the surfaced-secrets writeback still reads filePath off the
// original in-memory hits, so mutating in place here would break that path.
export function toJudgePayload(
  hit: TriageHit,
): Omit<TriageHit, 'filePath' | 'valueFingerprint' | 'keyVersion'> {
  const payload: TriageHit = { ...hit, context: maskText(hit.context) };
  delete payload.filePath;
  delete payload.valueFingerprint;
  delete payload.keyVersion;
  return payload;
}

export function runJudge(hits: readonly TriageHit[], deps: JudgeDeps): TriageRecommendation {
  // No live-spawn fallback: a caller that forgot the seam must fail as the
  // programming error it is rather than be quietly routed to the real
  // `codex`. First statement in the function, so it throws before the rubric
  // is read, before any hit is projected, and before the temp output dir is
  // minted — no raw is assembled for a call that cannot proceed.
  if (typeof deps.spawn !== 'function') {
    throw new TypeError('runJudge requires deps.spawn — there is no live-spawn fallback');
  }

  const rubric = deps.loadRubric?.() ?? readFileSync(DEFAULT_RUBRIC_PATH, 'utf8');
  const hitsJsonl = hits.map((h) => JSON.stringify(toJudgePayload(h))).join('\n');
  const fullPrompt = `${rubric}\n\n## Hits\n\n\`\`\`\n${hitsJsonl}\n\`\`\`\n`;

  const outDir = mkdtempSync(join(tmpdir(), 'aka-judge-'));
  const outFile = join(outDir, 'last-message.txt');
  const argv = [
    'exec',
    '--ephemeral',
    '--skip-git-repo-check',
    '--output-last-message',
    outFile,
    '-',
  ] as const;
  try {
    // The spawn is isolated from the parse: a spawn failure (execFileSync) throws
    // an error whose captured stdout/stderr may carry raw content even though the
    // prompt itself never rides argv. Re-throw it as raw-free metadata so nothing
    // raw can ride the error out to the parent command's stderr.
    try {
      deps.spawn(argv, judgeEnv(), fullPrompt);
    } catch (err) {
      // Deliberately NOT chaining `err` as `cause`: the execFileSync error's captured
      // stdout/stderr may carry raw content, and attaching it would re-expose
      // exactly what this throw exists to strip. Only raw-free metadata is surfaced.
      // eslint-disable-next-line preserve-caught-error -- caught error may carry raw; see above
      throw new Error(`codex exec judge subprocess failed (${spawnFailureMeta(err)})`);
    }
    // A subprocess that exits 0 without writing the last-message file still
    // fails loud (and raw-free) — an unreadable verdict must never pass.
    let lastMessage: string;
    try {
      lastMessage = readFileSync(outFile, 'utf8');
    } catch {
      throw new Error('codex exec wrote no last-message file');
    }
    return parseVerdict(lastMessage);
  } finally {
    try {
      rmSync(outDir, { recursive: true, force: true });
    } catch {
      // A throw here would REPLACE whatever the try block is throwing — the
      // raw-free spawn/parse failure the caller has to act on — with an fs
      // error about a throwaway path. The dir is a mkdtemp under tmpdir(),
      // so leaking it beats losing the real failure.
    }
  }
}
