/**
 * The ephemeral setup-wizard judge runner.
 *
 * The FP/severity judgment is the one place the wizard feeds the model RAW
 * hits (rawMatch + surrounding context) — the locked rubric (eval/prompt.md)
 * requires raw to judge accurately. To keep that raw out of the user's
 * scannable transcript store (~/.claude/projects), the judgment runs as a
 * SEPARATE, transient `claude -p` subprocess that writes NO transcript:
 *
 *   claude -p --no-session-persistence --output-format json   (prompt on stdin)
 *   env: CLAUDE_CODE_SKIP_PROMPT_HISTORY=1   (no transcript, any OS; keeps auth)
 *        CLAUDE_CONFIG_DIR=<fresh mkdtemp>   (darwin only, belt-and-suspenders)
 *
 * The prompt (rubric + raw hits) rides on the child's stdin, not argv: argv is
 * capped by the OS's ARG_MAX (~1MB on most platforms), and a large hit set
 * pushed the prompt past it, failing the spawn with E2BIG. stdin has no such
 * ceiling, and keeps the raw hits off the process list and out of any
 * argv-echoing error message as a bonus.
 *
 * HOME is deliberately NOT isolated as the primary guard — that would break
 * auth on Linux (credentials live under $HOME there). The env pair above is
 * what suppresses the transcript while preserving Keychain/OS-store auth.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { maskText } from '@akasecurity/plugin-sdk';
import type { TriageHit, TriageRecommendation } from '@akasecurity/schema';

import { parseRecommendation } from './parse-verdict.ts';

const TRIAGE_DIR = dirname(fileURLToPath(import.meta.url));
// src/triage/judge.ts -> plugins/claude-code/eval/prompt.md
const DEFAULT_RUBRIC_PATH = join(TRIAGE_DIR, '..', '..', 'eval', 'prompt.md');

// -------------------------------------------------------------------------
// Pure parse: envelope -> verdict (shares the fence extractor with eval/run.ts)
// -------------------------------------------------------------------------

// Pull `.result` (the model's final text) out of the `--output-format json`
// envelope, then extract + validate the fenced TriageRecommendation via the
// shared parser. A missing/errored result is a hard failure, never a silent
// pass — the caller must not act on a verdict we could not read.
export function parseVerdict(stdout: string): TriageRecommendation {
  // Never echo the subprocess output in an error: it may carry a raw hit the
  // model failed to strip, and this error propagates to the parent command's
  // stderr — outside the isolated judge process. Every failure reports only
  // raw-free metadata (the flags/types that failed), never the content.
  let envelope: { result?: string; is_error?: boolean };
  try {
    envelope = JSON.parse(stdout) as { result?: string; is_error?: boolean };
  } catch {
    throw new Error('claude -p returned a non-JSON envelope');
  }
  if (envelope.is_error || typeof envelope.result !== 'string') {
    throw new Error(
      `claude -p returned no usable result (is_error=${String(envelope.is_error === true)}, ` +
        `result type=${typeof envelope.result})`,
    );
  }
  try {
    return parseRecommendation(envelope.result);
  } catch {
    throw new Error('claude -p returned an unparseable TriageRecommendation');
  }
}

// -------------------------------------------------------------------------
// Subprocess env + spawn
// -------------------------------------------------------------------------

// Env for the ephemeral judge subprocess. CLAUDE_CODE_SKIP_PROMPT_HISTORY=1 is
// the cross-OS transcript suppressor (and keeps auth intact). On darwin we ALSO
// point CLAUDE_CONFIG_DIR at a fresh throwaway dir as belt-and-suspenders — the
// caller (runJudge) removes it after the call. DISABLE_NONESSENTIAL_TRAFFIC is
// telemetry-off only (NOT a transcript guard) — kept to match the documented
// scripted-Claude pattern in eval/run.ts.
export function judgeEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    // eslint-disable-next-line n/no-process-env -- subprocess must inherit PATH/auth
    ...process.env,
    CLAUDE_CODE_SKIP_PROMPT_HISTORY: '1',
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
  };
  if (process.platform === 'darwin') {
    env.CLAUDE_CONFIG_DIR = mkdtempSync(join(tmpdir(), 'aka-judge-cfg-'));
  }
  return env;
}

// Real subprocess spawn used in production wiring. Kept separate from runJudge
// so unit tests inject a fake and NEVER hit a live model. The prompt (which
// carries the raw hits) rides on stdin rather than argv — argv has an OS
// ceiling (ARG_MAX, ~1MB on most platforms) that a large hit set can exceed,
// failing the spawn with E2BIG; stdin has no such limit. Returns raw stdout
// (the JSON envelope) for parseVerdict.
export function spawnClaude(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  stdin: string,
): string {
  return execFileSync('claude', [...argv], {
    env,
    input: stdin,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
  });
}

// Raw-free description of a spawn failure. The prompt now rides on stdin, not
// argv, so an execFileSync error's `.message` (which echoes argv) can no
// longer carry the raw hits — but its captured stdout/stderr still might, and
// none of it may cross back to the parent command. This stays belt-and-
// suspenders: we surface ONLY the non-content metadata (exit status / signal /
// node error code), never `.message`, `.stdout`, or `.stderr`.
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
  // Injected spawn seam: receives the argv AFTER `claude`, the subprocess env,
  // and the prompt (fed on stdin, not argv — see spawnClaude), and returns
  // process stdout (the --output-format json envelope). Tests inject a fake
  // returning a canned envelope so no real `claude -p` runs.
  spawn: (argv: readonly string[], env: NodeJS.ProcessEnv, stdin: string) => string;
  // Override the rubric source (defaults to eval/prompt.md); injectable so
  // tests need not read the real file.
  loadRubric?: () => string;
}

// Minimize a hit before it crosses to the model. The rubric judges the actual
// value, so rawMatch stays; the model does not need the provenance. filePath
// encodes the OS username and every project directory name, so it is dropped.
// context is a raw text window masked only for other overlapping findings, so it
// is re-run through the full detection engine (maskText) to mask every secret in
// the window. rawMatch is then the only raw field that leaves the machine.
// maskText is fail-secure: a masking fault over-redacts, never leaks.
// The spread is load-bearing: it drops filePath from a COPY, never off the
// source hit — the surfaced-secrets writeback still reads filePath off the
// original in-memory hits, so mutating in place here would break that path.
export function toJudgePayload(hit: TriageHit): TriageHit {
  const payload: TriageHit = { ...hit, context: maskText(hit.context) };
  delete payload.filePath;
  return payload;
}

// Build the judge prompt (rubric + raw hits as JSONL) and run it through the
// ephemeral subprocess, returning the parsed verdict. The RAW hits ride in the
// prompt on purpose (the rubric needs them); the prompt rides on stdin (not
// argv) so a large hit set never trips the OS's ARG_MAX and so raw can't leak
// via a spawn error's argv-echoing `.message`. judgeEnv()'s env is what keeps
// the prompt out of any transcript. Always cleans up the darwin config dir.
export function runJudge(hits: readonly TriageHit[], deps: JudgeDeps): TriageRecommendation {
  const rubric = deps.loadRubric?.() ?? readFileSync(DEFAULT_RUBRIC_PATH, 'utf8');
  const hitsJsonl = hits.map((h) => JSON.stringify(toJudgePayload(h))).join('\n');
  const fullPrompt = `${rubric}\n\n## Hits\n\n\`\`\`\n${hitsJsonl}\n\`\`\`\n`;

  const argv = ['-p', '--no-session-persistence', '--output-format', 'json'] as const;
  const env = judgeEnv();
  try {
    // The spawn is isolated from the parse: a spawn failure (execFileSync) throws
    // an error whose captured stdout/stderr may still carry raw content even
    // though the prompt itself no longer rides argv. Re-throw it as raw-free
    // metadata so nothing raw can ride the error out to the parent command's
    // stderr — belt-and-suspenders now that stdin is the only raw-bearing seam.
    let stdout: string;
    try {
      stdout = deps.spawn(argv, env, fullPrompt);
    } catch (err) {
      // Deliberately NOT chaining `err` as `cause`: the execFileSync error's captured
      // stdout/stderr may still carry raw content, and attaching it would re-expose
      // exactly what this throw exists to strip. Only raw-free metadata is surfaced.
      // eslint-disable-next-line preserve-caught-error -- caught error may carry raw; see above
      throw new Error(`claude -p judge subprocess failed (${spawnFailureMeta(err)})`);
    }
    return parseVerdict(stdout);
  } finally {
    if (process.platform === 'darwin' && env.CLAUDE_CONFIG_DIR) {
      rmSync(env.CLAUDE_CONFIG_DIR, { recursive: true, force: true });
    }
  }
}
