/**
 * The ephemeral setup-wizard judge runner.
 *
 * The FP/severity judgment is the one place the wizard feeds the model RAW
 * hits (rawMatch + surrounding context) — the locked rubric (eval/prompt.md)
 * requires raw to judge accurately. To keep that raw out of the user's
 * scannable transcript store (~/.claude/projects), the judgment runs as a
 * SEPARATE, transient `claude -p` subprocess that writes NO transcript:
 *
 *   claude -p --no-session-persistence --output-format json <prompt>
 *   env: CLAUDE_CODE_SKIP_PROMPT_HISTORY=1   (no transcript, any OS; keeps auth)
 *        CLAUDE_CONFIG_DIR=<fresh mkdtemp>   (darwin only, belt-and-suspenders)
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
  const envelope = JSON.parse(stdout) as { result?: string; is_error?: boolean };
  if (envelope.is_error || typeof envelope.result !== 'string') {
    throw new Error(`claude -p returned no usable result: ${stdout.slice(0, 500)}`);
  }
  return parseRecommendation(envelope.result);
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
// so unit tests inject a fake and NEVER hit a live model. Returns raw stdout
// (the JSON envelope) for parseVerdict.
export function spawnClaude(argv: readonly string[], env: NodeJS.ProcessEnv): string {
  return execFileSync('claude', [...argv], {
    env,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 32 * 1024 * 1024,
  });
}

// -------------------------------------------------------------------------
// runJudge
// -------------------------------------------------------------------------

export interface JudgeDeps {
  // Injected spawn seam: receives the argv AFTER `claude` and the subprocess
  // env, returns process stdout (the --output-format json envelope). Tests
  // inject a fake returning a canned envelope so no real `claude -p` runs.
  spawn: (argv: readonly string[], env: NodeJS.ProcessEnv) => string;
  // Override the rubric source (defaults to eval/prompt.md); injectable so
  // tests need not read the real file.
  loadRubric?: () => string;
}

// Build the judge prompt (rubric + raw hits as JSONL) and run it through the
// ephemeral subprocess, returning the parsed verdict. The RAW hits ride in the
// prompt on purpose (the rubric needs them); judgeEnv()'s env is what keeps
// them out of any transcript. Always cleans up the darwin config dir.
export function runJudge(hits: readonly TriageHit[], deps: JudgeDeps): TriageRecommendation {
  const rubric = deps.loadRubric?.() ?? readFileSync(DEFAULT_RUBRIC_PATH, 'utf8');
  const hitsJsonl = hits.map((h) => JSON.stringify(h)).join('\n');
  const fullPrompt = `${rubric}\n\n## Hits\n\n\`\`\`\n${hitsJsonl}\n\`\`\`\n`;

  const argv = ['-p', '--no-session-persistence', '--output-format', 'json', fullPrompt] as const;
  const env = judgeEnv();
  try {
    return parseVerdict(deps.spawn(argv, env));
  } finally {
    if (process.platform === 'darwin' && env.CLAUDE_CONFIG_DIR) {
      rmSync(env.CLAUDE_CONFIG_DIR, { recursive: true, force: true });
    }
  }
}
