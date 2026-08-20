/**
 * PreInvocation — fires before the model is called.
 *
 * THIS EVENT STANDS IN FOR TWO CLAUDE CODE HOOKS THAT ANTIGRAVITY DOES NOT
 * HAVE. Its five events are PreToolUse, PostToolUse, PreInvocation,
 * PostInvocation and Stop: there is no SessionStart and no UserPromptSubmit.
 *
 *  - SessionStart. The once-per-session inventory pass hangs off the FIRST
 *    invocation of a conversation instead. Nothing extra is needed to make that
 *    once-per-session: `handleSessionStart` claims internally
 *    (plugin-sdk's claimSessionStart), so later invocations no-op.
 *
 *  - UserPromptSubmit. Antigravity's PreInvocation payload carries
 *    `invocationNum`, `initialNumSteps` and the common fields — and NO PROMPT
 *    TEXT. No event on this host hands a hook the user's message before the
 *    model sees it, and PreInvocation's output (`injectSteps`) can only ADD
 *    steps, never reject one. So a prompt can be neither blocked nor redacted
 *    on Antigravity, and this adapter does not pretend to: prompts are captured
 *    AFTER THE FACT from the transcript by the reconcile worker below, and the
 *    finding is ledgered rather than enforced. See skills/setup/SKILL.md,
 *    "Known limitations".
 *
 * stdin:  { invocationNum, initialNumSteps, conversationId, workspacePaths,
 *           transcriptPath, artifactDirectoryPath }
 * argv[2] (optional): the plugin manifest path (<plugin root>/plugin.json), so
 *   the harness build version lands in the inventory bag.
 * stdout: {} — no steps injected.
 *
 * Fail-open on a fail-closed host: `runHookFailOpen` always writes `{}` and
 * exits 0 — see shared.ts.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveAntigravityProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import {
  getString,
  parseJson,
  primaryWorkspacePath,
  readStdin,
  runHookFailOpen,
} from './shared.ts';

const CARRY_ON = {};

// The plugin's own version, read from the manifest the hook command passes as
// argv[2] (same source as the intro card). Best-effort: an unreadable/old
// manifest just omits the version — the harness dimension still resolves on tool.
function harnessVersion(): string | undefined {
  const manifestPath = process.argv[2];
  if (!manifestPath) return undefined;
  try {
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as { version?: unknown };
    return typeof manifest.version === 'string' ? manifest.version : undefined;
  } catch {
    return undefined;
  }
}

async function main(): Promise<unknown> {
  const input = parseJson(await readStdin());
  const sessionId = input ? getString(input, 'conversationId') : undefined;
  const cwd = (input ? primaryWorkspacePath(input) : undefined) ?? process.cwd();
  const transcriptPath = input ? getString(input, 'transcriptPath') : undefined;

  // No `harnessInterface` is recorded. Codex reads one from its rollout
  // (`codex_cli_rs` vs `codex_desktop`), but Antigravity's payload carries no
  // equivalent field. Hooks are believed to execute only in the CLI and not in
  // the IDE, which would make the value a constant — but that is an observed
  // limitation rather than a documented guarantee, so recording it as a fact
  // would be asserting something this hook cannot see.
  //
  // handleSessionStart's config parameter defaults to loadConfig() with NO
  // resolver override, which resolves Claude Code's provider shape — every
  // OTHER hook can rely on that default (they never read config.provider), but
  // this is the one place that snapshots it onto the session root, so it must
  // pass the Antigravity resolver explicitly.
  const config = loadConfig(undefined, resolveAntigravityProvider);
  const result = await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Antigravity,
      harnessVersion: harnessVersion(),
    },
    config,
  );
  // Stale-session notice (once per session — it rides the SessionStart claim):
  // a newer binary recorded the mirror, so this session's plugin generation is
  // outdated and its installed-pack writes are gated. stderr, not a decision.
  if (result.staleBinaryNotice !== null) {
    process.stderr.write(`[aka] ${result.staleBinaryNotice}\n`);
  }

  // The prompt-capture path. The transcript is the only place this host exposes
  // the user's message, so the throttled background pass over its tail is what
  // records prompts (and the tool results PostToolUse never sees). Triggering
  // it here means a conversation that never calls a tool is still captured.
  // Fully best-effort — a missing path or any error just skips it; the Stop and
  // PostToolUse triggers cover it.
  if (sessionId !== undefined && transcriptPath !== undefined) {
    triggerReconcile(config.dataDir, sessionId, transcriptPath);
  }
  return CARRY_ON;
}

await runHookFailOpen(main, CARRY_ON);
