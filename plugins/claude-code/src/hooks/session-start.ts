/**
 * SessionStart — fires when a Claude Code session begins (startup, resume, clear).
 *
 * stdin:  { session_id, cwd, hook_event_name, source, ... }
 * argv[2] (optional): the plugin manifest path (${CLAUDE_PLUGIN_ROOT}/.claude-plugin/
 *   plugin.json), so the harness build version lands in the inventory bag.
 *
 * The once-per-session inventory pass: resolve this machine's host/harness/account
 * and the project, upsert them, and open the Session audit-event root. All the
 * logic lives in @akasecurity/plugin-runtime; this script is just Claude Code stdio glue.
 *
 * Emits nothing (SessionStart has no decision to make). Fully fail-open: any error
 * → no output, exit 0.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { getString, parseJson, readStdin } from './shared.ts';

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

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const sessionId = input ? getString(input, 'session_id') : undefined;
  const cwd = (input ? getString(input, 'cwd') : undefined) ?? process.cwd();
  const result = await handleSessionStart({
    sessionId,
    cwd,
    tool: 'claude-code',
    harnessVersion: harnessVersion(),
    // harnessInterface is intentionally omitted: Claude Code's SessionStart hook
    // exposes no meaningful interface discriminator (terminal vs IDE vs web) yet.
    // The resolver already folds it into the harness bag, so pass it here once
    // the harness surfaces one — no schema change needed.
  });
  // Stale-session notice (once per session — it rides the SessionStart claim):
  // a newer binary recorded the mirror, so this session's plugin generation is
  // outdated and its installed-pack writes are gated. stderr, not a decision.
  if (result.staleBinaryNotice !== null) {
    process.stderr.write(`[aka] ${result.staleBinaryNotice}\n`);
  }

  // Token-usage catch-up (safety net): after the inventory pass, trigger
  // the SAME throttled, detached reconcile for the just-opened session so a final
  // usage record that lagged the last Stop is picked up. SessionStart's payload
  // carries `transcript_path` too, so no path reconstruction. Behind the shared
  // reconcile throttle (so it never piles onto a recent Stop spawn) and fully
  // best-effort — a missing path or any error just skips it, the Stop path covers it.
  const transcriptPath = input ? getString(input, 'transcript_path') : undefined;
  if (sessionId !== undefined && transcriptPath !== undefined) {
    triggerReconcile(loadConfig().dataDir, sessionId, transcriptPath);
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
