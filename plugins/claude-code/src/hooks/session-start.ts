/**
 * SessionStart — fires when a Claude Code session begins (startup, resume, clear).
 *
 * stdin:  { session_id, cwd, hook_event_name, source, ... }
 * argv[2] (optional): the plugin manifest path (${CLAUDE_PLUGIN_ROOT}/.claude-plugin/
 *   plugin.json), so the harness build version lands in the inventory bag.
 *
 * The once-per-session inventory pass: resolve this machine's host/harness/account
 * and the project, upsert them, and open the Session audit-event root. All the
 * logic lives in @akasecurity/plugin-runtime; the hook's run is runSessionStart
 * (session-start-run.ts), and this script reads stdin, the plugin manifest and
 * the host's environment and hands them in.
 *
 * Emits nothing on a standalone machine without vault consent (SessionStart
 * has no decision to make). On an attached machine it shows the user, as
 * systemMessage, the line saying where this session's activity goes; with
 * vault consent it also injects the standing vault protocol brief as
 * additionalContext. Fully fail-open: any error → no output,
 * exit 0.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';

import { pluginBuild } from '../build-info.ts';
import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { runSessionStart } from './session-start-run.ts';
import { countFailOpen, emit, parseJson, readStdin } from './shared.ts';

// Which SURFACE of Claude Code is running this session — the value the host
// stamps on its own subprocess environment. `claude-vscode` for the VS Code
// panel, `claude-desktop` for the desktop app, `cli` for a terminal, plus the
// SDK's own spellings; treated as an opaque string either way, never mapped to
// a harness id here.
//
// Read from the environment rather than peeked out of the transcript, and the
// difference is not a preference. `entrypoint` appears on the first
// user/assistant record — measured as record 3 or 4 across sixty transcripts —
// so a session that has just STARTED has no record carrying it, which is every
// `source: startup` session at the moment this hook runs. The transcript stays
// the backfill's source (history/usage.ts reads it there, where the records
// exist).
//
// Best-effort: an absent or empty value omits the fact, which is exactly the
// behaviour before this existed. Nothing downstream requires it.
function harnessInterface(): string | undefined {
  const value = process.env.CLAUDE_CODE_ENTRYPOINT;
  return value === undefined || value === '' ? undefined : value;
}

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
  await runSessionStart(parseJson(await readStdin()), {
    // One version value feeds both the inventory stamp and the posture
    // identity, so the two can never disagree about which build is running:
    // argv's manifest when the hook command passes one, else the manifest
    // beside the running script — read once either way.
    version: harnessVersion() ?? pluginBuild()?.version,
    harnessInterface: harnessInterface(),
    handleSessionStart,
    triggerReconcile,
    emit,
  });
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
