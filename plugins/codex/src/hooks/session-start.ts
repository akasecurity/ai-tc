/**
 * SessionStart — fires when a Codex CLI session begins (startup, resume,
 * clear, or compact). Same event name and payload shape as Claude Code's
 * SessionStart hook.
 *
 * stdin:  { session_id, cwd, hook_event_name, ... }
 * argv[2] (optional): the plugin manifest path (${PLUGIN_ROOT}/.codex-plugin/
 *   plugin.json), so the harness build version lands in the inventory bag.
 *
 * The once-per-session inventory pass: resolve this machine's host/harness/account
 * and the project, upsert them, and open the Session audit-event root. All the
 * logic lives in @akasecurity/plugin-runtime; this script is just Codex CLI stdio glue.
 *
 * Emits nothing (SessionStart has no decision to make). Fully fail-open: any error
 * → no output, exit 0.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCodexProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { peekSessionOriginator } from '../history/transcripts.ts';
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
  const transcriptPath = input ? getString(input, 'transcript_path') : undefined;
  // Best-effort: session_meta.originator distinguishes which client is
  // hosting this Codex session — 'codex_cli_rs'/'codex-tui'/'codex_exec' for
  // a terminal invocation, 'codex_desktop' for Codex running inside the
  // ChatGPT desktop app, 'codex_vscode' for the VS Code extension. Same
  // engine, same hooks/plugin system in every case; this is purely a
  // descriptive fact for the dashboard, never a fork of the harness/
  // sourceTool dimension. A missing/unreadable transcript file just omits it.
  const harnessInterface =
    transcriptPath !== undefined ? peekSessionOriginator(transcriptPath) : undefined;
  // handleSessionStart's config parameter defaults to loadConfig() with NO
  // resolver override, which resolves Claude Code's provider shape — every
  // OTHER Codex hook can rely on that default (they never read
  // config.provider), but SessionStart is the one place that snapshots it
  // onto the session root, so it must pass the Codex resolver explicitly.
  const config = loadConfig(undefined, resolveCodexProvider);
  const result = await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Codex,
      harnessVersion: harnessVersion(),
      harnessInterface,
    },
    config,
  );
  // Stale-session notice (once per session — it rides the SessionStart claim):
  // a newer binary recorded the mirror, so this session's plugin generation is
  // outdated and its installed-pack writes are gated. stderr, not a decision.
  if (result.staleBinaryNotice !== null) {
    process.stderr.write(`[aka] ${result.staleBinaryNotice}\n`);
  }

  // Token-usage catch-up (safety net): after the inventory pass, trigger
  // the SAME throttled, detached reconcile for the just-opened session so a final
  // usage record that lagged the last Stop is picked up. Behind the shared
  // reconcile throttle (so it never piles onto a recent Stop spawn) and fully
  // best-effort — a missing path or any error just skips it, the Stop path covers it.
  if (sessionId !== undefined && transcriptPath !== undefined) {
    triggerReconcile(config.dataDir, sessionId, transcriptPath);
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
