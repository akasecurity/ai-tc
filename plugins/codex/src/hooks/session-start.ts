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
 * Emits nothing (SessionStart has no decision to make) — except when the user
 * has granted vault consent, in which case it injects the standing vault
 * protocol brief as additionalContext, same as Claude Code's sibling hook.
 * This plugin has no vault wiring of its own (see pre-tool-use-decision.ts) —
 * it never MINTS a pointer — but `~/.aka` is one home shared by every AKA
 * surface on the machine, so a pointer minted by the Claude Code plugin's
 * vault or the setup wizard's history scrub can still surface in a Codex
 * session's context (a file read, a git diff, prior session history), and
 * without this brief the model has no idea what `[[aka:<category>:...]]` is.
 * Fully fail-open: any error → no output, exit 0.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCodexProvider } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import { PLUGIN_PACKAGE, pluginBuild } from '../build-info.ts';
import { triggerReconcile } from '../history/reconcile-trigger.ts';
import { peekSessionOriginator } from '../history/transcripts.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { standingBrief } from '../protocol/notes.ts';
import { emit, getString, parseJson, readStdin } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

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
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
  // One version value feeds both the inventory stamp and the posture
  // identity, so the two can never disagree about which build is running:
  // argv's manifest when the hook command passes one, else the manifest
  // beside the running script — read once either way.
  const version = harnessVersion() ?? pluginBuild()?.version;
  const result = await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Codex,
      harnessVersion: version,
      harnessInterface,
      pluginBuild: version === undefined ? undefined : { package: PLUGIN_PACKAGE, version },
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

  // Standing vault-protocol brief: only when the user has granted vault
  // consent does this hook emit anything at all — the brief teaches the model
  // what a pointer is and carries a per-session authenticity marker.
  // Without consent the vault is inert and SessionStart stays silent.
  //
  // The marker is minted with `sessionId` deliberately OMITTED, so it is
  // never persisted to the shared `protocol-marker` file: that file is keyed
  // by session id and overwritten on every mismatch, and Claude Code's
  // pre-tool-use/post-tool-use hooks re-read it on every vaulted event, so a
  // Codex session persisting its own marker there (SessionStart also fires on
  // resume/compact) would silently break a concurrent Claude Code session's
  // marker chain — the exact "authentic note reads as a forgery" degrade
  // protocol/marker.ts describes. Nothing is lost by not persisting: no
  // Codex hook emits a per-event note today (eventNote has no caller here),
  // so this marker is only ever read back from the brief text itself.
  if (isVaultConsentValid(config.settings.vaultConsent)) {
    await emit({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: standingBrief({
          marker: sessionProtocolMarker(config.dataDir, undefined),
          inlineReveal: config.settings.vaultInlineReveal,
        }),
      },
    });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
