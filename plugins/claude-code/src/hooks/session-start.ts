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
 * Emits nothing (SessionStart has no decision to make) — except when the user
 * has granted vault consent, in which case it injects the standing vault
 * protocol brief as additionalContext. Fully fail-open: any error → no output,
 * exit 0.
 */
import { readFileSync } from 'node:fs';

import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, recordSessionModel } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import { PLUGIN_PACKAGE, pluginBuild } from '../build-info.ts';
import { triggerReconcile } from '../history/reconcile-trigger.ts';
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
  // SessionStart is the ONLY event that carries the session's starting model,
  // and the harness does not always include it — so this is best-effort, and
  // `recordSessionModel` no-ops when it is absent. Recording it is what lets
  // UserPromptSubmit refuse the very FIRST turn of a session started on a
  // prohibited model; without it that turn has no transcript to read a model
  // from and is allowed through. SessionStart itself cannot block.
  recordSessionModel(
    loadConfig().dataDir,
    sessionId,
    input ? getString(input, 'model') : undefined,
  );
  // One version value feeds both the inventory stamp and the posture
  // identity, so the two can never disagree about which build is running:
  // argv's manifest when the hook command passes one, else the manifest
  // beside the running script — read once either way.
  const version = harnessVersion() ?? pluginBuild()?.version;
  const result = await handleSessionStart({
    sessionId,
    cwd,
    tool: SOURCE_TOOL.ClaudeCode,
    harnessVersion: version,
    pluginBuild: version === undefined ? undefined : { package: PLUGIN_PACKAGE, version },
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
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
  if (sessionId !== undefined && transcriptPath !== undefined) {
    triggerReconcile(config.dataDir, sessionId, transcriptPath);
  }

  // Standing vault-protocol brief: only when the user has granted vault
  // consent does this hook emit anything at all — the brief teaches the model
  // what a pointer is and carries the per-session authenticity marker.
  // Without consent the vault is inert and SessionStart stays silent.
  if (isVaultConsentValid(config.settings.vaultConsent)) {
    await emit({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: standingBrief({
          marker: sessionProtocolMarker(config.dataDir, sessionId),
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
