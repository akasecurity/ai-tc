// The SessionStart hook's run, with its inputs handed in so a test can drive it.
// The entry (session-start.ts) reads stdin, the plugin manifest and the host's
// environment, and passes the session start, the reconcile trigger and the
// emitter this runs with.
import type { handleSessionStart } from '@akasecurity/plugin-runtime';
import { sessionStartNotice } from '@akasecurity/plugin-runtime';
import { loadConfig, recordSessionModel } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import { INSTALL_ROOT, PLUGIN_PACKAGE } from '../build-info.ts';
import type { triggerReconcile } from '../history/reconcile-trigger.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { standingBrief } from '../protocol/notes.ts';
import { recordSessionStartAccount } from './account-stamp.ts';
import type { HookOutput } from './shared.ts';
import { getString } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

export interface SessionStartDeps {
  /** The plugin's version: the manifest the hook command names, else the one beside the script. */
  readonly version: string | undefined;
  /** The surface the host names on its own subprocess environment, when it names one. */
  readonly harnessInterface: string | undefined;
  readonly handleSessionStart: typeof handleSessionStart;
  readonly triggerReconcile: typeof triggerReconcile;
  readonly emit: (output: HookOutput) => Promise<void>;
  /** The clock the session's boundary and login view are stamped with; the entry passes none. */
  readonly now?: (() => number) | undefined;
}

/** One SessionStart, from its parsed stdin payload (null when it did not parse). */
export async function runSessionStart(
  input: Record<string, unknown> | null,
  deps: SessionStartDeps,
): Promise<void> {
  const sessionId = input ? getString(input, 'session_id') : undefined;
  const cwd = (input ? getString(input, 'cwd') : undefined) ?? process.cwd();
  const transcriptPath = input ? getString(input, 'transcript_path') : undefined;
  // Read ONCE for the whole hook. Two reads of settings.json on this path can
  // disagree about `dataDir` — a settings write landing between them is all it
  // takes — and then the model marker and the reconcile trigger would be
  // written against two different homes.
  const config = loadConfig();
  // SessionStart is the ONLY event that carries the session's starting model,
  // and the harness does not always include it — so this is best-effort, and
  // `recordSessionModel` no-ops when it is absent. Recording it is what lets
  // UserPromptSubmit refuse the very FIRST turn of a session started on a
  // prohibited model; without it that turn has no transcript to read a model
  // from and is allowed through. SessionStart itself cannot block.
  recordSessionModel(config.dataDir, sessionId, input ? getString(input, 'model') : undefined);
  // The session's boundary, its inheritance on a resume and its login view,
  // recorded before the session start claims the session: a resume of an id
  // already claimed, or one stopped inside the session start, keeps its
  // boundary.
  const account = recordSessionStartAccount({
    config,
    sessionId,
    transcriptPath,
    cwd,
    source: input ? getString(input, 'source') : undefined,
    now: deps.now,
  });
  const { version } = deps;
  const result = await deps.handleSessionStart({
    sessionId,
    cwd,
    tool: SOURCE_TOOL.ClaudeCode,
    harnessVersion: version,
    // The install root rides with the identity on this path exactly as on the
    // reconciler's (pluginBuild()), so the installed version the posture block
    // reads never depends on which path won the hourly throttle.
    pluginBuild:
      version === undefined
        ? undefined
        : { package: PLUGIN_PACKAGE, version, installRoot: INSTALL_ROOT },
    // The surface this session is running on, when the host says. Folded into
    // the harness bag by the resolver and snapshotted as `harness_interface`;
    // absent when the host stamps nothing, which reads as unknown rather than
    // as a terminal session.
    harnessInterface: deps.harnessInterface,
    // A session whose login is a work subscription, or cannot be told yet, leaves
    // its root to the reconcile, which keys it by the account its first reply ran
    // under. The session start still writes it at once where its repository is
    // enrolled, and on a machine-wide attachment.
    rootAwaitsAccount: account.basis !== undefined || account.undetermined,
    // The basis the login view reached, given only for a work login.
    accountBasis: account.basis,
  });
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session. Collected rather than written to stderr: on this hook
  // it rides the systemMessage below with the other notices.
  const redirected: string[] = [];
  warnIfStoreRedirected(config, sessionId, (message) => redirected.push(message));
  // What the user sees at session start, once per session (each rides its own
  // once-per-session claim): where this session's activity goes, the
  // stale-session notice (a newer binary recorded the mirror, so this session's
  // plugin generation is outdated and its installed-pack writes are gated), the
  // warn-era notice, and the store-redirect warning. Shown as systemMessage,
  // the one SessionStart channel the host puts in front of the user: stderr
  // from a hook that exits 0 goes only to the debug log.
  const shown = sessionStartNotice(result, redirected);

  // Token-usage catch-up (safety net): after the inventory pass, trigger
  // the SAME throttled, detached reconcile for the just-opened session so a final
  // usage record that lagged the last Stop is picked up. SessionStart's payload
  // carries `transcript_path` too, so no path reconstruction. Behind the shared
  // reconcile throttle (so it never piles onto a recent Stop spawn) and fully
  // best-effort — a missing path or any error just skips it, the Stop path covers it.
  if (sessionId !== undefined && transcriptPath !== undefined) {
    deps.triggerReconcile(config.dataDir, sessionId, transcriptPath);
  }

  // Standing vault-protocol brief: only when the user has granted vault
  // consent does this hook give the model anything — the brief teaches the
  // model what a pointer is and carries the per-session authenticity marker.
  // Without consent the vault is inert, and only the user notice (if any) goes
  // out.
  if (isVaultConsentValid(config.settings.vaultConsent)) {
    await deps.emit({
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: standingBrief({
          marker: sessionProtocolMarker(config.dataDir, sessionId),
          inlineReveal: config.settings.vaultInlineReveal,
        }),
      },
      ...(shown === undefined ? {} : { systemMessage: shown }),
    });
  } else if (shown !== undefined) {
    await deps.emit({ systemMessage: shown });
  }
}
