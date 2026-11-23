/**
 * sessionStart — fires when a Cursor agent session begins.
 *
 * stdin:  { session_id, conversation_id, hook_event_name, workspace_roots,
 *           is_background_agent, composer_mode, cursor_version, model, … }
 * stdout: nothing, on every path. Cursor's `sessionStart` output can carry
 *         `additional_context` and `env`, and this hook sets neither.
 * stderr: the session start's once-per-session notices and the store-redirect
 *         warning, when any apply.
 *
 * The once-per-session inventory pass: resolve this machine's host, harness,
 * account and project, upsert them, and open the Session audit-event root every
 * later capture hangs off. All of that lives in `@akasecurity/plugin-runtime`;
 * this module is stdio glue.
 *
 * A PAYLOAD WITH NO WORKSPACE DECLINES WITHOUT OPENING THE STORE. This event
 * carries no `cwd`, only `workspace_roots`, and a user-level hook runs from
 * `~/.cursor`, so the process's own cwd would resolve a repo from the wrong
 * place and stamp a durable row with it.
 */
import { handleSessionStart, sessionStartNotice } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCursorProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { pluginBuild } from '../build-info.ts';
import { isOwnEvent } from './event-name.ts';
import { readCwd, readPayloadEvent, readSessionId } from './payload.ts';
import type { HookHandler } from './shared.ts';
import { parseJson, writeNotice } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

/**
 * The surface a session runs on, as an opaque attribute: a background (cloud)
 * agent says so, and anything else is the editor's own agent.
 */
export function harnessInterfaceFor(input: Record<string, unknown>): string {
  return input.is_background_agent === true ? 'background-agent' : 'ide';
}

export const runSessionStart: HookHandler = async (event, stdin, options = {}) => {
  const input = parseJson(stdin);
  if (!input) return undefined;
  if (!isOwnEvent('sessionStart', event, readPayloadEvent(input))) return undefined;

  const cwd = readCwd(input);
  if (cwd === undefined) return undefined;
  const sessionId = readSessionId(input);

  // The one hook that snapshots the provider onto the session root, so the one
  // that passes this host's resolver explicitly.
  const config = loadConfig(options.akaHome, resolveCursorProvider);
  warnIfStoreRedirected(config, sessionId);
  const build = pluginBuild();
  const result = await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Cursor,
      harnessVersion: build?.version,
      harnessInterface: harnessInterfaceFor(input),
      pluginBuild: build,
      homeDir: options.homeDir,
    },
    config,
  );
  const notice = sessionStartNotice(result);
  if (notice !== undefined) writeNotice(notice);
  return undefined;
};
