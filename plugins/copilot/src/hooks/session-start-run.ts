/**
 * sessionStart (Copilot CLI, cloud coding agent) / SessionStart (VS Code agent
 * mode) — fires when a session begins.
 *
 * event:   the token argv carried (see ./event-name.ts). The plugin manifest
 *          path rides argv[3]; see `MANIFEST_ARGV_INDEX` in ../build-info.ts.
 * stdin:   CLI    { sessionId, timestamp, cwd, source, initialPrompt? }
 *          VSCode { hook_event_name, session_id, cwd, source }
 * stdout:  no hook output, on every path, on both dialects. On the CLI the
 *          notices below also go out as progress lines, which the host strips
 *          before reading the output (see `progressLine` in ./shared.ts).
 * stderr:  the session start's once-per-session notices (forwarding, stale
 *          plugin, warn-era cap) and the store-redirect warning, when any apply.
 *
 * The once-per-session inventory pass: resolve this machine's host / harness /
 * account and the project, upsert them, and open the Session audit-event root
 * that every later capture hangs off. All of that lives in
 * `@akasecurity/plugin-runtime`; this script is stdio glue.
 *
 * THIS HOOK EMITS NOTHING AND THAT IS NOT AN OVERSIGHT. SessionStart reaches no
 * verdict on either host, and on the CLI an emitted payload is only ever read
 * as one — so `runSessionStart` returns `undefined` unconditionally and the entry
 * passes `runHookEntry` no fail-open payload. Silence is what both hosts read as "no
 * opinion", and it is the same answer a throw, a decline and a watchdog win
 * produce here.
 *
 * TWO THINGS ARE DIFFERENT HERE FROM EVERY SIBLING, and both are recorded facts
 * rather than guesses:
 *
 *  1. **This event is not first.** The recorded CLI session stamps
 *     `userPromptSubmitted` at 1788547858031 and `sessionStart` at
 *     1788547858051 — the prompt hook fires TWENTY MILLISECONDS BEFORE the
 *     session hook it is supposedly inside (see `test/fixtures/cli/README.md`).
 *     So this once-per-session pass routinely runs after the session's first
 *     capture has already been written, and nothing on this path may assume
 *     otherwise. It does not have to: `handleSessionStart` is claimed once per
 *     session and the root it opens is keyed on the session id rather than on
 *     being written first. `test/hooks/session-start-order.test.ts` drives the
 *     recorded order rather than the intuitive one.
 *
 *  2. **The provider is unresolved, on purpose.** Copilot publishes no
 *     base-url environment variable, so `resolveCopilotProvider` answers
 *     `'unknown'` rather than naming a backend nothing in this process can
 *     see. See `@akasecurity/plugin-sdk`'s `provider-copilot.ts`.
 *
 * `harnessInterface` is the surface this session runs on, derived from the
 * payload DIALECT rather than from a transcript originator (the Codex sibling's
 * route), because the two hosts this package covers are told apart by their
 * wire shape and nothing else. It rides in the attribute bag as an opaque
 * string; it never forks the harness dimension.
 *
 * A PAYLOAD WITH NO `cwd` DECLINES WITHOUT OPENING THE STORE. `cwd` is required
 * by `handleSessionStart` and there is no safe default here: VS Code documents
 * the hook process's own cwd as the home directory unless the hook entry
 * declares one, so `process.cwd()` could resolve a repo from `~` and stamp the
 * session root — a durable row — with whatever happens to live there. The CLI
 * sends `cwd` on every recorded payload, and so did the recorded VS Code 1.141
 * session, which also ran the hooks in the workspace, so this costs neither
 * recorded host anything.
 *
 * This module is the handler and nothing else: it reads neither argv's event
 * token nor stdin, and never exits. `./session-start.ts` is the entry that
 * feeds it, and `runHookFailOpen` there is what guarantees the exit 0.
 */
import { handleSessionStart, sessionStartNotice } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCopilotProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { harnessVersionFromArgv, PLUGIN_PACKAGE, pluginBuild } from '../build-info.ts';
import { readSessionStartFacts } from './session-start-payload.ts';
import type { HookHandler } from './shared.ts';
import { noticeWriter, parseJson, writeNotice } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

/**
 * The two events this entry is registered for, one per dialect.
 *
 * Checked rather than assumed, for the reason `pre-tool-use-run.ts` gives: a
 * manifest that wired this script to some other event would otherwise open a
 * session root off a payload that is not a session start — and on this host
 * `sessionEnd` and `sessionStart` carry the SAME envelope, so nothing in the
 * payload would catch it.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['sessionStart', 'SessionStart']);

/**
 * The sessionStart handler. `options.akaHome` points the store and settings at
 * another home and `options.homeDir` the host-config read at another home dir;
 * the entry passes neither.
 */
export const runSessionStart: HookHandler = async (event, stdin, options = {}) => {
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const facts = readSessionStartFacts(parseJson(stdin));
  // No workspace, no session root. See the header: a default here is a
  // fabricated repo on a durable row, not a graceful degradation.
  if (facts.cwd === undefined) return undefined;

  // SessionStart is the one hook that snapshots the provider onto the session
  // root, so it is the one that must pass this host's resolver explicitly —
  // `loadConfig`'s default resolves Claude Code's shape, which every OTHER hook
  // in this package can live with because none of them reads `.provider`.
  const config = loadConfig(options.akaHome, resolveCopilotProvider);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session, on stderr and, on the CLI, as a progress line.
  warnIfStoreRedirected(config, facts.sessionId, noticeWriter(facts.dialect));
  // One version value feeds both the inventory stamp and the posture identity,
  // so the two can never disagree about which build is running: argv's manifest
  // when the hook command passes one (at slot THREE on this host), else the
  // manifest beside the running script.
  const version = harnessVersionFromArgv() ?? pluginBuild()?.version;
  const result = await handleSessionStart(
    {
      sessionId: facts.sessionId,
      cwd: facts.cwd,
      tool: SOURCE_TOOL.Copilot,
      harnessVersion: version,
      harnessInterface: facts.harnessInterface,
      pluginBuild: version === undefined ? undefined : { package: PLUGIN_PACKAGE, version },
      homeDir: options.homeDir,
    },
    config,
  );
  // The session start's notices, once per session (they ride the SessionStart
  // claim): where this session's activity is forwarded, that a newer binary
  // recorded the mirror (so this session's plugin generation is outdated and
  // its installed-pack writes are gated), and that a warn-era store's
  // block/redact categories were capped to warn. Never a payload: this hook has
  // no decision channel and no message field on either dialect, and an
  // invented payload here would be read as a decision. stderr, plus a progress
  // line on the CLI, which is not a payload.
  const notice = sessionStartNotice(result);
  if (notice !== undefined) writeNotice(notice, facts.dialect);

  return undefined;
};
