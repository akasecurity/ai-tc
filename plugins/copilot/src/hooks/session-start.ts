/**
 * sessionStart (Copilot CLI, cloud coding agent) / SessionStart (VS Code agent
 * mode) — fires when a session begins.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 *          The event rides slot TWO on this host, so the manifest is displaced
 *          one place right; see `MANIFEST_ARGV_INDEX` in ../build-info.ts.
 * stdin:   CLI    { sessionId, timestamp, cwd, source, initialPrompt? }
 *          VSCode { hook_event_name, session_id, cwd, source }
 * stdout:  NOTHING, on every path, on both dialects.
 *
 * The once-per-session inventory pass: resolve this machine's host / harness /
 * account and the project, upsert them, and open the Session audit-event root
 * that every later capture hangs off. All of that lives in
 * `@akasecurity/plugin-runtime`; this script is stdio glue.
 *
 * THIS HOOK EMITS NOTHING AND THAT IS NOT AN OVERSIGHT. SessionStart reaches no
 * verdict on either host, and on the CLI an emitted payload is only ever read
 * as one — so `main` returns `undefined` unconditionally and `runHookFailOpen`
 * is passed no fail-open payload. Silence is what both hosts read as "no
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
 * by `handleSessionStart` and there is no safe default here: under VS Code the
 * hook process's own cwd is the HOME DIRECTORY unless the hook entry declared
 * one, so `process.cwd()` would resolve a repo from `~` and stamp the session
 * root — a durable row — with whatever happens to live there. The CLI sends
 * `cwd` on every recorded payload, so this costs that host nothing.
 *
 * `runHookFailOpen` is what guarantees the exit 0; see ./shared.ts for the
 * limit of that guarantee, which is everything that yields.
 */
import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCopilotProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { harnessVersionFromArgv, PLUGIN_PACKAGE, pluginBuild } from '../build-info.ts';
import { readEventName } from './event-name.ts';
import { readSessionStartFacts } from './session-start-payload.ts';
import { parseJson, readStdin, runHookFailOpen, writeNotice } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

/**
 * The two events this entry is registered for, one per dialect.
 *
 * Checked rather than assumed, for the reason `pre-tool-use.ts` gives: a
 * manifest that wired this script to some other event would otherwise open a
 * session root off a payload that is not a session start — and on this host
 * `sessionEnd` and `sessionStart` carry the SAME envelope, so nothing in the
 * payload would catch it.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set(['sessionStart', 'SessionStart']);

async function main(): Promise<undefined> {
  const event = readEventName();
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const facts = readSessionStartFacts(parseJson(await readStdin()));
  // No workspace, no session root. See the header: a default here is a
  // fabricated repo on a durable row, not a graceful degradation.
  if (facts.cwd === undefined) return undefined;

  // SessionStart is the one hook that snapshots the provider onto the session
  // root, so it is the one that must pass this host's resolver explicitly —
  // `loadConfig`'s default resolves Claude Code's shape, which every OTHER hook
  // in this package can live with because none of them reads `.provider`.
  const config = loadConfig(undefined, resolveCopilotProvider);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session on stderr, so this hook's stdout silence is untouched.
  warnIfStoreRedirected(config, facts.sessionId);
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
    },
    config,
  );
  // Stale-session notice (once per session — it rides the SessionStart claim):
  // a newer binary recorded the mirror, so this session's plugin generation is
  // outdated and its installed-pack writes are gated. stderr, never stdout:
  // this hook has no decision channel at all, and an invented payload here
  // would be read as one.
  if (result.staleBinaryNotice !== null) writeNotice(`[aka] ${result.staleBinaryNotice}`);

  return undefined;
}

// No fail-open payload, and nothing to emit on the happy path either: this hook
// reaches no verdict, so every path through it writes nothing and exits 0.
await runHookFailOpen(main);
