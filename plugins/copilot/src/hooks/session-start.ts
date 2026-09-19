/**
 * sessionStart (CLI, cloud) / SessionStart (VS Code) — fires when a session
 * begins.
 *
 * argv:   [node, script, '<eventName>', '<pluginManifestPath>?']
 *         — argv[2] is the EVENT NAME on this host, so the manifest is at
 *           argv[3]. See ../build-info.ts.
 * stdin:  CLI    { sessionId, timestamp, cwd, source, initialPrompt? }
 *         VSCode { hook_event_name, session_id, cwd, source }
 *
 * Emits nothing. SessionStart has no decision to make on either host, so this
 * takes the siblings' silent shape rather than `runHookFailOpen` — the explicit
 * allow is `preToolUse`'s alone, because that is the one event the CLI reads a
 * crash on as a deny.
 *
 * TWO THINGS ARE DIFFERENT HERE FROM EVERY SIBLING, and both are recorded
 * facts rather than guesses:
 *
 *  1. **This event is not first.** The recorded CLI session stamps
 *     `userPromptSubmitted` at 1788547858031 and `sessionStart` at
 *     1788547858051 — the prompt hook fires TWENTY MILLISECONDS BEFORE the
 *     session hook it is supposedly inside. So the once-per-session inventory
 *     pass here routinely runs after the session's first capture has already
 *     been written, and nothing on this path may assume otherwise. It does not
 *     have to: `handleSessionStart` is idempotent and content-addressed, and
 *     the session root it opens is keyed on the session id rather than on
 *     being written first. `test/hooks/session-start-order.test.ts` drives the
 *     recorded order rather than the intuitive one.
 *
 *  2. **The provider is unresolved, on purpose.** Copilot publishes no
 *     base-url environment variable, so `resolveCopilotProvider` answers
 *     `'unknown'` rather than naming a backend nothing in this process can
 *     see. See `@akasecurity/plugin-sdk`'s `provider-copilot.ts`.
 *
 * `harnessInterface` is the surface this session runs on — `cli`, `vscode`,
 * `cloud` — derived from the payload DIALECT rather than from a transcript
 * originator (the Codex sibling's route), because the two hosts this package
 * covers are told apart by their wire shape and nothing else. It rides in the
 * attribute bag as an opaque string; it never forks the harness dimension.
 *
 * Fully fail-open: any error → no output, exit 0.
 */
import { handleSessionStart } from '@akasecurity/plugin-runtime';
import { loadConfig, resolveCopilotProvider } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { harnessVersionFromArgv, PLUGIN_PACKAGE, pluginBuild } from '../build-info.ts';
import { readSessionStartFacts } from './session-start-payload.ts';
import { parseJson, readStdin } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';

async function main(): Promise<void> {
  const facts = readSessionStartFacts(parseJson(await readStdin()));
  const sessionId = facts.sessionId;
  const cwd = facts.cwd ?? process.cwd();

  // SessionStart is the one hook that snapshots the provider onto the session
  // root, so it is the one that must pass this host's resolver explicitly —
  // `loadConfig`'s default resolves Claude Code's shape, which every OTHER
  // hook in this package can live with because none of them reads `.provider`.
  const config = loadConfig(undefined, resolveCopilotProvider);
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
  // One version value feeds both the inventory stamp and the posture identity,
  // so the two can never disagree about which build is running: argv's manifest
  // when the hook command passes one (at slot THREE on this host), else the
  // manifest beside the running script.
  const version = harnessVersionFromArgv() ?? pluginBuild()?.version;
  const result = await handleSessionStart(
    {
      sessionId,
      cwd,
      tool: SOURCE_TOOL.Copilot,
      harnessVersion: version,
      harnessInterface: facts.harnessInterface,
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
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
