/**
 * PreModelSwitch — fires before Claude Code applies a requested model switch,
 * and can refuse it.
 *
 * stdin:  { session_id, transcript_path, cwd, hook_event_name, from_model, to_model }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreModelSwitch",
 *     "permissionDecision":"deny","permissionDecisionReason":"..."}}  → switch refused
 *   no output                                                        → allow
 *
 * This is the PREVENTIVE half of prohibited-model governance and the only point
 * in the harness where a model choice can be refused before it takes effect. The
 * containment half is user-prompt-submit.ts, which refuses a TURN already
 * running on a prohibited model — a session can start on one, or have one
 * restored on resume, without any switch ever passing through here.
 *
 * Neither blocks an LLM API call: no hook fires around the request itself. What
 * the two together enforce is that a governed session does not RUN on a
 * prohibited model, for as long as the user keeps the plugin installed.
 *
 * The prohibition list rides the policy bundle the gateway already serves, so
 * this hook touches the local store and never the network.
 *
 * Fail-open: any error → no output, exit 0.
 */
import { loadConfig, recordSessionModel } from '@akasecurity/plugin-sdk';

import { decidePreModelSwitch } from './model-guard.ts';
import { emit, getString, parseJson, readStdin } from './shared.ts';
import { openGatewayOrNull, warnIfStoreRedirected } from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (input === null) return;
  const toModel = getString(input, 'to_model');
  if (toModel === undefined || toModel === '') return;

  const config = loadConfig();
  const sessionId = getString(input, 'session_id');
  // A symlinked home redirects the policy cache this hook decides from, so it
  // is worth saying here as much as anywhere: the prohibitions it reads may not
  // be the ones this machine was attached with. Once per session, on stderr, so
  // the stdout decision contract is untouched.
  warnIfStoreRedirected(config, sessionId);

  // No store, no bundle, no prohibition list — allow. Deliberately silent here,
  // unlike user-prompt-submit's once-per-session store warning: a model switch
  // is not the moment to explain store health, and that hook already says it.
  const gateway = openGatewayOrNull(config);
  if (gateway === null) return;

  let prohibited: readonly string[] | undefined;
  try {
    prohibited = (await gateway.getPolicyBundle()).prohibitedModels;
  } finally {
    await gateway.close();
  }

  const decision = decidePreModelSwitch(toModel, prohibited);
  if (decision !== null) {
    await emit(decision);
    return;
  }

  // ALLOWED — so this is the authoritative moment the session's model becomes
  // `to_model`, and recording it here is what lets user-prompt-submit decide
  // without re-reading the transcript. Recorded only on the allow path: a
  // refused switch never happened, and storing its target would make the next
  // turn enforce against a model the session is not running.
  recordSessionModel(config.dataDir, sessionId, toModel);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
