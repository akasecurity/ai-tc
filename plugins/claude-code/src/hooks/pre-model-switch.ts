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
import { loadConfig } from '@akasecurity/plugin-sdk';

import { runPreModelSwitch } from './model-switch-run.ts';
import { emit, getString, parseJson, readStdin } from './shared.ts';
import { openGatewayOrNull, warnIfStoreRedirected } from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (input === null) return;
  const toModel = getString(input, 'to_model');
  if (toModel === undefined || toModel === '') return;
  const config = loadConfig();
  await runPreModelSwitch(input, toModel, getString(input, 'session_id'), {
    config,
    openGateway: () => openGatewayOrNull(config),
    emit,
    warnIfStoreRedirected,
  });
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
