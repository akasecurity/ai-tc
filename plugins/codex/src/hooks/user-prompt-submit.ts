/**
 * UserPromptSubmit — fires after the user submits a prompt, before the model
 * sees it. Same event name and stdin shape as Claude Code's UserPromptSubmit hook.
 *
 * stdin:  { prompt, session_id, cwd, hook_event_name, ... }
 * stdout (exit 0):
 *   {"decision":"block","reason":"..."}  → this prompt is rejected, reason
 *     shown, the SESSION continues (the user can resubmit) — confirmed
 *     against UserPromptSubmitCommandOutputWire in openai/codex's
 *     codex-rs/hooks/src/schema.rs. `continue:false` (the universal
 *     HookUniversalOutputWire field every hook output shares) is a DIFFERENT,
 *     stronger signal that stops the whole turn — using it here would kill
 *     the session over one flagged prompt instead of just rejecting it.
 *   {"systemMessage":"..."}              → warning shown, prompt continues
 *   no output                            → allow
 *
 * Codex cannot rewrite prompt text on this event either, so a `redact` decision
 * BLOCKS here, same as Claude Code — warning and passing the prompt through
 * would send the raw secret to the model. True in-place redaction happens in
 * pre-tool-use via updatedInput.
 *
 * It is also where a session running on a PROHIBITED model is refused. Codex
 * exposes no model-switch event, so unlike Claude Code there is no point at
 * which the switch itself can be denied — this is the only seam, and it acts a
 * turn later than the switch it is reacting to. It blocks no LLM API call
 * either; what it enforces is that a governed session does not keep running on
 * a prohibited model.
 *
 * This is also the first-run nudge point: on a clean prompt from a machine that
 * hasn't completed setup, surface a one-line pointer to it. And it is the
 * store-health surface: when the local store cannot open (so nothing is
 * scanned or recorded), say so once per session instead of silently looking
 * protected.
 * Fail-open: any error → no output, exit 0.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import {
  claimOnboardingNudge,
  createPluginRuntime,
  decideProhibitedModelTurn,
  loadConfig,
  uniqueRuleIds,
} from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import { resolveCodexSessionModel } from './model-guard.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const prompt = input ? getString(input, 'prompt') : undefined;
  if (prompt === undefined || prompt === '') return;

  const config = loadConfig();
  const sessionId = input ? getString(input, 'session_id') : undefined;
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
  const metadata = input ? baseMetadata(input) : undefined;

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
    return;
  }
  // PROHIBITED-MODEL CONTAINMENT, ahead of the scan on purpose. It is the
  // cheaper verdict (two small local reads against a detection pass over the
  // whole prompt) and the stronger one: if this turn cannot run at all, what the
  // prompt contains no longer changes the outcome. Running it first also means a
  // throw inside the scan path cannot skip it.
  //
  // Wrapped fail-open throughout. A bundle that will not load, or a model that
  // cannot be resolved, leaves `blocked` null and the turn proceeds to the
  // ordinary detection path.
  const blocked = await (async (): Promise<{ decision: 'block'; reason: string } | null> => {
    try {
      const { prohibitedModels } = await gateway.getPolicyBundle();
      // Bundle FIRST: with no prohibition list there is nothing to enforce, and
      // resolving the model would be a transcript read spent to reach the same
      // allow.
      if (prohibitedModels === undefined || prohibitedModels.length === 0) return null;
      const model = resolveCodexSessionModel(
        config.dataDir,
        sessionId,
        input === null ? undefined : getString(input, 'transcript_path'),
      );
      return decideProhibitedModelTurn(model, prohibitedModels);
    } catch {
      return null;
    }
  })();
  if (blocked !== null) {
    // Closed here rather than left to the runtime's `finally` below, which this
    // return never reaches.
    await gateway.close();
    await emit(blocked);
    return;
  }

  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  let result: CaptureResult;
  try {
    result = await runtime.capture({
      kind: 'prompt',
      sourceTool: SOURCE_TOOL.Codex,
      text: prompt,
      metadata,
    });
  } finally {
    await runtime.close();
  }

  if (result.action === 'block' || result.action === 'redact') {
    // A redact policy blocks here too: this surface has no prompt-rewrite
    // channel, so the only way to honor "the raw value must not reach the
    // model" is to stop the prompt with removal-based guidance.
    await emit({
      decision: 'block',
      reason: blockMessage({
        subject: 'prompt',
        ruleIds: uniqueRuleIds(result.findings),
        blockedRef: result.blockedReferences?.[0],
      }),
    });
    return;
  }
  if (result.action === 'warn') {
    // A warn never escalates: the prompt continues, flagged. A warned value is
    // ledgered like a blocked one, so when a reference exists the message
    // points at the same out-of-band approve flow.
    await emit({
      systemMessage: `AKA flagged sensitive content (${uniqueRuleIds(result.findings)}) — sent unchanged.${exceptionPointer(result.blockedReferences)}`,
    });
    return;
  }

  if (!config.onboarded && claimOnboardingNudge(config.dataDir, sessionId)) {
    await emit({
      systemMessage:
        'AKA is active and monitoring your prompts (log-only by default — nothing is blocked or redacted yet). Run the aka-setup skill to choose your installation type and set enforcement (warn/redact/block) per detection.',
    });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
