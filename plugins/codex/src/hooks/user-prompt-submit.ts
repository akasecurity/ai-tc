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
  loadConfig,
  uniqueRuleIds,
} from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const prompt = input ? getString(input, 'prompt') : undefined;
  if (prompt === undefined || prompt === '') return;

  const config = loadConfig();
  const sessionId = input ? getString(input, 'session_id') : undefined;
  const metadata = input ? baseMetadata(input) : undefined;

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
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
