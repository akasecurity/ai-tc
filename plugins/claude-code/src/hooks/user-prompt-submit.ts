/**
 * UserPromptSubmit — fires after the user submits a prompt, before the model
 * sees it.
 *
 * stdin:  { prompt, session_id, cwd, hook_event_name, ... }
 * stdout (exit 0):
 *   {"decision":"block","reason":"..."}  → prompt is blocked, reason shown
 *   {"systemMessage":"..."}              → warning shown, prompt continues
 *   no output                            → allow
 *
 * Claude Code cannot rewrite prompt text, so a `redact` decision degrades to a
 * warning here; true redaction happens in pre-tool-use via updatedInput.
 *
 * This is also the first-run nudge point: on a clean prompt from a machine that
 * hasn't completed `/aka:setup`, surface a one-line pointer to it (fail-open
 * defaults are already in effect, so the nudge is informational, not blocking).
 * And it is the store-health surface: when the local store cannot open (so
 * nothing is scanned or recorded), say so once per session instead of silently
 * looking protected.
 * Fail-open: any error → no output, exit 0.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import {
  claimOnboardingNudge,
  createPluginRuntime,
  loadConfig,
  uniqueRuleIds,
} from '@akasecurity/plugin-sdk';

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

  // Load config here (rather than deferring to the runtime wiring) so the
  // adapter can also key the onboarding nudge off `onboarded`.
  const config = loadConfig();
  const sessionId = input ? getString(input, 'session_id') : undefined;
  const metadata = input ? baseMetadata(input) : undefined;

  // The gateway is opened HERE (not behind a catch-all) so a store-open
  // failure is observable: still allow — fail-open — but tell the user once
  // per session that nothing is being scanned, instead of staying silent (or
  // worse, nudging "AKA is active and monitoring" below).
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
      sourceTool: 'claude-code',
      text: prompt,
      metadata,
    });
  } finally {
    await runtime.close();
  }

  if (result.action === 'block') {
    // Removal first; then the copy-paste-complete exception command built from
    // the ledger reference the runtime just recorded (see exception-guidance).
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
  if (result.action === 'redact' || result.action === 'warn') {
    // A redacted value is ledgered like a blocked one, so when a reference
    // exists the message points at the same out-of-band approve flow.
    await emit({
      systemMessage: `AKA flagged sensitive content (${uniqueRuleIds(result.findings)}). Prompts cannot be redacted in place — sent unchanged.${exceptionPointer(result.blockedReferences)}`,
    });
    return;
  }

  // Not enforced this prompt (action was monitor/log or allow — possibly WITH
  // findings). If the user hasn't onboarded, nudge them: detections monitor
  // (log-only) by DEFAULT, so nothing is blocked or redacted until they assign a
  // stronger action to a detection. Gate it to once per session so a busy
  // pre-onboarding session isn't spammed every prompt.
  if (!config.onboarded && claimOnboardingNudge(config.dataDir, sessionId)) {
    await emit({
      systemMessage:
        'AKA is active and monitoring your prompts (log-only by default — nothing is blocked or redacted yet). Run /aka:setup to choose your installation type and set enforcement (warn/redact/block) per detection.',
    });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
