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
 * Claude Code cannot rewrite prompt text, so a `redact` decision BLOCKS here —
 * warning and passing the prompt through would send the raw secret to the
 * model. With a valid vault-consent grant the block reason carries a
 * pointerized rewrite of the prompt (each secret replaced by a vault pointer)
 * for the user to paste and resubmit, copied to the clipboard best-effort;
 * without consent the reason is the plain removal-based block message. True
 * in-place redaction happens in pre-tool-use via updatedInput. That collapse
 * lives in user-prompt-submit-decision.ts, which is importable and unit-tested;
 * this file is the I/O around it.
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
  createVaultGlue,
  loadConfig,
} from '@akasecurity/plugin-sdk';
import { isVaultConsentValid } from '@akasecurity/schema';

import { writeClipboard } from './clipboard.ts';
import { ONBOARDING_NUDGE } from './onboarding-nudge.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from './store-health.ts';
import { decideUserPromptSubmit } from './user-prompt-submit-decision.ts';

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

  // Consent is resolved HERE rather than inside the decision: an absent
  // tokenizer is what makes "no consent → the vault is never touched" a
  // structural property instead of a flag the decision could forget to read.
  const decision = await decideUserPromptSubmit(prompt, result, {
    tokenizePrompt: isVaultConsentValid(config.settings.vaultConsent)
      ? (text, findings) =>
          createVaultGlue().tokenizeText(text, {
            findings,
            sighting: { location: 'prompt', kind: 'prompt' },
          })
      : undefined,
    writeClipboard,
  });
  if (decision !== null) {
    await emit(decision);
    return;
  }

  // Not enforced this prompt (action was monitor/log or allow — possibly WITH
  // findings). If the user hasn't onboarded, nudge them: detections monitor
  // (log-only) by DEFAULT, so nothing is blocked or redacted until they assign a
  // stronger action to a detection. Gate it to once per session so a busy
  // pre-onboarding session isn't spammed every prompt.
  if (!config.onboarded && claimOnboardingNudge(config.dataDir, sessionId)) {
    await emit({ systemMessage: ONBOARDING_NUDGE });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
