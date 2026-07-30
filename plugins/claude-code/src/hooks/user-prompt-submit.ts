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
 * in-place redaction happens in pre-tool-use via updatedInput.
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
  uniqueRuleIds,
} from '@akasecurity/plugin-sdk';
import { isVaultConsentValid } from '@akasecurity/schema';

import { blockMessage, exceptionPointer } from '../exception-guidance.ts';
import { writeClipboard } from './clipboard.ts';
import { ONBOARDING_NUDGE } from './onboarding-nudge.ts';
import { resubmitMessage } from './resubmit-message.ts';
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

  if (result.action === 'block' || result.action === 'redact') {
    // A redact policy blocks here too: this surface has no prompt-rewrite
    // channel, so the only way to honor "the raw value must not reach the
    // model" is to stop the prompt. Removal-based guidance first; with a valid
    // vault-consent grant the reason upgrades to the resubmit message carrying
    // a pointerized rewrite of the prompt (and the clipboard gets the same
    // rewrite, best-effort). Consent absent → the vault is never touched.
    const ruleIds = uniqueRuleIds(result.findings);
    const blockedRef = result.blockedReferences?.[0];
    let reason = blockMessage({ subject: 'prompt', ruleIds, blockedRef });
    if (isVaultConsentValid(config.settings.vaultConsent)) {
      const rewrite = await pointerizedRewrite(prompt, result.findings);
      if (rewrite !== null) {
        // Only the pointerized text ever reaches the clipboard — never the raw
        // prompt.
        const clipboardWrote = writeClipboard(rewrite);
        reason = resubmitMessage({ ruleIds, rewrite, clipboardWrote, blockedRef });
      }
    }
    await emit({ decision: 'block', reason });
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

  // Not enforced this prompt (action was monitor/log or allow — possibly WITH
  // findings). If the user hasn't onboarded, nudge them: detections monitor
  // (log-only) by DEFAULT, so nothing is blocked or redacted until they assign a
  // stronger action to a detection. Gate it to once per session so a busy
  // pre-onboarding session isn't spammed every prompt.
  if (!config.onboarded && claimOnboardingNudge(config.dataDir, sessionId)) {
    await emit({ systemMessage: ONBOARDING_NUDGE });
  }
}

// The pointerized rewrite offered in the block reason, or null when it cannot
// be offered safely. Every DETECTED span is pointerized (not only the enforced
// ones) — the whole prompt is blocked regardless, so vaulting more never leaks
// more. Null on any fault, on a rewrite that minted no pointer, or — the
// never-leak gate — when any finding's raw match still appears in the
// rewritten text; the caller then falls back to the removal-based message.
async function pointerizedRewrite(
  prompt: string,
  findings: CaptureResult['findings'],
): Promise<string | null> {
  try {
    const tokenized = await createVaultGlue().tokenizeText(prompt, { findings });
    if (tokenized.pointers.length === 0) return null;
    for (const finding of findings) {
      if (finding.rawMatch !== '' && tokenized.text.includes(finding.rawMatch)) return null;
    }
    return tokenized.text;
  } catch {
    return null;
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
