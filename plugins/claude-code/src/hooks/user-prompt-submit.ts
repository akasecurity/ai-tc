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
 * It is also where a session already RUNNING on a prohibited model is contained:
 * PreModelSwitch refuses a switch onto one, but a session can start on a
 * prohibited model, or have one restored on resume, without any switch passing
 * through that hook. Neither point blocks an LLM API call — no hook fires around
 * the request — so what the two enforce together is that a governed session does
 * not RUN on a prohibited model.
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
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import { writeClipboard } from './clipboard.ts';
import { refuseProhibitedTurn } from './model-guard.ts';
import { ONBOARDING_NUDGE } from './onboarding-nudge.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
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
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
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
  // PROHIBITED-MODEL CONTAINMENT, ahead of the scan on purpose. It is the
  // cheaper verdict (two small local reads against a detection pass over the
  // whole prompt) and the stronger one: if this turn cannot run at all, what the
  // prompt contains no longer changes the outcome. Running it first also means a
  // throw inside the scan path cannot skip it. The decision itself is
  // `refuseProhibitedTurn`, which is importable and fail-open throughout.
  const blocked = await refuseProhibitedTurn(
    gateway,
    config.dataDir,
    sessionId,
    input === null ? undefined : getString(input, 'transcript_path'),
  );
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
      sourceTool: SOURCE_TOOL.ClaudeCode,
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
      ? (text, findings, reversible) =>
          createVaultGlue().tokenizeText(text, {
            findings,
            // Per-finding custody, exactly as the tool-call paths pass it.
            // Omitting it means "keep all", which would vault a value whose
            // detection chose one-way Redact.
            reversible,
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
