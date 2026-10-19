/**
 * UserPromptSubmit — fires after the user submits a prompt, before the model
 * sees it.
 *
 * stdin:  { prompt, session_id, cwd, hook_event_name, ... }
 * stdout (exit 0):
 *   {"decision":"block","reason":"..."}  → prompt is blocked, reason shown
 *     (also for a prompt too large to scan within the time limit)
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
 * the request — so what the two enforce together is that a session does not RUN
 * on a prohibited model where the organization's model policy governs it:
 * everywhere on a machine-wide attachment, and in enrolled repositories on
 * a scoped one, keyed from the directory each turn runs in. In a session signed
 * in to a recognised work subscription the turn is keyed by the session's own
 * key, so the policy governs it in any folder; the first prompt of a new
 * session is keyed by its directory alone. A turn the policy does not govern is
 * scanned like any other.
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

import { actionFromCapture, pointersByFinding, recordModFindings } from '../mod/findings-log.ts';
import { consumeModHandoff } from '../mod/handoff.ts';
import { resolveHookAccount, stampFor } from './account-stamp.ts';
import { writeClipboard } from './clipboard.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from './large-input.ts';
import { handleProhibitedTurn } from './model-guard.ts';
import { ONBOARDING_NUDGE } from './onboarding-nudge.ts';
import {
  baseMetadata,
  captureScopeKey,
  countFailOpen,
  emit,
  getString,
  parseJson,
  readStdin,
} from './shared.ts';
import { captureDeferredStamped } from './stamped-capture.ts';
import {
  claimStoreUnavailableWarning,
  openGateway,
  storeDegradedMessage,
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
  // The scope key rides BESIDE the metadata, never inside it: EventMetadata is a
  // published wire shape, and the key is a local attribute only the local writer
  // stores. A prompt names no file, so this is the cwd key, and free: baseMetadata
  // has just walked this directory and the resolver is memoised per directory.
  // The capture is stamped with it for the session's account (stampFor).
  const scopeKey = input ? captureScopeKey(input) : undefined;

  // The gateway is opened HERE (not behind a catch-all) so a store-open
  // failure is observable: still allow — fail-open — but tell the user once
  // per session that nothing is being scanned, instead of staying silent (or
  // worse, nudging "AKA is active and monitoring" below).
  const opened = openGateway(config);
  if (opened.gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeDegradedMessage(config.dbPath, opened.error) });
    }
    return;
  }
  const gateway = opened.gateway;
  // The session's account, checked once for this turn: its refusal and its
  // capture are both stamped from it.
  const account = resolveHookAccount(gateway, {
    dataDir: config.dataDir,
    sessionId,
    transcriptPath: input === null ? undefined : getString(input, 'transcript_path'),
    cwd: input === null ? undefined : getString(input, 'cwd'),
  });
  // PROHIBITED-MODEL CONTAINMENT, ahead of the scan on purpose. It is the
  // cheaper verdict (two small local reads against a detection pass over the
  // whole prompt) and the stronger one: if this turn cannot run at all, what the
  // prompt contains no longer changes the outcome. Running it first also means a
  // throw inside the scan path cannot skip it. The decision itself is
  // `refuseProhibitedTurn`, which is importable and fail-open throughout.
  if (
    await handleProhibitedTurn(
      gateway,
      config.dataDir,
      sessionId,
      input === null ? undefined : getString(input, 'transcript_path'),
      input === null ? undefined : getString(input, 'cwd'),
      emit,
    )
  ) {
    return;
  }

  // A prompt the mod's helper already rewrote and recorded (its event and
  // findings are in the store; this hook is seeing pointers or markers): record
  // nothing, or one prompt would appear in Activity twice. Only the RECORDING is
  // skipped. The prompt this hook is handed is still scanned and decided, as a
  // second check on what the mod produced: the rewrite is normally clean and
  // decides to nothing, but a value the mod left (a warn-level one beside a redacted
  // one, which keeps its warning) or a note planted for a raw prompt is judged
  // here exactly as a prompt with no mod would be.
  const handedOff = consumeModHandoff(config.dataDir, prompt);
  // A prompt at or above the large-input threshold is scanned under a deadline
  // and refused if that scan does not finish (see large-input.ts).
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS),
  });
  let result: CaptureResult;
  try {
    const decided = await captureDeferredStamped(
      runtime,
      { kind: 'prompt', sourceTool: SOURCE_TOOL.ClaudeCode, text: prompt, metadata },
      stampFor(gateway, account, scopeKey),
    );
    if (!handedOff) await decided.record();
    result = decided.result;
  } finally {
    await runtime.close();
  }

  // Consent is resolved HERE rather than inside the decision: an absent
  // tokenizer is what makes "no consent → the vault is never touched" a
  // structural property instead of a flag the decision could forget to read.
  let vaultedWith: ReadonlyMap<string, string> = new Map();
  const decision = await decideUserPromptSubmit(prompt, result, {
    tokenizePrompt: isVaultConsentValid(config.settings.vaultConsent)
      ? async (text, findings, reversible) => {
          const tokenized = await createVaultGlue().tokenizeText(text, {
            findings,
            // Per-finding custody, exactly as the tool-call paths pass it.
            // Omitting it means "keep all", which would vault a value whose
            // detection chose one-way Redact.
            reversible,
            sighting: { location: 'prompt', kind: 'prompt' },
          });
          try {
            vaultedWith = pointersByFinding(findings, reversible, tokenized.pointers);
          } catch {
            // A record of the pointers never changes the rewrite.
          }
          return tokenized;
        }
      : undefined,
    writeClipboard,
  });
  // The widgets' record of what was found, unless the mod's helper already wrote
  // it. Nothing here may reach the decision, so a fault in any of it is dropped.
  if (!handedOff && sessionId !== undefined) {
    try {
      // All or nothing: the block reason carries one rewrite of the whole prompt,
      // so one pointer in it shows the user was handed every pointer minted.
      const first = vaultedWith.values().next();
      const vaulted =
        first.done !== true &&
        decision !== null &&
        'reason' in decision &&
        decision.reason.includes(first.value);
      recordModFindings(config.dataDir, sessionId, {
        sessionId,
        kind: 'prompt',
        text: prompt,
        result,
        where: 'prompt',
        action: actionFromCapture(result.action, vaulted),
        pointers: vaultedWith,
      });
    } catch {
      // A record the widgets cannot show is not a reason to change the verdict.
    }
  }
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
  // Fail-open: never break the user's session — but count the exit, so
  // `aka status` can say the hooks have been failing open on this machine.
  countFailOpen();
}
process.exit(0);
