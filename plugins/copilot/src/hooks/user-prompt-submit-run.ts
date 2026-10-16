/**
 * userPromptSubmitted (Copilot CLI, cloud coding agent) / UserPromptSubmit
 * (VS Code agent mode) — the prompt capture surface.
 *
 * ONE HANDLER, THREE EVENT NAMES, ONE REGISTRATION. Which event it was invoked
 * for is the token argv carried (./event-name.ts), never the payload:
 * `userPromptTransformed` carries `prompt` as well as `transformedPrompt`, so a
 * handler that keyed on the fields present would scan the untransformed text
 * twice and never see the scaffolding the host wrapped around it. That event is
 * handled here and deliberately NOT registered in `hooks.json` — registering it
 * beside the submitted one records every prompt twice. See
 * ./user-prompt-payload.ts.
 *
 * event:   the token argv carried.
 * stdin:   CLI    { sessionId, timestamp, cwd, prompt, transformedPrompt? }
 *          VSCode { hook_event_name, session_id, cwd, prompt }
 * output, CLI:     undefined, always — every notice goes to stderr
 * output, VS Code: { systemMessage } → a note, or undefined
 *
 * **THIS HOOK BLOCKS NOTHING AND REWRITES NOTHING, on either host**, and the
 * capture says so: `runtime.capture` here passes `rewritable: false`, so a
 * `redact` policy resolves to `settings.redactFallback` INSIDE the runtime —
 * where the emitted message, the recorded `findings.actionTaken` and the ledger
 * read one answer. The hook never escalates for itself.
 *
 * Neither host has a prompt-stop channel this repository has observed: the
 * CLI's `modifiedPrompt` is listed under "Not measured" in
 * `test/fixtures/cli/README.md`, and VS Code's block channel is exit 2, which
 * ./shared.ts guarantees no path here reaches. So a `block` policy is reported
 * as a flagged-and-recorded prompt that went out unchanged rather than dressed
 * up as enforcement. The argument, and why the wording matters, is at
 * `promptDecision`.
 *
 * A PROMPT TOO LARGE TO SCAN IN TIME IS NOT REFUSED. The runtime is built with
 * the large-input bound, so a prompt at or above the threshold is scanned in a
 * worker under the hook's deadline, and one whose scan does not finish comes
 * back with `scanIncomplete` set and no findings. With no channel to stop the
 * prompt, refusing it is not available — but reading the empty findings as
 * clean would tell the user nothing about a prompt nobody checked. So it is
 * reported as unscanned (`promptDecision`), and the runtime records the row
 * with no content and the refusal stamped on it.
 *
 * This module is the handler and nothing else: it reads neither argv's event
 * token nor stdin, and never exits. `./user-prompt-submit.ts` is the entry that
 * feeds it, and `runHookFailOpen` there is what guarantees the exit 0.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { claimOnboardingNudge, createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId } from './dialect.ts';
import type { HookEvent } from './event-name.ts';
import { HOOK_SCAN_DEADLINE_MS, largeInputBound } from './large-input.ts';
import type { HookHandler } from './shared.ts';
import { baseMetadata, captureScopeKey, parseJson, writeNotice } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { promptDecision, promptPersist, readPromptCapture } from './user-prompt-payload.ts';

/**
 * The events this handler is registered for, across both dialects.
 *
 * `userPromptTransformed` is in the set but not in `hooks.json`: the set says
 * what this handler can HANDLE, the manifest says what it is SPAWNED for, and
 * keeping the two separate is what makes wiring the transformed event later a
 * manifest-only change. A miswired manifest still declines here.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set<HookEvent>([
  'userPromptSubmitted',
  'userPromptTransformed',
  'UserPromptSubmit',
]);

function isOwnEvent(event: string): event is HookEvent {
  return OWN_EVENTS.has(event);
}

const ONBOARDING_NUDGE =
  'AKA is active and monitoring your prompts (log-only by default — nothing is blocked ' +
  'or redacted yet). Run the aka-setup skill to choose your installation type and set ' +
  'enforcement (warn/redact/block) per detection.';

/**
 * The prompt handler. `options.akaHome` points the store and settings at
 * another home and `options.scanWorkerUrl` the bounded scan at another worker;
 * the entry passes neither.
 */
export const runUserPromptSubmit: HookHandler = async (event, stdin, options = {}) => {
  if (event !== undefined && !isOwnEvent(event)) return undefined;

  const input = parseJson(stdin);
  const capture = readPromptCapture(event, input);
  // The fast path: no payload, or an empty prompt. Returning here exits before
  // `loadConfig` and before the store opens, so there is nothing to scan and
  // nothing is said about it.
  if (capture === undefined || input === null) return undefined;

  // A payload whose dialect cannot be told is declined, as preToolUse and
  // postToolUse decline one: a guess would choose the message channel and the
  // session-id spelling for a payload that carries neither dialect's marker.
  const dialect = detectDialect(input);
  if (dialect === undefined) return undefined;
  const sessionId = readSessionId(dialect, input);
  const config = loadConfig(options.akaHome);
  // A symlinked store path redirects the corpus without failing anything; say
  // so once per session on stderr, so this hook's stdout contract is untouched.
  warnIfStoreRedirected(config, sessionId);

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // Nothing is being scanned or recorded — say so once per session rather
    // than looking protected. On the CLI that has to be stderr: `systemMessage`
    // is not an output field there, so the same object on stdout would be
    // dropped and the user told nothing at all.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      const message = storeUnavailableMessage(config.dbPath);
      if (dialect === 'vscode') return { systemMessage: message };
      writeNotice(message);
    }
    return undefined;
  }

  // A prompt at or above the large-input threshold is scanned in a worker
  // under the hook's deadline (see large-input.ts); one that does not finish
  // comes back as `scanIncomplete`, which `promptDecision` reports as unscanned.
  const runtime = createPluginRuntime(gateway, config.settings, {
    dataDir: config.dataDir,
    largeInput: largeInputBound(HOOK_SCAN_DEADLINE_MS, false),
    ...(options.scanWorkerUrl === undefined
      ? {}
      : { scanIsolation: { workerUrl: options.scanWorkerUrl } }),
  });
  let result: CaptureResult;
  try {
    result = await runtime.capture(
      {
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.Copilot,
        text: capture.text,
        metadata: baseMetadata(dialect, input),
        // Keyed by the cwd the payload carries and by nothing else; see
        // captureScopeKey.
        scopeKey: captureScopeKey(dialect, input),
      },
      {
        persist: promptPersist(capture.event),
        // There is no prompt-rewrite channel on either host that this
        // repository has confirmed, so a redact cannot be carried out — the
        // runtime resolves it to the configured fallback rather than this hook
        // reporting a masking that never happened.
        rewritable: false,
      },
    );
  } finally {
    await runtime.close();
  }

  const decision = promptDecision(capture.event, dialect, result);
  // Set only on a dialect whose stdout has no field to carry it, so this never
  // competes with the payload below for the single JSON object stdout takes.
  if (decision.notice !== undefined) {
    writeNotice(decision.notice);
    return undefined;
  }
  if (decision.output !== null) return decision.output;

  // The first-run nudge rides a SUBMITTED prompt the hook said nothing else
  // about: the transformed event fires for the same turn milliseconds later,
  // and claiming the nudge there would spend it on a message nothing prints.
  if (
    capture.event === 'submitted' &&
    !config.onboarded &&
    claimOnboardingNudge(config.dataDir, sessionId)
  ) {
    if (dialect === 'vscode') return { systemMessage: ONBOARDING_NUDGE };
    writeNotice(ONBOARDING_NUDGE);
  }
  return undefined;
};
