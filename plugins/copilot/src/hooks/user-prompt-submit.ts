/**
 * userPromptSubmitted (Copilot CLI, cloud coding agent) / UserPromptSubmit
 * (VS Code agent mode) — the prompt capture surface.
 *
 * ONE SCRIPT, THREE EVENT NAMES, ONE REGISTRATION. Which event it was invoked
 * for comes off argv (./event-name.ts), never off the payload:
 * `userPromptTransformed` carries `prompt` as well as `transformedPrompt`, so a
 * script that keyed on the fields present would scan the untransformed text
 * twice and never see the scaffolding the host wrapped around it. That event is
 * handled here and deliberately NOT registered in `hooks.json` — registering it
 * beside the submitted one records every prompt twice. See
 * ./user-prompt-payload.ts.
 *
 * argv[2]: the event token. argv[3] (optional): the plugin manifest path.
 * stdin:   CLI    { sessionId, timestamp, cwd, prompt, transformedPrompt? }
 *          VSCode { hook_event_name, session_id, cwd, prompt }
 * stdout (exit 0), CLI:     (nothing, ever — the notice goes to stderr)
 * stdout (exit 0), VS Code: {"systemMessage":"…"} → a note, or nothing
 *
 * **THIS HOOK BLOCKS NOTHING AND REWRITES NOTHING, on either host**, and the
 * capture says so: every `runtime.capture` here passes `rewritable: false`, so
 * a `redact` policy resolves to `settings.redactFallback` INSIDE the runtime —
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
 * `runHookFailOpen` is what guarantees the exit 0; see ./shared.ts for the
 * limit of that guarantee, which is everything that yields.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { claimOnboardingNudge, createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId } from './dialect.ts';
import { readEventName } from './event-name.ts';
import type { HookOutput } from './shared.ts';
import { baseMetadata, parseJson, readStdin, runHookFailOpen, writeNotice } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { promptDecision, promptPersist, readPromptCapture } from './user-prompt-payload.ts';

/**
 * The events this entry is registered for, across both dialects.
 *
 * `userPromptTransformed` is in the set but not in `hooks.json`: the set says
 * what this script can HANDLE, the manifest says what it is SPAWNED for, and
 * keeping the two separate is what makes wiring the transformed event later a
 * manifest-only change. A miswired manifest still declines here.
 */
const OWN_EVENTS: ReadonlySet<string> = new Set([
  'userPromptSubmitted',
  'userPromptTransformed',
  'UserPromptSubmit',
]);

// Same reasoning as pre-tool-use.ts: a payload whose dialect cannot be told is
// read as the CLI's, the host where a wrong guess costs the most.
const DEFAULT_DIALECT = 'cli' as const;

async function main(): Promise<HookOutput | undefined> {
  const event = readEventName();
  if (event !== undefined && !OWN_EVENTS.has(event)) return undefined;

  const input = parseJson(await readStdin());
  const capture = readPromptCapture(event, input);
  // The fast path: no event token this script owns, no payload, or an empty
  // prompt. Returning here exits before `loadConfig` and before the store
  // opens, so there is nothing to scan and nothing is said about it.
  if (capture === undefined || input === null) return undefined;

  const dialect = detectDialect(input) ?? DEFAULT_DIALECT;
  const sessionId = readSessionId(dialect, input);
  const config = loadConfig();
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

  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  let result: CaptureResult;
  try {
    result = await runtime.capture(
      {
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.Copilot,
        text: capture.text,
        metadata: baseMetadata(dialect, input),
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
  if (decision.notice !== undefined) writeNotice(decision.notice);
  if (decision.output !== null) return decision.output;

  // The first-run nudge rides a clean SUBMITTED prompt only: the transformed
  // event fires for the same turn milliseconds later, and claiming the nudge
  // there would spend it on a message nothing prints.
  if (
    capture.event === 'submitted' &&
    !config.onboarded &&
    claimOnboardingNudge(config.dataDir, sessionId)
  ) {
    const message =
      'AKA is active and monitoring your prompts (log-only by default — nothing is blocked ' +
      'or redacted yet). Run the aka-setup skill to choose your installation type and set ' +
      'enforcement (warn/redact/block) per detection.';
    if (dialect === 'vscode') return { systemMessage: message };
    writeNotice(message);
  }
  return undefined;
}

// No fail-open payload: a body that threw, declined or outran the watchdog has
// scanned nothing, and saying nothing is how a hook declines on both hosts.
await runHookFailOpen(main);
