/**
 * userPromptSubmitted / userPromptTransformed (CLI) and UserPromptSubmit
 * (VS Code) — the prompt capture surface.
 *
 * ONE SCRIPT, THREE EVENT NAMES. Which one it was invoked for comes off argv
 * (`./event-name.ts`), never off the payload: `userPromptTransformed` carries
 * `prompt` as well as `transformedPrompt`, so a script that keyed on the fields
 * present would scan the untransformed text twice and never see the
 * scaffolding the host wrapped around it. See `./user-prompt-payload.ts`.
 *
 * argv:   [node, script, '<eventName>']
 * stdin:  CLI    { sessionId, timestamp, cwd, prompt, transformedPrompt? }
 *         VSCode { hook_event_name, session_id, cwd, prompt }
 * stdout (exit 0):
 *   {"systemMessage":"…"}  → a note; the prompt continues either way
 *   no output              → nothing flagged
 *
 * **THIS HOOK BLOCKS NOTHING, on either host.** Silence is the sibling shape
 * here rather than `runHookFailOpen`'s explicit allow, because `preToolUse` is
 * the one event the CLI reads a crash on as a deny. And even a clean run emits
 * no decision: no prompt-stop or prompt-rewrite channel has been observed on
 * either surface, so a `block` policy is reported as a flagged-and-recorded
 * prompt that went out unchanged rather than dressed up as enforcement. The
 * argument, and why the wording matters, is at `promptEmitPayload`.
 *
 * Fail-open: any error → no output, exit 0.
 */
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { claimOnboardingNudge, createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId } from './dialect.ts';
import { readEventName } from './event-name.ts';
import { baseMetadata, emit, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
  warnIfStoreRedirected,
} from './store-health.ts';
import { promptEmitPayload, promptPersist, readPromptCapture } from './user-prompt-payload.ts';

// Same reasoning as pre-tool-use.ts: a payload whose dialect cannot be told is
// read as the CLI's, the host where a wrong guess costs the most.
const DEFAULT_DIALECT = 'cli' as const;

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const capture = readPromptCapture(readEventName(), input);
  if (capture === undefined || input === null) return;

  const dialect = detectDialect(input) ?? DEFAULT_DIALECT;
  const sessionId = readSessionId(input, dialect);
  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);

  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    // Nothing is being scanned or recorded — say so once per session rather
    // than looking protected.
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
    return;
  }

  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });
  let result: CaptureResult;
  try {
    result = await runtime.capture(
      {
        kind: 'prompt',
        sourceTool: SOURCE_TOOL.Copilot,
        text: capture.text,
        metadata: baseMetadata(input, dialect),
      },
      { persist: promptPersist(capture.event) },
    );
  } finally {
    await runtime.close();
  }

  const payload = promptEmitPayload(capture.event, result);
  if (payload !== undefined) {
    await emit(payload);
    return;
  }

  // The first-run nudge rides a clean SUBMITTED prompt only: the transformed
  // event fires for the same turn milliseconds later, and claiming the nudge
  // there would spend it on a message nothing prints.
  if (
    capture.event === 'submitted' &&
    !config.onboarded &&
    claimOnboardingNudge(config.dataDir, sessionId)
  ) {
    await emit({
      systemMessage:
        'AKA is active and monitoring your prompts (log-only by default — nothing is blocked ' +
        'or redacted yet). Run the aka-setup skill to choose your installation type and set ' +
        'enforcement (warn/redact/block) per detection.',
    });
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
