/**
 * postToolUse (CLI, cloud) / PostToolUse (VS Code) — fires after a tool call
 * returns, with the result the model is about to see.
 *
 * argv:   [node, script, '<eventName>']
 * stdin:  CLI    { sessionId, cwd, toolName, toolArgs, toolResult }
 *         VSCode { hook_event_name, session_id, tool_name, tool_input,
 *                  tool_response }
 * stdout (exit 0):
 *   {"modifiedResult":{…}}                          → CLI: result replaced
 *   {"decision":"block","additionalContext":"…"}     → VS Code: result withheld
 *   {"systemMessage":"…"}                            → a note; result passes
 *   no output                                        → nothing flagged
 *
 * Silence is the shape here, not `runHookFailOpen`'s explicit allow: the CLI
 * denies on a crash for `preToolUse` alone, and every other event on both hosts
 * fails open. Fail-open: any error → no output, exit 0.
 *
 * **`toolResult.resultType` IS NOT AN EXIT STATUS** and nothing on this path
 * reads it. See `./tool-response.ts` for the recorded proof.
 *
 * ONE NOTE THIS HOOK CANNOT PRINT: on the CLI a rewrite rides `modifiedResult`,
 * which is a single-key output with no channel to carry a `systemMessage`
 * beside it. So a CLI redaction is silent to the USER — what explains it is the
 * withhold notice the MODEL receives, and only on the withhold path. Same
 * limitation `modifiedArgs` has on `preToolUse`; it belongs in `SKILL.md`'s
 * Known limitations rather than being worked around with a second write, which
 * would be two concatenated objects and therefore invalid JSON.
 */
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { createPluginRuntime, loadConfig } from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import { detectDialect, readSessionId, readToolCall } from './dialect.ts';
import { responseEmitPayload, scanResponseFields } from './scan-response.ts';
import { baseMetadata, emit, parseJson, readStdin } from './shared.ts';
import { warnIfStoreRedirected } from './store-health.ts';
import { responseKey, scannableResponseFields } from './tool-response.ts';

// Same reasoning as pre-tool-use.ts: an untellable dialect is read as the CLI's.
const DEFAULT_DIALECT = 'cli' as const;

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  const dialect = detectDialect(input) ?? DEFAULT_DIALECT;
  const call = readToolCall(input, dialect);
  const response = input[responseKey(dialect)];
  const fields = scannableResponseFields(dialect, response);
  if (fields.length === 0) return;

  // The RAW name only — an absent tool name must not be recorded as the
  // literal display fallback.
  const toolName = call?.name ?? 'tool';
  const metadata = baseMetadata(input, dialect) ?? {};
  if (call) metadata.toolName = call.name;

  const config = loadConfig();
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, readSessionId(input, dialect));
  const gateway = resolveDataGateway(config);
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  let outcome;
  try {
    outcome = await scanResponseFields(toolName, fields, (text) =>
      runtime.capture(
        { kind: 'response', sourceTool: SOURCE_TOOL.Copilot, text, metadata },
        // A response is text the host produced, recorded to trail the
        // enforcement decisions rather than as a corpus of its own: 'always'
        // would copy every command's whole output into the store.
        { persist: 'with-findings' },
      ),
    );
  } finally {
    await runtime.close();
  }

  const payload = responseEmitPayload(dialect, outcome, response);
  if (payload !== undefined) await emit(payload);
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
