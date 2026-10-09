/**
 * The helper the prompt.submit mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-tokenize.js`.
 *
 * The vault key must never enter the mod, and the mod has no store. So when the
 * mod finds values its policy says to redact, it hands the prompt here. This
 * process does what the UserPromptSubmit hook would do with it, in the same
 * order and through the same code: it captures the prompt (scan, policy,
 * exceptions, one event, N findings, all in today's shape), then rewrites each
 * value the policy said to redact. With a valid vault consent that is a vault
 * pointer for a value whose detection keeps it and `[REDACTED:<CATEGORY>]` for
 * one it destroys; without consent every value is the one-way marker.
 *
 * stdin:  {"v":1,"text":"<prompt>","sessionId":"...","cwd":"..."}
 * stdout: {"v":1,"text":"<rewritten prompt>","note":"<model note>"|null}
 * Exit 1 with nothing on stdout means "no rewrite": the mod then lets the
 * prompt through unchanged and the command hook decides it as it always did.
 *
 * The raw value never leaves this process except inside the vault. Nothing is
 * written to stderr.
 */
import { redact } from '@akasecurity/detections';
import type { CaptureResult } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, SOURCE_TOOL } from '@akasecurity/schema';

import {
  baseMetadata,
  captureScopeKey,
  countFailOpen,
  getString,
  parseJson,
  readStdin,
} from '../hooks/shared.ts';
import { openGateway } from '../hooks/store-health.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote } from '../protocol/notes.ts';
import { recordModHandoff } from './handoff.ts';

type Finding = CaptureResult['findings'][number];

// `[[aka:<category>:...]]` -> the category segment. Callers pass only tokens the
// vault minted, so a token that does not split is not one worth reporting.
function categoryOf(token: string): string {
  return token.split(':')[1] ?? 'secret';
}

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  const text = input === null ? undefined : getString(input, 'text');
  if (input?.v !== 1 || text === undefined || text === '') process.exit(1);

  const sessionId = getString(input, 'sessionId');
  const hookInput: Record<string, unknown> = {
    session_id: sessionId,
    cwd: getString(input, 'cwd'),
  };
  const config = loadConfig();
  const opened = openGateway(config);
  if (opened.gateway === null) process.exit(1);

  // The capture the UserPromptSubmit hook makes, with its arguments.
  const runtime = createPluginRuntime(opened.gateway, config.settings, { dataDir: config.dataDir });
  let result: CaptureResult;
  try {
    result = await runtime.capture({
      kind: 'prompt',
      sourceTool: SOURCE_TOOL.ClaudeCode,
      text,
      metadata: baseMetadata(hookInput),
      scopeKey: captureScopeKey(hookInput),
    });
  } finally {
    await runtime.close();
  }

  // Only a redact verdict is a rewrite. A block, or a policy that changed since
  // the mod's snapshot, is the command hook's to decide on the raw prompt.
  if (result.action !== 'redact') process.exit(1);
  const enforced: Finding[] = result.enforcedFindings ?? result.findings;
  if (enforced.length === 0) process.exit(1);

  let rewritten: string;
  let note: string | null = null;
  if (isVaultConsentValid(config.settings.vaultConsent)) {
    const tokenized = await createVaultGlue().tokenizeText(text, {
      findings: enforced,
      reversible: new Set(result.reversibleFindings ?? []),
      sighting: { location: 'prompt', kind: 'prompt' },
    });
    rewritten = tokenized.text;
    note = eventNote({
      marker: sessionProtocolMarker(config.dataDir, sessionId),
      surface: 'prompt',
      realized: {
        pointers: tokenized.pointers.map((token) => ({ token, category: categoryOf(token) })),
        degraded: tokenized.degraded,
      },
    });
  } else {
    rewritten = redact(text, enforced);
  }
  // The never-leak gate of the hook's pointerized rewrite: a value still in the
  // text means the rewrite is not one to hand the model.
  for (const finding of enforced) {
    if (finding.rawMatch !== '' && rewritten.includes(finding.rawMatch)) process.exit(1);
  }

  recordModHandoff(config.dataDir, rewritten);
  process.stdout.write(`${JSON.stringify({ v: 1, text: rewritten, note })}\n`);
}

try {
  await main();
} catch {
  // Exit 1 and no output: the mod passes the prompt on unchanged.
  countFailOpen();
  process.exit(1);
}
process.exit(0);
