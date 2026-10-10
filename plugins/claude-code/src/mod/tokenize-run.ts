/**
 * The helper the prompt.submit mod runs through `$.process.run`:
 * `node <plugin root>/scripts/mod-tokenize.js`.
 *
 * The vault key must never enter the mod, and the mod has no store. So when the
 * mod finds values its policy says to redact, it hands the prompt here. This
 * process does what the UserPromptSubmit hook would do with it, in the same
 * order and through the same code: it scans the prompt and decides it (policy,
 * exceptions), then rewrites each
 * value the policy said to redact. With a valid vault consent that is a vault
 * pointer for a value whose detection keeps it and `[REDACTED:<CATEGORY>]` for
 * one it destroys; without consent every value is the one-way marker.
 *
 * stdin:  {"v":1,"text":"<prompt>","sessionId":"...","cwd":"..."}
 *         or, for a conversation row the session.append backstop found a value
 *         in, {"v":1,"row":{"door":"attachment"},"text":"<block>",...}. A row is
 *         recorded as a `response` (only when it has findings, like PostToolUse),
 *         never as a prompt, leaves no prompt handoff, and carries no model note.
 * stdout: {"v":1,"text":"<rewritten prompt>","note":"<model note>"|null}
 * Exit 1 with nothing on stdout means "no rewrite": the mod then lets the
 * prompt through unchanged and the command hook decides it as it always did.
 *
 * The prompt's event and findings (all in today's shape) are recorded only when
 * a rewrite is returned, as the very last step before it is written: a helper
 * that declines, or is killed first by the mod's timeout, leaves nothing in the
 * store and the command hook records the prompt itself.
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
} from '../hooks/shared.ts';
import { openGateway } from '../hooks/store-health.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote } from '../protocol/notes.ts';
import { recordModHandoff } from './handoff.ts';
import type { HelperRun } from './helper-run.ts';

type Finding = CaptureResult['findings'][number];

// `[[aka:<category>:...]]` -> the category segment. Callers pass only tokens the
// vault minted, so a token that does not split is not one worth reporting.
function categoryOf(token: string): string {
  return token.split(':')[1] ?? 'secret';
}

async function tokenize(stdin: string): Promise<HelperRun> {
  const input = parseJson(stdin);
  const text = input === null ? undefined : getString(input, 'text');
  if (input?.v !== 1 || text === undefined || text === '') return { code: 1, stdout: '' };

  const sessionId = getString(input, 'sessionId');
  const rowInput = input.row;
  const rowDoor =
    typeof rowInput === 'object' && rowInput !== null
      ? getString(rowInput as Record<string, unknown>, 'door')
      : undefined;
  const isRow = rowInput !== undefined;
  if (isRow && rowDoor === undefined) return { code: 1, stdout: '' };
  const hookInput: Record<string, unknown> = {
    session_id: sessionId,
    cwd: getString(input, 'cwd'),
  };
  const config = loadConfig();
  const opened = openGateway(config);
  if (opened.gateway === null) return { code: 1, stdout: '' };

  // The capture the UserPromptSubmit hook makes, with its arguments, decided
  // first and recorded last. Nothing reaches the store until this process has a
  // rewrite to hand back: a verdict that is not a rewrite, a policy that changed
  // since the mod's snapshot, the never-leak gate, a fault, or the mod's timeout
  // killing this process all leave the store untouched, so the command hook,
  // which then decides the raw prompt itself, is the only one to record it.
  const runtime = createPluginRuntime(opened.gateway, config.settings, { dataDir: config.dataDir });
  let answer: { text: string; note: string | null } | null;
  try {
    const deferred = await runtime.captureDeferred(
      {
        kind: isRow ? 'response' : 'prompt',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        text,
        metadata: baseMetadata(hookInput),
        scopeKey: captureScopeKey(hookInput),
      },
      isRow ? { persist: 'with-findings' } : undefined,
    );
    const { result } = deferred;

    // Only a redact verdict is a rewrite. A block, or a policy that changed since
    // the mod's snapshot, is the command hook's to decide on the raw prompt.
    const enforced: Finding[] = result.enforcedFindings ?? result.findings;
    if (result.action !== 'redact' || enforced.length === 0) {
      answer = null;
    } else {
      let rewritten: string;
      let note: string | null = null;
      if (isVaultConsentValid(config.settings.vaultConsent)) {
        const tokenized = await createVaultGlue().tokenizeText(text, {
          findings: enforced,
          reversible: new Set(result.reversibleFindings ?? []),
          sighting: isRow
            ? { location: `${rowDoor ?? 'conversation'} row`, kind: 'transcript' }
            : { location: 'prompt', kind: 'prompt' },
        });
        rewritten = tokenized.text;
        note = isRow
          ? null
          : eventNote({
              marker: sessionProtocolMarker(config.dataDir, sessionId),
              surface: 'prompt',
              realized: {
                pointers: tokenized.pointers.map((token) => ({
                  token,
                  category: categoryOf(token),
                })),
                degraded: tokenized.degraded,
              },
            });
      } else {
        rewritten = redact(text, enforced);
      }
      // The never-leak gate of the hook's pointerized rewrite: a value still in
      // the text means the rewrite is not one to hand the model.
      const leaks = enforced.some(
        (finding) => finding.rawMatch !== '' && rewritten.includes(finding.rawMatch),
      );
      if (leaks) {
        answer = null;
      } else {
        // The last steps before answering: the prompt's event and findings, then
        // the note that tells the hook they exist. Both only for a rewrite that
        // is about to be returned.
        await deferred.record();
        if (!isRow) recordModHandoff(config.dataDir, rewritten);
        answer = { text: rewritten, note };
      }
    }
  } finally {
    await runtime.close();
  }
  if (answer === null) return { code: 1, stdout: '' };
  return { code: 0, stdout: `${JSON.stringify({ v: 1, text: answer.text, note: answer.note })}\n` };
}

/** The rewrite for one request on stdin. Never throws: a fault is exit 1 and silence. */
export async function runModTokenize(stdin: string): Promise<HelperRun> {
  try {
    return await tokenize(stdin);
  } catch {
    // Exit 1 and no output: the mod passes the prompt on unchanged.
    countFailOpen();
    return { code: 1, stdout: '' };
  }
}
