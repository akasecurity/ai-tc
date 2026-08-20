/**
 * PreToolUse — fires before a tool call executes. The one surface where true
 * redaction works: `updatedInput` replaces the tool's arguments — but only
 * for fields whose text is handed onward as data (Write/Edit/MultiEdit
 * content, the WebFetch and Task prompts). A redact decision on an executable
 * field (Bash `command`, WebFetch `url`, any MCP argument) escalates to deny
 * instead: masking inside it would silently change what runs. See
 * pre-tool-use-fields.ts for the per-tool field map and
 * pre-tool-use-decision.ts for the collapse rules.
 *
 * stdin:  { tool_name, tool_input, session_id, ... }
 * stdout (exit 0):
 *   {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",...}}
 *     → tool call blocked
 *   {"hookSpecificOutput":{...,"permissionDecision":"allow","updatedInput":{...}}}
 *     → tool runs with redacted input (Write/Edit only)
 *   no output → allow unchanged
 *
 * Fail-open: any error → no output, exit 0.
 */
import type { VaultGlue } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, pointerTokenScanner, SOURCE_TOOL } from '@akasecurity/schema';

import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote, userDisclosure } from '../protocol/notes.ts';
import { replaceAtPath, stringAtPath } from './paths.ts';
import type { PointerField } from './pointer-substitution.ts';
import {
  decideInputPointers,
  denyPointerMessage,
  denyUnresolvedPointerMessage,
} from './pointer-substitution.ts';
import type { PreToolUseOutput, ScannedField } from './pre-tool-use-decision.ts';
import { decidePreToolUse } from './pre-tool-use-decision.ts';
import { inputEventKind, inputFilePath, scannableInputFields } from './pre-tool-use-fields.ts';
import { baseMetadata, emit, getString, parseJson, readStdin } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGatewayOrNull,
  storeUnavailableMessage,
} from './store-health.ts';

async function main(): Promise<void> {
  const input = parseJson(await readStdin());
  if (!input) return;

  const toolName = getString(input, 'tool_name') ?? '';
  const rawToolInput = input.tool_input;
  if (typeof rawToolInput !== 'object' || rawToolInput === null) return;

  // Resolved before the store is opened: the matcher is broad enough to spawn
  // this hook for MCP tools whose payload carries no scannable text, and those
  // calls should cost nothing.
  const toolInput = rawToolInput as Record<string, unknown>;
  const fields = scannableInputFields(toolName, toolInput);
  if (fields.length === 0) return;

  const config = loadConfig();
  const sessionId = getString(input, 'session_id');
  // Vaulting (and everything narrated about it) is consent-gated; without the
  // grant this hook behaves exactly as it did before the vault existed.
  const consented = isVaultConsentValid(config.settings.vaultConsent);
  const vaultGlue = consented ? createVaultGlue() : null;

  // Model-echoed pointers are decided BEFORE the secret scan: an ungranted
  // pointer inside text that executes must deny outright, whatever the rest of
  // the payload holds. The check runs in every consent state — a stale pointer
  // from an earlier grant must not execute as literal text either. With no
  // glue (no consent) nothing touches the store: every pointer is simply
  // unresolved, which is exactly the deny/keep posture we need.
  const pointerFields: PointerField[] = [];
  for (const spec of fields) {
    const text = stringAtPath(toolInput, spec.path);
    if (text !== undefined && text !== '') {
      pointerFields.push({ path: spec.path, text, executable: spec.executable });
    }
  }
  // Executable fields are probed FIRST — grant resolution only, no
  // de-reference. One ungranted pointer denies the whole call, and a call that
  // is denied must never have audited a reveal for the pointers that WERE
  // granted: the owner's crossing trail would then report values as sent to
  // the model on a call that never ran.
  const spentGrantIds: string[] = [];
  let denyForPointer = false;
  if (vaultGlue) {
    for (const field of pointerFields.filter((f) => f.executable)) {
      const probe = await vaultGlue.probeModelPointers(field.text, {
        resolveGrant: vaultGlue.revealGrantResolver,
      });
      if (probe.ungranted.length > 0) denyForPointer = true;
    }
  } else {
    denyForPointer = pointerFields.some((f) => f.executable && pointerTokenScanner().test(f.text));
  }

  const pointerOutcomes = denyForPointer
    ? []
    : await decideInputPointers(pointerFields, async (text) => {
        if (!vaultGlue) {
          return {
            text,
            revealed: [],
            unresolved: [...text.matchAll(pointerTokenScanner())].map((m) => m[0]),
            grantIds: [],
          };
        }
        const result = await vaultGlue.substituteModelPointers(text, {
          resolveGrant: vaultGlue.revealGrantResolver,
        });
        spentGrantIds.push(...result.grantIds);
        return result;
      });
  // The probe settles most denials, but it cannot settle all of them: it only
  // resolves grants, while the substitution above must additionally OPEN each
  // row's ciphertext. A pointer whose grant resolves but whose value will not
  // open reaches this point looking granted, and the substitution reports it
  // back as a deny. Dropping that verdict would run the tool with the pointer
  // still literal in a field that executes. That case gets its own message:
  // the grant was never the problem, so pointing the user at granting one would
  // send them somewhere that cannot help.
  const unresolvedAfterGrant = pointerOutcomes.some((o) => o.disposition === 'deny');
  if (denyForPointer || unresolvedAfterGrant) {
    await emit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: denyForPointer
          ? denyPointerMessage(toolName)
          : denyUnresolvedPointerMessage(toolName),
      },
    });
    return;
  }
  // Fold granted de-refs into the input the rest of the hook sees: the secret
  // scan re-detects each revealed value, and the SAME grant satisfies
  // suppression there (reveal is strictly stronger) — without spending a
  // second use, because the crossing already spent it. Emitting must not
  // depend on a detection outcome: a suppressed or warn-only result would
  // otherwise let the tool run with the pointers still literal.
  let effectiveInput = toolInput;
  let derefHappened = false;
  for (const outcome of pointerOutcomes) {
    if (outcome.disposition !== 'deref' || outcome.text === undefined) continue;
    effectiveInput = replaceAtPath(effectiveInput, outcome.path, outcome.text) as Record<
      string,
      unknown
    >;
    derefHappened = true;
  }

  // A store that cannot open means NOTHING is scanned or enforced for this
  // call. Still allow — fail-open — but say so once per session instead of
  // silently passing everything through.
  const gateway = openGatewayOrNull(config);
  if (gateway === null) {
    if (claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeUnavailableMessage(config.dbPath) });
    }
    return;
  }
  // One runtime held across the field loop: a per-field open would re-parse the
  // policy bundle and could even evaluate two fields of one payload under
  // different policy snapshots. We own its lifetime here and close it in the
  // `finally` below.
  const runtime = createPluginRuntime(gateway, config.settings, { dataDir: config.dataDir });

  const kind = inputEventKind(toolName);
  // The tool NAME rides in the metadata (never its arguments — metadata is
  // stored unredacted), so findings on file-less captures (a Bash command, an
  // MCP payload) still carry a display location.
  const metadata = baseMetadata(input) ?? {};
  if (toolName) metadata.toolName = toolName;
  const filePath = inputFilePath(toolInput);
  if (filePath) metadata.filePath = filePath;

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      const text = stringAtPath(effectiveInput, spec.path);
      if (text === undefined || text === '') continue;

      const result = await runtime.capture(
        { kind, sourceTool: SOURCE_TOOL.ClaudeCode, text, metadata },
        // code_change keeps the default 'always': those events are the at-rest
        // trail the re-scan resolver reconciles against, so a benign one still
        // has to exist. tool_use records only what was flagged — this hook sees
        // every Bash command and one call per string leaf of every MCP payload,
        // and 'always' would copy that whole stream into the store to trail the
        // enforcement decisions that are the point of the kind.
        {
          ...(kind === 'tool_use' ? { persist: 'with-findings' as const } : {}),
          // Grants this call's pointer crossing already spent: suppression
          // applies without charging a second use.
          ...(spentGrantIds.length > 0 ? { preAuthorizedGrantIds: spentGrantIds } : {}),
        },
      );
      scanned.push({ spec, text, result });
    }
  } finally {
    await runtime.close();
  }

  // Collapse the per-field runtime results into the hook payload (pure module),
  // then flush it. With consent, redact fields rewrite to vault pointers and
  // the payload gains the model note + user disclosure; without it, the
  // one-way rewrite and message are exactly the pre-vault ones. `await` the
  // emit so stdout drains before process.exit — main's hook-flush fix (commit
  // 7eb59e55) applies here too.
  const decision = await decidePreToolUse(
    toolName,
    effectiveInput,
    scanned,
    vaultGlue
      ? (text, findings) =>
          vaultGlue.tokenizeText(text, {
            findings,
            sighting: filePath
              ? { location: filePath, kind: 'file' }
              : { location: `${toolName} input`, kind: 'tool-input' },
          })
      : undefined,
  );
  const revealNote = `AKA revealed granted vault value(s) to this ${toolName} call — the reveal exception you approved authorized it.`;
  if (decision) {
    const output = withProtocolNotes(
      decision.output,
      decision.realized,
      toolName,
      config,
      sessionId,
      vaultGlue,
    );
    // A deref must survive EVERY non-deny outcome. A warn-only decision carries
    // no hookSpecificOutput, so emitting it alone would run the tool with the
    // literal pointers the grant just resolved.
    if (derefHappened && !('hookSpecificOutput' in output)) {
      await emit({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'allow',
          updatedInput: effectiveInput,
        },
        systemMessage: `${output.systemMessage} ${revealNote}`,
      });
      return;
    }
    await emit(output);
    return;
  }
  // No detection outcome, but a grant rewrote the input: the tool must still
  // receive the revealed values rather than the literal pointers.
  if (derefHappened) {
    await emit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        updatedInput: effectiveInput,
      },
      systemMessage: revealNote,
    });
  }
}

// Attach the model note and extend the user disclosure on a tokenized allow
// payload. Anything failing here drops only the narration, never the decision.
function withProtocolNotes(
  output: PreToolUseOutput,
  realized: Parameters<typeof eventNote>[0]['realized'] | null,
  toolName: string,
  config: ReturnType<typeof loadConfig>,
  sessionId: string | undefined,
  vaultGlue: VaultGlue | null,
): PreToolUseOutput {
  if (!vaultGlue || realized === null || !('hookSpecificOutput' in output)) return output;
  if (!('updatedInput' in output.hookSpecificOutput) || !('systemMessage' in output)) {
    return output;
  }
  try {
    const surface = `${toolName} input`;
    const marker = sessionProtocolMarker(config.dataDir, sessionId);
    const note = eventNote({ marker, surface, realized });
    const disclosure = userDisclosure({ surface, realized });
    return {
      ...output,
      hookSpecificOutput: {
        ...output.hookSpecificOutput,
        ...(note === null ? {} : { additionalContext: note }),
      },
      systemMessage: disclosure ?? output.systemMessage,
    };
  } catch {
    return output;
  }
}

try {
  await main();
} catch {
  // Fail-open: never break the user's session
}
process.exit(0);
