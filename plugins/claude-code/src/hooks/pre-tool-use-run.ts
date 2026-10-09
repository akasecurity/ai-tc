// The PreToolUse pipeline, free of stdio so two callers share it: the command
// hook (pre-tool-use.ts, which reads stdin and writes stdout) and the tool.call
// mod's helper (src/mod/tool-call-entry.ts, which answers the mod). One
// implementation is how the mod and the hook cannot decide a call differently.
//
// Hook entry files run main() on import and must never be imported by tests;
// this module has no such side effect.

import type { PluginConfig, VaultGlue } from '@akasecurity/plugin-sdk';
import { createPluginRuntime, createVaultGlue, loadConfig } from '@akasecurity/plugin-sdk';
import { isVaultConsentValid, pointerTokenScanner, SOURCE_TOOL } from '@akasecurity/schema';

import type { HandoffNote } from '../mod/handoff.ts';
import { isAuthorizedValue, takeToolHandoff } from '../mod/handoff.ts';
import { sessionProtocolMarker } from '../protocol/marker.ts';
import { eventNote, userDisclosure } from '../protocol/notes.ts';
import { handleSubagentSpawn } from './model-guard.ts';
import { replaceAtPath } from './paths.ts';
import type { PointerDenyField, PointerField } from './pointer-substitution.ts';
import {
  decideInputPointers,
  decidePointerDeny,
  denyPointerMessage,
  denyUnresolvedPointerMessage,
} from './pointer-substitution.ts';
import type { PreToolUseOutput, ScannedField } from './pre-tool-use-decision.ts';
import { decidePreToolUse } from './pre-tool-use-decision.ts';
import {
  fieldText,
  inputEventKind,
  inputFilePath,
  inputLineBasis,
  isSyntheticField,
  scannableInputFields,
} from './pre-tool-use-fields.ts';
import type { HookOutput } from './shared.ts';
import { baseMetadata, captureScopeKey, getString } from './shared.ts';
import {
  claimStoreUnavailableWarning,
  openGateway,
  openGatewayOrNull,
  storeDegradedMessage,
  warnIfStoreRedirected,
} from './store-health.ts';

/** What a run did, for the caller to act on beyond what it emitted. */
export type PreToolUseRun = 'finished' | 'store-unavailable' | 'nothing-to-scan';

export interface PreToolUseRunOptions {
  /**
   * `hook`: the command hook, which governs subagent spawns and steps aside for a
   * call the tool.call mod already decided. `mod`: the mod's helper, which does
   * neither (the hook still runs after the mod and keeps both) and stays silent
   * about an unavailable store (the hook says it).
   */
  mode: 'hook' | 'mod';
  /**
   * Called with every scanned field once the decision is made, for a caller that
   * needs what was found beside what was decided (the mod's helper names the
   * detections it let through in a note). Never throws into the run.
   */
  onScanned?: (scanned: readonly ScannedField[]) => void;
}

export async function runPreToolUse(
  input: Record<string, unknown>,
  emit: (output: HookOutput) => Promise<void>,
  options: PreToolUseRunOptions,
): Promise<PreToolUseRun> {
  const toolName = getString(input, 'tool_name') ?? '';
  const rawToolInput = input.tool_input;
  if (typeof rawToolInput !== 'object' || rawToolInput === null) return 'nothing-to-scan';

  const toolInput = rawToolInput as Record<string, unknown>;
  const sessionId = getString(input, 'session_id');
  // Read at most once per hook, and only if something below actually needs it —
  // the matcher is broad enough to spawn this hook for tool calls that reach
  // neither the spawn seam nor the scan, and those must still cost nothing.
  let configMemo: PluginConfig | undefined;
  const loadConfigOnce = (): PluginConfig => (configMemo ??= loadConfig());

  // PROHIBITED-MODEL GOVERNANCE for a subagent spawn, ahead of BOTH the scan
  // and the early return below.
  //
  // The position is the point. A spawn's arguments carry no executable text, so
  // it leaves through `fields.length === 0` before any of the scan's setup
  // happens — which is why this cannot sit beside the scan and borrow its
  // gateway. It is also the only seam that sees a subagent at all: a subagent
  // turn is neither a user prompt nor a model switch, and both of those resolve
  // the PARENT's model, which is exactly what a spawn overrides.
  //
  // `handleSubagentSpawn` opens nothing unless the call really is a spawn, and
  // reads no agent definition unless the organization prohibits something, so
  // the ordinary tool call pays one set lookup for this.
  //
  // Only the command hook does this. The tool.call mod's helper leaves it alone:
  // the hook runs after the mod and governs the spawn itself.
  if (
    options.mode === 'hook' &&
    (await handleSubagentSpawn(
      () => openGatewayOrNull(loadConfigOnce()),
      toolName,
      toolInput,
      sessionId,
      getString(input, 'cwd'),
      emit,
    ))
  ) {
    return 'nothing-to-scan';
  }

  // Resolved before the store is opened: the matcher is broad enough to spawn
  // this hook for MCP tools whose payload carries no scannable text, and those
  // calls should cost nothing. An object key is scannable content now too
  // (see scannableInputFields' own comment), so this free path has narrowed
  // to a tool_input with no string keys at all — most MCP calls, having some
  // key, now do pay the store-open cost below.
  const fields = scannableInputFields(toolName, toolInput);
  if (fields.length === 0) return 'nothing-to-scan';

  const config = loadConfigOnce();
  // A call the tool.call mod's helper already decided, whose input this hook is
  // being shown after the mod's rewrite: its events and findings are recorded and
  // any grant it needed is spent, so a second pass would record twice and could
  // refuse for a use already consumed. The note is consumed once, and then it is
  // only trusted for what it can still vouch for: the hook does not take a note's
  // word that an executable field is clean (see noteStillHolds). A missing,
  // unmatched or no longer holding note leaves this pass to decide as it always did.
  if (options.mode === 'hook') {
    const note = takeToolHandoff(config.dataDir, toolName, toolInput);
    if (note !== null && (await noteStillHolds(config, note, toolName, toolInput, fields))) {
      return 'finished';
    }
  }
  // A symlinked store path redirects the corpus without failing anything;
  // say so once per session (stderr, so the stdout contract is untouched).
  warnIfStoreRedirected(config, sessionId);
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
  //
  // A joined-keys chunk (isSyntheticField — see pre-tool-use-fields.ts) is
  // still probed for the deny decision below, and denies on ANY pointer it
  // carries, granted or not — see decidePointerDeny's own comment on why a
  // GRANTED one is no safer there. What it never does is enter SUBSTITUTION
  // (decideInputPointers, further down) — a resolved deref would try to write
  // the revealed text back through the chunk's synthetic path, which has no
  // real position in the payload to write to.
  const pointerFields: PointerDenyField[] = [];
  const substitutionFields: PointerField[] = [];
  for (const spec of fields) {
    const text = fieldText(spec, toolInput);
    if (text === undefined || text === '') continue;
    const synthetic = isSyntheticField(spec);
    pointerFields.push({ text, executable: spec.executable, synthetic });
    if (!synthetic) substitutionFields.push({ path: spec.path, text, executable: spec.executable });
  }
  // Executable fields are probed FIRST — grant resolution only, no
  // de-reference. One ungranted pointer denies the whole call, and a call that
  // is denied must never have audited a reveal for the pointers that WERE
  // granted: the owner's crossing trail would then report values as sent to
  // the model on a call that never ran. With no glue, every pointer found is
  // definitionally unresolved (there is no vault to check a grant against),
  // so the fake probe reports it straight back as ungranted.
  const spentGrantIds: string[] = [];
  const denyForPointer = await decidePointerDeny(pointerFields, (text) =>
    vaultGlue
      ? vaultGlue.probeModelPointers(text, { resolveGrant: vaultGlue.revealGrantResolver })
      : Promise.resolve({ ungranted: [...text.matchAll(pointerTokenScanner())].map((m) => m[0]) }),
  );

  const pointerOutcomes = denyForPointer
    ? []
    : await decideInputPointers(substitutionFields, async (text) => {
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
    return 'finished';
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
  const opened = openGateway(config);
  if (opened.gateway === null) {
    if (options.mode === 'hook' && claimStoreUnavailableWarning(config.dataDir, sessionId)) {
      await emit({ systemMessage: storeDegradedMessage(config.dbPath, opened.error) });
    }
    return 'store-unavailable';
  }
  const gateway = opened.gateway;
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
  // Keyed by the file this call names (a Write, Edit, MultiEdit or NotebookEdit
  // target; a relative path is read against the cwd), else by the session's cwd
  // when it names none: see captureScopeKey. Beside the metadata rather than in
  // it: the key is local, the metadata is wire.
  const scopeKey = captureScopeKey(input, filePath);

  const scanned: ScannedField[] = [];
  try {
    for (const spec of fields) {
      // A joined-keys chunk (see pre-tool-use-fields.ts) carries its own
      // text, computed during the walk rather than addressable at spec.path
      // in the tool input — never a deref target, so effectiveInput (which
      // only ever differs from toolInput at a real pointer's path) is
      // irrelevant to it.
      const text = fieldText(spec, effectiveInput);
      if (text === undefined || text === '') continue;

      const result = await runtime.capture(
        {
          kind,
          sourceTool: SOURCE_TOOL.ClaudeCode,
          text,
          metadata,
          scopeKey,
          lineBasis: inputLineBasis(toolName),
        },
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
          // Per FIELD: a field that EXECUTES cannot be masked in place, since
          // rewriting a command changes what runs. Data fields can be, and keep
          // true redaction — including the reversible vault rewrite below. A
          // redact on an executable field degrades to the configured
          // `redactFallback` inside the runtime, the one place the emitted
          // decision, the recorded action and the ledger all read.
          rewritable: !spec.executable,
        },
      );
      scanned.push({ spec, text, result });
    }
  } finally {
    await runtime.close();
  }
  try {
    options.onScanned?.(scanned);
  } catch {
    // A note about what was found never changes what was decided.
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
      ? (text, findings, reversible) =>
          vaultGlue.tokenizeText(text, {
            findings,
            // Which of those the assigned archetype said to KEEP. The glue
            // rewrites every span either way; this decides only which survive
            // as recoverable pointers and which are destroyed.
            reversible,
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
      return 'finished';
    }
    await emit(output);
    return 'finished';
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
  return 'finished';
}

// Whether a handoff note still vouches for the call the hook is shown. The note
// stands in for a decision the helper made and a grant it spent, neither of which
// can be repeated, but a note is only a file: anything able to write the data
// directory could plant one for a call the helper never saw. So an EXECUTABLE field
// (one whose text runs, where a value cannot be masked in place) is looked at
// again, writing and spending nothing:
//   - a vault pointer left in it was never decided (the helper denies an ungranted
//     one and dereferences a granted one), so the note does not hold;
//   - a value the policy enforces (block or redact) may be there only if the note
//     names it among those the helper let through, as a keyed fingerprint that
//     only a holder of the store's key can produce.
// Data fields are not re-judged: the helper rewrote them and what it spent on them
// is its record. A fault in the re-check trusts the note (fail open): the helper
// did decide the call.
async function noteStillHolds(
  config: PluginConfig,
  note: HandoffNote,
  toolName: string,
  toolInput: Record<string, unknown>,
  fields: readonly ReturnType<typeof scannableInputFields>[number][],
): Promise<boolean> {
  try {
    const texts: string[] = [];
    for (const spec of fields) {
      if (!spec.executable && !isSyntheticField(spec)) continue;
      const text = fieldText(spec, toolInput);
      if (text === undefined || text === '') continue;
      if (text.matchAll(pointerTokenScanner()).next().done !== true) return false;
      texts.push(text);
    }
    if (texts.length === 0) return true;
    const opened = openGateway(config);
    if (opened.gateway === null) return true;
    const runtime = createPluginRuntime(opened.gateway, config.settings, {
      dataDir: config.dataDir,
    });
    try {
      const context = { filePath: inputFilePath(toolInput), eventKind: inputEventKind(toolName) };
      for (const text of texts) {
        for (const finding of await runtime.enforcedIn(text, context)) {
          if (!isAuthorizedValue(config.dataDir, note, finding.rawMatch)) return false;
        }
      }
    } finally {
      await runtime.close();
    }
    return true;
  } catch {
    return true;
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
