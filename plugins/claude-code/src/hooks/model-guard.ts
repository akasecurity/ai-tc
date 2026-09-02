// Prohibited-model governance, decision-only: the three refusals this feature
// can make and the model resolution they share. Pure logic plus bounded reads,
// so it unit-tests without a hook process — hook ENTRY files run main() on
// import and must never be imported by tests (the same split as
// pre-tool-use-decision.ts and user-prompt-submit-decision.ts).
//
// The three refusals answer DIFFERENT hooks in DIFFERENT vocabularies, which is
// the one thing to get right here — see each function's own note.
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

import type { DataGateway } from '@akasecurity/plugin-sdk';
import {
  buildModelRefusalEvent,
  decideProhibitedModelTurn,
  isModelProhibited,
  matchProhibitedSpawnModel,
  modelFromTranscript,
  prohibitedModelMessage,
  readSessionModel,
} from '@akasecurity/plugin-sdk';
import { SOURCE_TOOL } from '@akasecurity/schema';

import type { PreToolUseOutput } from './pre-tool-use-decision.ts';

/**
 * The one arm of `PreToolUseOutput` this seam can produce.
 *
 * Narrower than the union on purpose: a spawn refusal is only ever a deny, and
 * saying so is what lets a caller read the decision without narrowing a shape
 * that also admits an allow-with-rewrite and a bare systemMessage.
 */
export type PreToolUseDenyOutput = Extract<
  PreToolUseOutput,
  { hookSpecificOutput: { permissionDecision: 'deny' } }
>;

// PreModelSwitch answers in the SAME permission vocabulary as PreToolUse —
// `permissionDecision: 'deny'` with a reason — rather than UserPromptSubmit's
// top-level `{decision:'block'}`. Two hooks, two shapes, and the harness honors
// only its own; getting them backwards produces a hook that emits valid JSON and
// silently allows.
export interface PreModelSwitchOutput {
  hookSpecificOutput: {
    hookEventName: 'PreModelSwitch';
    permissionDecision: 'deny';
    permissionDecisionReason: string;
  };
}

/**
 * Deny the switch when `toModel` is prohibited; otherwise say nothing.
 *
 * Null means NO OPINION, which the harness reads as allow — the correct answer
 * for every uncertain case, and there are three of them: an absent `to_model`, a
 * bundle with no prohibition list, and a model not on the list. Only a model
 * KNOWN to be prohibited produces a denial.
 */
export function decidePreModelSwitch(
  toModel: string | undefined,
  prohibitedModels: readonly string[] | undefined,
): PreModelSwitchOutput | null {
  // Narrowed BEFORE the prohibition check rather than asserted after it.
  // `isModelProhibited` already returns false for an absent model, so this
  // reads as redundant — but it is what lets the compiler see a `string` at the
  // message call, and the two escape hatches that would avoid it (a cast, a
  // non-null assertion) are both banned here precisely because they survive a
  // later change to that helper while this does not.
  if (toModel === undefined || toModel === '') return null;
  if (!isModelProhibited(toModel, prohibitedModels)) return null;
  return {
    hookSpecificOutput: {
      hookEventName: 'PreModelSwitch',
      permissionDecision: 'deny',
      permissionDecisionReason: prohibitedModelMessage(toModel, 'switch'),
    },
  };
}

// ---------------------------------------------------------------------------
// The containment half: a TURN already running on a prohibited model.
// ---------------------------------------------------------------------------

/**
 * The model this session is running on, or undefined when it cannot be told.
 *
 * Two sources, cheapest first. The recorded marker is written by the model-switch
 * hooks and by SessionStart, and is authoritative when present. The transcript is
 * the fallback for a session those never covered — one that predates this plugin
 * version, or whose marker a concurrent session clobbered.
 *
 * Undefined is a real and expected answer, most obviously on the FIRST turn of a
 * session that started on a prohibited model without announcing it: no switch has
 * happened and no assistant record exists yet. That turn is allowed. It is the
 * known hole in this control, and it closes on the second turn, when the
 * transcript can answer.
 */
export function resolveSessionModel(
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): string | undefined {
  return readSessionModel(dataDir, sessionId) ?? modelFromTranscript(transcriptPath);
}

/**
 * Resolve the session's model against the bundle's prohibition list, and return
 * the refusal when there is one.
 *
 * Importable rather than inline in the hook entry, so the whole containment path
 * is exercised by the suite: an entry runs `main()` on import and can never be
 * imported by a test, so logic left there is uncovered by construction.
 *
 * TOTAL AND FAIL-OPEN. A bundle that will not load, or a model that cannot be
 * resolved, returns null and the turn proceeds to the ordinary detection path —
 * this control refuses on knowledge, never on ignorance.
 */
export async function refuseProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
): Promise<{ decision: { decision: 'block'; reason: string }; model: string } | null> {
  try {
    const { prohibitedModels } = await gateway.getPolicyBundle();
    // Bundle FIRST: with no prohibition list there is nothing to enforce, and
    // resolving the model would be a transcript read spent to reach the same
    // allow.
    if (prohibitedModels === undefined || prohibitedModels.length === 0) return null;
    const model = resolveSessionModel(dataDir, sessionId, transcriptPath);
    const decision = decideProhibitedModelTurn(model, prohibitedModels);
    // The model rides back with the verdict so the caller records WHICH model
    // was refused without resolving it twice — and so the audit row and the
    // message the user sees can never disagree about it. `model` is defined
    // whenever a decision exists: the decision returns null for an absent one.
    return decision === null || model === undefined ? null : { decision, model };
  } catch {
    return null;
  }
}

/**
 * The whole containment step: decide, and on a refusal close the gateway and
 * emit. Returns true when the turn was refused and the caller must stop.
 *
 * The emit and the close live HERE rather than in the hook entry for the same
 * reason the decision does — an entry runs `main()` on import, so a test can
 * never import one and anything left there is uncovered by construction. What
 * remains in the entry is the call and the early return.
 *
 * `emit` is a parameter rather than an import so this module stays free of the
 * stdout contract and testable without one.
 */
export async function handleProhibitedTurn(
  gateway: Pick<DataGateway, 'getPolicyBundle' | 'recordAuditEvent' | 'close'>,
  dataDir: string,
  sessionId: string | undefined,
  transcriptPath: string | undefined,
  emit: (output: { decision: 'block'; reason: string }) => Promise<void>,
): Promise<boolean> {
  const blocked = await refuseProhibitedTurn(gateway, dataDir, sessionId, transcriptPath);
  if (blocked === null) return false;
  // Recorded while the gateway is still open, and best-effort: a refusal that
  // cannot be written down is still a refusal, so a failed write must not reach
  // the entry's outer catch and turn this block into a fail-open allow — the one
  // way an audit trail could leave a session LESS governed than before it
  // existed.
  try {
    await gateway.recordAuditEvent(
      buildModelRefusalEvent({
        id: randomUUID(),
        sessionId,
        model: blocked.model,
        seam: 'turn',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        occurredAt: new Date().toISOString(),
      }),
    );
  } catch {
    // Swallowed on purpose — see above.
  }
  // Closed here rather than left to the caller's runtime `finally`, which the
  // refusal path never reaches.
  await gateway.close();
  await emit(blocked.decision);
  return true;
}

// ---------------------------------------------------------------------------
// The spawn seam: a SUBAGENT asked to run on a prohibited model.
//
// Neither seam above can reach this. A subagent turn is not a user prompt and
// not a switch, and both of those resolve the PARENT session's model — which is
// exactly the model a spawn overrides. So a session on an approved model could
// run unbounded work on a prohibited one, refused nowhere.
// ---------------------------------------------------------------------------

/**
 * The tools that start a subagent.
 *
 * BOTH spellings, because the harness renamed this tool: older builds send
 * `Task`, current ones send `Agent`. Naming only one of them is how this
 * boundary came to be unguarded in the first place — the manifest matcher went
 * on listing `Task` long after the harness had stopped sending it, so the hook
 * never ran here at all and every check inside it was dead code.
 *
 * EXPORTED so the manifest test derives its spawn case from this set rather
 * than restating it. There are three places a rename has to reach — this set,
 * the field table and the manifest matcher — and a test that cross-checks only
 * two of them leaves the third to be noticed by a human.
 */
export const SUBAGENT_TOOLS: ReadonlySet<string> = new Set(['Task', 'Agent']);

/** A subagent_type safe to resolve as a filename. */
const SAFE_SUBAGENT_TYPE = /^[A-Za-z0-9][A-Za-z0-9_-]*$/;

/**
 * The `model:` a subagent definition pins, or undefined.
 *
 * Read from the agent's own markdown frontmatter, project directory first and
 * then the user one, which is the order the harness resolves them in.
 *
 * `subagent_type` is caller-chosen, so it is refused unless it is a plain
 * name: joined unchecked it addresses any file on disk, and this runs on a
 * hook path in the user's own checkout.
 *
 * Bounded and silent — an unreadable or absent definition is simply no answer.
 */
function modelFromAgentDefinition(
  subagentType: string | undefined,
  cwd: string | undefined,
): string | undefined {
  if (subagentType === undefined || !SAFE_SUBAGENT_TYPE.test(subagentType)) return undefined;
  const roots = [cwd, homedir()].filter((r): r is string => r !== undefined && r !== '');
  for (const root of roots) {
    try {
      const raw = readFileSync(join(root, '.claude', 'agents', `${subagentType}.md`), 'utf8');
      const lines = raw.split('\n');
      if (lines[0]?.trim() !== '---') continue;
      for (const line of lines.slice(1)) {
        if (line.trim() === '---') break;
        const sep = line.indexOf(':');
        if (sep === -1) continue;
        if (line.slice(0, sep).trim() !== 'model') continue;
        const value = line
          .slice(sep + 1)
          .trim()
          .replace(/^['"]|['"]$/g, '');
        if (value !== '') return value;
      }
    } catch {
      // No definition here — try the next root.
    }
  }
  return undefined;
}

/**
 * The model a spawn will actually run on, as far as this hook can tell.
 *
 * THE ORDER IS THE HARNESS'S, and getting it wrong is a bypass rather than a
 * detail: an explicit `model` argument wins, else the agent definition's own
 * `model:` frontmatter, else the parent's. Only that last case is the one the
 * switch and turn seams have already vetted, so only that one returns undefined
 * and is allowed here. Treating an absent argument as "inherits the parent"
 * would leave a repo-local `.claude/agents/<type>.md` — an ordinary writable
 * file — naming a prohibited model that nothing checks.
 */
export function resolveSpawnModel(
  toolInput: Record<string, unknown>,
  cwd: string | undefined,
): string | undefined {
  const explicit = toolInput.model;
  if (typeof explicit === 'string' && explicit !== '') return explicit;
  const subagentType = toolInput.subagent_type;
  return modelFromAgentDefinition(typeof subagentType === 'string' ? subagentType : undefined, cwd);
}

/**
 * Deny a spawn onto a prohibited model; otherwise say nothing.
 *
 * PreToolUse vocabulary — the hook this actually runs in. It looks identical to
 * `PreModelSwitchOutput` and is not: each harness event honors only its own
 * `hookEventName`, so the two are interchangeable right up until one silently
 * allows.
 *
 * Returns the MATCHED prohibited id alongside the output, so the caller records
 * the id the prohibition was keyed on rather than the caller's spelling.
 */
export function decideSubagentSpawn(
  requested: string | undefined,
  prohibitedModels: readonly string[] | undefined,
): { output: PreToolUseDenyOutput; matched: string } | null {
  if (requested === undefined || requested === '') return null;
  const matched = matchProhibitedSpawnModel(requested, prohibitedModels);
  if (matched === undefined) return null;
  return {
    matched,
    output: {
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: prohibitedModelMessage(requested, 'spawn'),
      },
    },
  };
}

/**
 * The whole spawn step: decide, and on a refusal record it, emit and close.
 * Returns true when the spawn was refused and the caller must stop.
 *
 * Opens its own gateway and owns its lifecycle, because it runs BEFORE
 * pre-tool-use has opened one: a spawn carries no scannable field, so the scan
 * path returns early and everything it sets up happens too late to be borrowed.
 *
 * BUNDLE FIRST, then the model. With no prohibition list there is nothing to
 * enforce, and resolving the model would be a file read spent to reach the same
 * allow — the same ordering `refuseProhibitedTurn` uses for the same reason.
 *
 * TOTAL AND FAIL-OPEN: any failure returns false and the call proceeds.
 */
export async function handleSubagentSpawn(
  openGateway: () => Pick<DataGateway, 'getPolicyBundle' | 'recordAuditEvent' | 'close'> | null,
  toolName: string,
  toolInput: Record<string, unknown>,
  sessionId: string | undefined,
  cwd: string | undefined,
  emit: (output: PreToolUseDenyOutput) => Promise<void>,
): Promise<boolean> {
  if (!SUBAGENT_TOOLS.has(toolName)) return false;

  const gateway = openGateway();
  if (gateway === null) return false;

  let decision: { output: PreToolUseDenyOutput; matched: string } | null;
  let requested: string | undefined;
  try {
    const { prohibitedModels } = await gateway.getPolicyBundle();
    if (prohibitedModels === undefined || prohibitedModels.length === 0) {
      await gateway.close();
      return false;
    }
    requested = resolveSpawnModel(toolInput, cwd);
    decision = decideSubagentSpawn(requested, prohibitedModels);
  } catch {
    await gateway.close();
    return false;
  }
  if (decision === null || requested === undefined) {
    await gateway.close();
    return false;
  }

  // Best-effort and swallowed, for the same reason the other two seams swallow
  // theirs: a refusal that cannot be written down is still a refusal, and
  // letting a failed write reach the entry's outer catch would turn this deny
  // into a fail-open allow.
  //
  // `model` is the MATCHED id, not the caller's spelling, so an operator
  // filtering on the prohibited id sees this refusal beside the switch and turn
  // ones; the spelling rides along as `requested_model`.
  try {
    await gateway.recordAuditEvent(
      buildModelRefusalEvent({
        id: randomUUID(),
        sessionId,
        model: decision.matched,
        requestedModel: requested,
        seam: 'spawn',
        sourceTool: SOURCE_TOOL.ClaudeCode,
        occurredAt: new Date().toISOString(),
      }),
    );
  } catch {
    // Swallowed on purpose — see above.
  }

  // EMITTED BEFORE THE CLOSE. The refusal is already decided, and `close()`
  // can throw on a handle it cannot close — that rejection would escape to the
  // entry's outer catch and leave empty stdout, which this host reads as no
  // opinion. A bookkeeping failure must not discard a deny.
  await emit(decision.output);
  try {
    await gateway.close();
  } catch {
    // Same reason the audit write above is swallowed.
  }
  return true;
}
