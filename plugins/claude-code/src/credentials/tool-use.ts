// Credential handles around the PreToolUse and PostToolUse pipelines.
//
// PreToolUse: the pipeline scans and records the input exactly as the model
// wrote it, handles included. Its answer is then taken, and unless it denies
// the call, the handles are replaced by their values in the input it answers
// with. A handle that does not resolve stays as written and the call runs.
//
// PostToolUse: a value injected earlier in the session is replaced by its
// handle in the tool's output BEFORE the pipeline scans it, so the value is
// never scanned, recorded or shown to the model, and the replaced output is
// returned as `updatedToolOutput`.
import { resolveCredentialValues } from '@akasecurity/plugin-runtime';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { CredentialSlug } from '@akasecurity/schema';

import type { HookOutput } from '../hooks/shared.ts';
import { getString } from '../hooks/shared.ts';
import {
  handleList,
  handleSlugsIn,
  scrubValues,
  substituteHandles,
  valueScrubber,
} from './handles.ts';
import type { CredentialResolver } from './session-credentials.ts';
import {
  injectedValues,
  notePendingCall,
  noteTranscript,
  resolveForSession,
  settlePendingCall,
} from './session-credentials.ts';

type Emit = (output: HookOutput) => Promise<void>;

export interface CredentialHookDeps {
  readonly resolve?: CredentialResolver;
  /**
   * True when this process stays up to see the call's PostToolUse. A one-shot
   * hook process forgets the value on exit and could not replace it in the
   * output, so it refuses the call instead of injecting.
   */
  readonly persistent?: boolean;
  /** Called with the session id after a value was injected or scrubbed. */
  readonly onValuesUsed?: (sessionId: string | undefined) => void;
}

const attachedResolver: CredentialResolver = (slugs, sessionId) =>
  resolveCredentialValues({ dataDir: dataDir(), slugs, sessionId });

function joinMessages(...parts: (string | undefined)[]): string | undefined {
  const present = parts.filter((p): p is string => p !== undefined && p !== '');
  return present.length === 0 ? undefined : present.join(' ');
}

/** Runs `run`, collecting what it emits, and rethrows its failure after `after` has run. */
async function collecting(
  run: (emit: Emit) => Promise<unknown>,
  after: (outputs: HookOutput[]) => Promise<HookOutput[]>,
  emit: Emit,
): Promise<void> {
  const outputs: HookOutput[] = [];
  let failure: { error: unknown } | undefined;
  try {
    await run((output) => {
      outputs.push(output);
      return Promise.resolve();
    });
  } catch (error) {
    failure = { error };
  }
  let final: HookOutput[];
  try {
    final = await after(outputs);
  } catch {
    final = outputs;
  }
  for (const output of final) await emit(output);
  if (failure !== undefined) throw failure.error;
}

function isDeny(output: HookOutput): boolean {
  return (
    'hookSpecificOutput' in output &&
    'permissionDecision' in output.hookSpecificOutput &&
    output.hookSpecificOutput.permissionDecision === 'deny'
  );
}

function refusalNote(
  toolName: string,
  refused: readonly CredentialSlug[],
  unanswered: readonly CredentialSlug[],
): string | undefined {
  const missing = [...refused, ...unanswered];
  if (missing.length === 0) return undefined;
  return `AKA could not supply ${handleList(missing)} to this ${toolName} call; it runs with the handle as written.`;
}

/** The PreToolUse answer with credential handles replaced by their values. */
async function withValues(
  input: Record<string, unknown>,
  outputs: HookOutput[],
  deps: CredentialHookDeps,
): Promise<HookOutput[]> {
  const toolInput = input.tool_input;
  if (typeof toolInput !== 'object' || toolInput === null) return outputs;
  if (outputs.length > 1 || outputs.some(isDeny)) return outputs;
  const output = outputs[0];
  const decided =
    output !== undefined &&
    'hookSpecificOutput' in output &&
    output.hookSpecificOutput.hookEventName === 'PreToolUse' &&
    'updatedInput' in output.hookSpecificOutput
      ? output.hookSpecificOutput
      : undefined;
  const base: Record<string, unknown> =
    decided?.updatedInput ?? (toolInput as Record<string, unknown>);
  const slugs = handleSlugsIn(base);
  if (slugs.length === 0) return outputs;

  const sessionId = getString(input, 'session_id');
  const toolName = getString(input, 'tool_name') ?? 'tool';
  if (deps.persistent !== true) {
    return [
      {
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'deny',
          permissionDecisionReason: `AKA's credential service is starting, so it did not supply ${handleList(slugs)}. Run the same call again.`,
        },
      },
    ];
  }
  const resolved = await resolveForSession(sessionId, slugs, deps.resolve ?? attachedResolver);
  noteTranscript(sessionId, getString(input, 'transcript_path'));
  const note = refusalNote(
    toolName,
    resolved.refused.map(({ slug }) => slug),
    resolved.unanswered,
  );
  const shown =
    output !== undefined && 'systemMessage' in output ? output.systemMessage : undefined;
  if (resolved.values.size === 0) {
    if (note === undefined) return outputs;
    if (output === undefined) return [{ systemMessage: note }];
    return [{ ...output, systemMessage: joinMessages(shown, note) ?? note }];
  }

  const { value, substituted } = substituteHandles(base, resolved.values);
  const updatedInput = value as Record<string, unknown>;
  notePendingCall(getString(input, 'tool_use_id'));
  deps.onValuesUsed?.(sessionId);
  const message = joinMessages(
    shown,
    `AKA supplied ${handleList(substituted)} to this ${toolName} call.`,
    note,
  );
  if (output !== undefined && decided !== undefined && 'permissionDecision' in decided) {
    return [
      {
        hookSpecificOutput: { ...decided, updatedInput },
        systemMessage: message ?? '',
      },
    ];
  }
  return [
    {
      hookSpecificOutput: { hookEventName: 'PreToolUse', updatedInput },
      ...(message === undefined ? {} : { systemMessage: message }),
    },
  ];
}

/**
 * Runs the PreToolUse pipeline `run` and answers with credential handles in the
 * input replaced by their values. A call with no handle is passed straight
 * through; any fault in the substitution emits what the pipeline decided.
 */
export async function preToolUseWithCredentials(
  input: Record<string, unknown>,
  emit: Emit,
  run: (input: Record<string, unknown>, emit: Emit) => Promise<unknown>,
  deps: CredentialHookDeps = {},
): Promise<void> {
  if (handleSlugsIn(input.tool_input).length === 0) {
    await run(input, emit);
    return;
  }
  await collecting(
    (collect) => run(input, collect),
    (outputs) => withValues(input, outputs, deps),
    emit,
  );
}

/**
 * Runs the PostToolUse pipeline `run` over the tool output with every value
 * injected in this session replaced by its handle, and answers with that output
 * whenever a value was replaced, whatever the pipeline decided.
 */
export async function postToolUseWithCredentials(
  input: Record<string, unknown>,
  emit: Emit,
  run: (input: Record<string, unknown>, emit: Emit) => Promise<unknown>,
  deps: CredentialHookDeps = {},
): Promise<void> {
  const sessionId = getString(input, 'session_id');
  settlePendingCall(getString(input, 'tool_use_id'));
  const injected = injectedValues(sessionId);
  if (injected.size === 0) {
    await run(input, emit);
    return;
  }
  noteTranscript(sessionId, getString(input, 'transcript_path'));
  const scrubber = valueScrubber(injected);
  const cleanInput = { ...input };
  const slugs = new Set<CredentialSlug>();
  let updatedToolOutput: unknown;
  for (const key of ['tool_output', 'tool_response'] as const) {
    if (input[key] === undefined) continue;
    const scrubbed = scrubValues(input[key], scrubber);
    for (const slug of scrubbed.slugs) slugs.add(slug);
    cleanInput[key] = scrubbed.value;
    updatedToolOutput = scrubbed.value;
  }
  if (slugs.size === 0) {
    await run(input, emit);
    return;
  }
  deps.onValuesUsed?.(sessionId);
  const toolName = getString(input, 'tool_name') ?? 'tool';
  const scrubbed = { slugs: [...slugs], value: updatedToolOutput };
  await collecting(
    (collect) => run(cleanInput, collect),
    (outputs) => {
      const note = `AKA replaced ${handleList(scrubbed.slugs)} in the ${toolName} output so the value does not reach the model.`;
      const rewrote = outputs.find(
        (o) =>
          'hookSpecificOutput' in o &&
          o.hookSpecificOutput.hookEventName === 'PostToolUse' &&
          'updatedToolOutput' in o.hookSpecificOutput,
      );
      if (rewrote !== undefined) return Promise.resolve(outputs);
      const shown = outputs.find((o): o is { systemMessage: string } => 'systemMessage' in o);
      return Promise.resolve([
        {
          hookSpecificOutput: { hookEventName: 'PostToolUse', updatedToolOutput: scrubbed.value },
          systemMessage: joinMessages(shown?.systemMessage, note) ?? note,
        },
      ]);
    },
    emit,
  );
}
