// The pure decision half of pointer handling in tool INPUTS. A model that has
// been handed vault pointers will echo them back into tool calls; per
// pointer-bearing field the question is deref (an active reveal grant covers
// it — substitute the raw value back in), keep (a data field where the literal
// pointer is inert and travels as-is), or deny (an executable field where a
// literal pointer cannot execute as text, and the raw value must not be
// substituted without a grant).
//
// The substitute function is injected: it resolves grants against the vault
// and audits every crossing — revealed or refused — internally, so this module
// adds no audit of its own. Pure decision building (no I/O) so it unit-tests
// without a hook process — hook entry files run main() on import and must
// NEVER be imported by tests (same split as pre-tool-use-decision.ts).
import { hasPointer } from '@akasecurity/plugin-sdk';

import type { PathSegment } from './paths.ts';

// One tool_input field addressed for write-back, with its text and whether the
// host acts on that text directly (a shell command, a URL to fetch).
export interface PointerField {
  path: PathSegment[];
  text: string;
  executable: boolean;
}

export interface PointerFieldOutcome {
  path: PathSegment[];
  disposition: 'deref' | 'keep' | 'deny';
  // The rewritten field text; present only when disposition is 'deref'. A
  // 'deny' NEVER carries text — substitute's rewrite contains the raw values
  // of whatever pointers WERE granted, and a denied field must not leak a
  // partially-substituted form anywhere in the hook payload.
  text?: string | undefined;
}

/**
 * Decide each pointer-bearing field of a tool input. Fields without a pointer
 * yield no outcome (and `substitute` is never called for them). Never throws:
 * a failing `substitute` degrades that field to fully unresolved — deny when
 * executable, keep when data.
 *
 * Per field:
 * - executable: any unresolved pointer denies the call — the literal pointer
 *   cannot execute as text, and one ungranted pointer poisons the whole
 *   command, so a partially-substituted rewrite must never run. Only a fully
 *   granted field derefs.
 * - data: any revealed pointer derefs with the substituted text (unresolved
 *   pointers stay literal inside it, which is inert); with nothing revealed
 *   the field keeps its literal pointers unchanged.
 */
export async function decideInputPointers(
  fields: PointerField[],
  substitute: (text: string) => Promise<{ text: string; revealed: string[]; unresolved: string[] }>,
): Promise<PointerFieldOutcome[]> {
  const outcomes: PointerFieldOutcome[] = [];

  for (const field of fields) {
    if (!hasPointer(field.text)) continue;

    let text = field.text;
    let revealed: string[] = [];
    let unresolved: string[] = [];
    let failed = false;
    try {
      ({ text, revealed, unresolved } = await substitute(field.text));
    } catch {
      failed = true;
    }

    if (field.executable) {
      // Deny unless every pointer in the field resolved under a grant. This
      // also covers a failed or empty-handed substitute: the field still
      // carries a literal pointer that cannot execute as text.
      if (failed || unresolved.length > 0 || revealed.length === 0) {
        outcomes.push({ path: field.path, disposition: 'deny' });
      } else {
        outcomes.push({ path: field.path, disposition: 'deref', text });
      }
    } else if (!failed && revealed.length > 0) {
      outcomes.push({ path: field.path, disposition: 'deref', text });
    } else {
      outcomes.push({ path: field.path, disposition: 'keep' });
    }
  }

  return outcomes;
}

/** The deny reason for a pointer in executable text, in the house voice of the
 * enforcement messages. */
export function denyPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command cannot execute as text, and AKA does not ` +
    'substitute the raw value without an active reveal exception. Ask the user to grant ' +
    'one (aka exception approve) or remove the pointer.'
  );
}

/**
 * The deny reason when a grant DID cover the pointer but the value could not be
 * resolved — a purge that landed mid-call, an entry whose ciphertext no longer
 * opens. Granting another exception would not help, so the message must not
 * send the user after one.
 */
export function denyUnresolvedPointerMessage(toolName: string): string {
  return (
    `A vault pointer in a ${toolName} command is covered by a reveal exception but its ` +
    'value could not be resolved, so the command was not run rather than executed with ' +
    'the pointer as literal text. The entry may have been purged; check the vault.'
  );
}
