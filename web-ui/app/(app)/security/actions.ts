'use server';

import type { ActionInputFailure } from '@akasecurity/schema';
import {
  DISMISS_CONFIRMATION,
  DismissMethod as DismissMethodSchema,
  DismissRecommendationInput as DismissRecommendationInputSchema,
  parseActionInput,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// The Recommended Actions card's one mutation. It writes the same
// `finding_resolution` rows the CLI's resolution lifecycle already reads, so a
// dismissal made here is the dismissal every other surface sees — the findings
// list, the severity rollup and the card's own next render agree because they
// all derive status from the same latest-resolution rule.
//
// Loopback-only, like every other mutation on this dashboard (the server binds
// 127.0.0.1; Next enforces Origin/Host on server actions). No raw content is
// read, written or echoed: the only caller-supplied value that reaches a query
// is a rule id, and it goes in as a bind parameter.

export interface DismissResult {
  ok: boolean;
  /** How many finding keys were closed. Present only on success. */
  dismissed?: number;
  error?: string;
}

// Same wording as the exception surface's: a failure names the schema KEY that
// failed, never the payload, so nothing a caller sent can be reflected back.
function malformedInput(failure: ActionInputFailure): string {
  if (failure.field === null) {
    return 'The request did not arrive in the expected shape — reload the page and try again.';
  }
  return failure.wrongType
    ? `The '${failure.field}' field did not arrive as text — reload the page and try again.`
    : `The '${failure.field}' field was not in the expected form — reload the page and try again.`;
}

/**
 * Close out every open finding of one rule, recording why.
 *
 * ONE-WAY, and the dialog says so: nothing in the product reopens a dismissed
 * finding. The scanner's redetect pass reopens a key whose latest disposition
 * is `resolved` — a value that was fixed and came back — and a dismissal is
 * deliberately not that, so a later scan detecting the same value again leaves
 * it closed. There is no un-dismiss surface either.
 *
 * The typed confirmation is re-checked here; the dialog gate is not the
 * control. Nothing stops a caller posting straight to this action, and the two
 * sibling irreversible actions on this dashboard (`rotateKey`, `purgeVault`)
 * take the same belt-and-braces shape for the same reason.
 */
export async function dismissRecommendation(input: unknown): Promise<DismissResult> {
  const parsed = parseActionInput(DismissRecommendationInputSchema, input);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };

  if (parsed.data.confirmation !== DISMISS_CONFIRMATION) {
    return { ok: false, error: `Type "${DISMISS_CONFIRMATION}" to confirm.` };
  }

  // Parsed as a plain string above (the boundary's narrowest useful claim) and
  // narrowed to the dashboard-writable subset here — so the machine verdicts a
  // person has no standing to claim ('fixed-at-source' asserts a re-scan,
  // 'enforced-in-flight' and 'redetected' are written by the boundary and the
  // scanner, 'exception' asserts an approved grant) are refused at the door
  // rather than reaching `insertResolution`'s re-parse, which would accept them.
  const method = DismissMethodSchema.safeParse(parsed.data.method);
  if (!method.success) {
    return { ok: false, error: "The 'method' field was not a disposition you can record." };
  }

  const ruleId = parsed.data.ruleId.trim();
  if (ruleId === '') return { ok: false, error: 'No rule was named.' };

  let dismissed: number;
  try {
    const store = db();
    // Resolved and written in the same call: the keys come from the same
    // predicate that counted them for the card, so what is written is what was
    // shown. A key closed by another surface between the read and the write is
    // harmless — the append-only table takes a superseding row and the latest
    // one still reads `dismissed`.
    const keys = await store.security.openFindingKeysForRule(ruleId);
    const at = Date.now();
    store.resolutions.insertResolutions(
      keys.map((findingKey) => ({
        findingKey,
        status: 'dismissed' as const,
        method: method.data,
        resolvedAt: at,
        evidence: JSON.stringify({ source: 'dashboard', surface: 'recommended-actions', ruleId }),
      })),
    );
    dismissed = keys.length;
  } catch {
    // The error is swallowed rather than reported: a store error's message can
    // quote the statement that failed, and this store holds scanned content.
    // The same reason `app/(app)/error.tsx` renders a digest and never
    // `error.message`.
    return {
      ok: false,
      error: 'Could not record the dismissal — the local store refused the write. Nothing changed.',
    };
  }

  // Both pages derive from the resolution rows this just wrote: the card drops
  // the rule, and the findings list stops counting it as open.
  //
  // Guarded, and reported as a SUCCESS if it fails. The rows are committed by
  // the time this runs, so a revalidation that throws means a stale page and
  // nothing more — letting it escape would reject an action whose write
  // already landed, telling the reader the dismissal failed while the findings
  // are in fact closed. The worst case here is a card that still lists the rule
  // until the next navigation.
  try {
    revalidatePath('/security');
    revalidatePath('/findings');
  } catch {
    // Nothing to report: the dismissal succeeded, and the reader's next page
    // load reads the rows this wrote.
  }
  return { ok: true, dismissed };
}
