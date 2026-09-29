'use server';

import {
  DISMISS_CONFIRMATION,
  DismissMethod as DismissMethodSchema,
  DismissRecommendationInput as DismissRecommendationInputSchema,
  parseActionInput,
} from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { malformedInput } from '../../lib/action-refusals';
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
//
// The malformed-payload wording comes from ../../lib/action-refusals, which is
// where it lives so it can be tested: every export of a `'use server'` module
// must be an async Server Action, so a formatter defined here is reachable only
// by performing the whole write it describes. Its generic "did not arrive as
// expected" is also the right wording now that `ruleId` carries a `.max()` —
// this schema is no longer one where every failure is a type failure.

export interface DismissResult {
  ok: boolean;
  /** How many finding keys were closed. Present only on success. */
  dismissed?: number;
  error?: string;
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
    // The keys come from the same predicate that counted them for the card, so
    // what is written is what was shown. They are selected inside the write's
    // own IMMEDIATE transaction, so no scan can resolve one of them in between.
    dismissed = store.dismissOpenFindingsForRule(ruleId, {
      method: method.data,
      resolvedAt: Date.now(),
      evidence: JSON.stringify({ source: 'dashboard', surface: 'recommended-actions', ruleId }),
    });

    // Nothing to write is TWO different situations, and reporting success for
    // both is what made this control dishonest.
    //
    // The card counts a legacy at-rest row — one written before
    // `ALTER TABLE inspection_findings ADD finding_key`, so `finding_key` is
    // NULL — as open, while a disposition can only ever be written against a
    // key. On a store old enough to hold them, a rule whose open rows are ALL
    // such rows offered a working Dismiss that returned success, closed the
    // dialog, and left the same row with the same count for the reader to try
    // again. Nothing on screen distinguished it from a completed dismissal.
    //
    // So the two are separated here: if the card still counts this rule as
    // open after finding no dismissible key, what is left is undismissable and
    // the reader is told so. Otherwise there was genuinely nothing to do —
    // another surface got there first — and closing the dialog is right. The
    // extra read costs a grouped scan and runs only on this path.
    if (dismissed === 0) {
      const stillCounted = (await store.security.recommendationInputs()).some(
        (row) => row.ruleId === ruleId,
      );
      if (stillCounted) {
        return {
          ok: false,
          error:
            'These findings predate this version of the local store, so they cannot be closed from here. Re-scan the affected files to record them in a form the dashboard can act on.',
        };
      }
      return { ok: true, dismissed: 0 };
    }
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
