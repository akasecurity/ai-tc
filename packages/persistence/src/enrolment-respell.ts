import type { RespelledEntry } from './attachment-scope-edit.ts';
import { respellAttachmentScopeEntries } from './attachment-scope-edit.ts';
import { defaultDataDir } from './local-layout.ts';
import { applyOnboarding, readUserSettings } from './settings.ts';

/**
 * `skipped`    nothing stored under a spelling this build no longer stamps.
 * `rewritten`  at least one stored entry was re-keyed, and the record written.
 * `failed`     the read, the lock or the write failed; nothing was changed.
 */
export type EnrolmentRespellOutcome = 'skipped' | 'rewritten' | 'failed';

/**
 * Re-key stored enrolments whose identity is a spelling this build no longer
 * stamps, so a repository enrolled before the canonical form converged starts
 * forwarding again.
 *
 * A scope key is matched by EXACT STRING, so such an entry forwards nothing
 * while still reading as enrolled, and nothing raises an error about it. This
 * rewrite is what closes that; an entry no spelling can be worked out for is
 * left alone and named by `aka status` instead.
 *
 * ONE-TIME AND IDEMPOTENT with no marker to keep: the editor answers "nothing to
 * do" for a record whose keys are already canonical, so this needs no window of
 * its own and a caller may run it on every pass.
 *
 * TWO READS, and the split is the point. The outer one is only a GATE, so that a
 * machine with canonical keys never reaches `applyOnboarding` at all — that
 * function writes whatever its updater returns and stamps `onboardedAt` while it
 * is there, so calling it per pass would rewrite settings.json forever and mark
 * a machine that never onboarded as onboarded. The edit that LANDS is derived
 * again inside the lock, through the updater, because a read-modify-write whose
 * read sits outside the lock is how a concurrent `aka enroll` loses its entry.
 * Getting the gate wrong therefore costs one skipped pass and never an answer:
 * an entry added between the two reads is swept by the pass after.
 *
 * NEVER THROWS: a locked `attachmentScope` refuses the write
 * (`ManagedFieldError`), an unreadable or unwritable settings file fails it, and
 * either way the stale spelling survives to the next pass. Opens no socket and
 * asks no deployment.
 */
export function respellStoredEnrolments(base: string = defaultDataDir()): EnrolmentRespellOutcome {
  try {
    if (
      respellAttachmentScopeEntries(readUserSettings(base).attachmentScope).respelled.length === 0
    ) {
      return 'skipped';
    }
    // The list rather than a boolean, for the reason `aka enroll` keeps one:
    // a flag the compiler only ever sees assigned `false` before the call is
    // narrowed to `false` after it, since nothing tells it the updater ran.
    let respelled: readonly RespelledEntry[] = [];
    applyOnboarding((current) => {
      const result = respellAttachmentScopeEntries(current.attachmentScope);
      respelled = result.respelled;
      return respelled.length > 0 ? { attachmentScope: result.next } : {};
    }, base);
    return respelled.length > 0 ? 'rewritten' : 'skipped';
  } catch {
    return 'failed';
  }
}
