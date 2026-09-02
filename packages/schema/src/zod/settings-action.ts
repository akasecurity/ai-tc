// Wire contracts for the settings surface's mutating entry points.
//
// Same reasoning as the exception surface (see ./exception-action.ts): these
// arrive as untrusted JSON over an HTTP POST, so the TypeScript signature on
// the receiving function is a compile-time claim about a runtime that never
// checked it. A payload that is not an object at all throws on the first field
// read, and a thrown Server Action REJECTS — the browser gets a framework error
// page instead of the recoverable `{ ok: false, error }` these actions were
// written to return.
//
// Shape only. Whether a choice string names a real mode is still checked by the
// domain schema at the call site; what this layer guarantees is that the check
// receives the type it was written for.
import { z } from 'zod';

import { printable } from './control-plane.ts';

// Deliberately NOT `.strict()`, for the reason exception-action.ts gives: an
// unknown key from a newer client must not refuse a save over a field this
// action does not read, and stripping one cannot widen anything here.

/**
 * `saveSettings` — the consents and display preferences the dashboard edits.
 *
 * Every consent is a bare answer, never the stored record: acknowledgement
 * times and payload versions are stamped server-side, so a client cannot
 * backdate a grant or claim a version it never saw.
 *
 * `modelJudgeConsent` and `historySyncConsent` are REQUIRED, and that is a
 * security property rather than a strictness preference. `historySyncConsent`
 * is a three-state enum rather than a boolean for a related reason, set out on
 * HistorySyncConsentChoice — but it is required in exactly the same way. `modelJudgeConsent` was
 * optional, and the action treated an absent field as `false` — so any caller
 * that simply did not mention it silently REVOKED a live egress grant. A
 * required boolean makes a revocation something the caller has to say, and every
 * egress grant added since carries the same requirement for the same reason.
 */
/**
 * The history-sync answer, as three EXPLICIT states rather than a boolean.
 *
 * `unchanged` exists because the settings form submits every field on every
 * save, so a boolean forces an unrelated edit to assert something about this
 * grant — and BOTH assertions are wrong when the stored grant is stale. `true`
 * silently re-consents to a widened payload the user never affirmed; `false`
 * deletes the grant, its acknowledgedAt, and with them the paused badge, the
 * `aka status` paused line and `aka sync-history`'s stale branch — every surface
 * that exists to explain why sharing stopped, leaving the user told they never
 * opted in.
 *
 * It is a third VALUE and not an optional field, which keeps the property the
 * required boolean was introduced for: an absent key is still a parse error, so
 * a caller that simply does not mention this grant cannot revoke it by omission.
 * Saying "leave it alone" has to be said.
 */
export const HistorySyncConsentChoice = z
  .enum(['granted', 'revoked', 'unchanged'])
  .meta({ id: 'HistorySyncConsentChoice' });
export type HistorySyncConsentChoice = z.infer<typeof HistorySyncConsentChoice>;

/**
 * The model-judge answer, three states for the reason HistorySyncConsentChoice
 * gives — this form submits every field on every save, so an untouched row must
 * be able to say "leave it alone".
 *
 * Left as a boolean this grant is deleted fleet-wide on everyone's next
 * unrelated save the moment MODEL_JUDGE_PAYLOAD_VERSION is bumped, and today
 * every save rewrites its acknowledgedAt — so the record of when consent was
 * actually given drifts forward on edits that had nothing to do with it.
 */
export const ModelJudgeConsentChoice = z
  .enum(['granted', 'revoked', 'unchanged'])
  .meta({ id: 'ModelJudgeConsentChoice' });
export type ModelJudgeConsentChoice = z.infer<typeof ModelJudgeConsentChoice>;

export const SaveSettingsInput = z.object({
  historicalAccess: z.string(),
  modelJudgeConsent: ModelJudgeConsentChoice,
  historySyncConsent: HistorySyncConsentChoice,
  vaultConsent: z.string(),
  vaultInlineReveal: z.string(),
});
export type SaveSettingsInput = z.infer<typeof SaveSettingsInput>;

/**
 * `attachToControlPlane` — register this machine against an organization's
 * deployment.
 *
 * `endpoint` is validated as a string here and no further. The real check is
 * `isSafeEndpoint` at the write boundary, which is where it belongs: it refuses
 * to put a credential on a cleartext wire, and a looser duplicate here would
 * only drift from it.
 *
 * `accessKey` IS A CREDENTIAL AND NEVER REACHES settings.json. It exists on this
 * input because the action needs it, not because the descriptor stores it — the
 * action hands it to `writeControlPlaneCredential`, which owns the separate
 * owner-only file, and writes the `ControlPlaneConnection` descriptor without it.
 * That split is the one ControlPlaneConnection describes, and this field does not
 * weaken it: settings.json still carries the public half alone.
 *
 * It used to be absent, and that was the defect. Attaching wrote a descriptor
 * with no credential, which every later surface reads as attached-and-broken —
 * `aka status` says "attached — no usable credential" and forwarding silently
 * does nothing. A keyless attach has no valid outcome, so this is required
 * rather than optional; emptiness is rejected by the action.
 */
export const AttachInput = z.object({
  endpoint: z.string(),
  // `printable`, not a second copy of its regex. The label is written into
  // settings.json and printed into `aka status`, which a user reads to decide
  // whether their machine is managed — an escape sequence there can repaint or
  // hide lines of that block. `cli/src/commands/attach.ts` refuses the same set
  // on `--label` at argv-parse time so it can say why in its own words; this is
  // the same rule for the other attach surface, which writes the same field
  // into the same file that same command reads back.
  //
  // 200 matches the tenantName bound beside it in control-plane.ts; nothing
  // renders a longer one usefully.
  label: printable(200).optional(),
  accessKey: z.string(),
});
export type AttachInput = z.infer<typeof AttachInput>;
