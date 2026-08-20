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
 * `modelJudgeConsent` is REQUIRED, and that is a security property rather than
 * a strictness preference. It was optional, and the action treated an absent
 * field as `false` — so any caller that simply did not mention it silently
 * REVOKED a live egress grant. A required boolean makes a revocation something
 * the caller has to say.
 */
export const SaveSettingsInput = z.object({
  historicalAccess: z.string(),
  modelJudgeConsent: z.boolean(),
  vaultConsent: z.string(),
  vaultInlineReveal: z.string(),
});
export type SaveSettingsInput = z.infer<typeof SaveSettingsInput>;

/**
 * `attachToControlPlane` — register this machine against an organization's
 * deployment.
 *
 * `endpoint` is stored verbatim and dialled by nothing in this repository. It
 * is validated as a non-empty string and no further: a URL check here would
 * imply this tree knows what a valid endpoint looks like, and it does not —
 * whichever distribution supplies the transport owns that question.
 *
 * There is deliberately no credential field. See ControlPlaneConnection.
 */
export const AttachInput = z.object({
  endpoint: z.string(),
  label: z.string().optional(),
});
export type AttachInput = z.infer<typeof AttachInput>;
