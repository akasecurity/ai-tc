// Wire contracts for the exception surface's mutating entry points.
//
// These arrive as untrusted JSON over an HTTP POST, so the TypeScript signature
// on the receiving function is a compile-time claim about a runtime that never
// checked it: a caller is free to post a number, a null, or an object carrying
// a hostile `toString`. Every field below is therefore `z.string()` — the
// narrowest useful claim, and the one that stops a non-string reaching a
// `.trim()`, a `.slice()`, a template literal, or a SQL bind parameter.
//
// Shape only. Whether a scope answer parses, whether a rule exists, whether a
// reason is blank — those are domain checks the caller still makes, against
// state these schemas cannot see. What this layer guarantees is that each of
// those checks receives the type it was written for.
import { z } from 'zod';

// Deliberately NOT `.strict()`. Rejecting an unknown key would refuse a payload
// from a newer client over a field this action does not read, and stripping one
// cannot widen anything here — every value that matters is named below. That is
// the opposite of ExceptionConditions, where a stripped key drops an AND-clause
// and broadens the grant.

// The retyped value that gates a permanent grant. Optional because a
// non-permanent scope never sends it; when it is sent it must be text, so an
// object that coerces to the expected string cannot stand in for it.
const confirmation = z.string().optional();

/** `approveBlocked` — grant from a blocked-ledger row, keyed by its reference. */
export const ApproveBlockedInput = z.object({
  reference: z.string(),
  scope: z.string(),
  reason: z.string(),
  confirmation,
});
export type ApproveBlockedInput = z.infer<typeof ApproveBlockedInput>;

/** `addException` — pre-authorize a raw value that has never been blocked. */
export const AddExceptionInput = z.object({
  ruleId: z.string(),
  value: z.string(),
  scope: z.string(),
  reason: z.string(),
  confirmation,
});
export type AddExceptionInput = z.infer<typeof AddExceptionInput>;

/** `grantRevealFromPointer` — mint a reveal-to-model grant from a vault pointer. */
export const GrantRevealInput = z.object({
  pointer: z.string(),
  scope: z.string(),
  justification: z.string(),
  confirmation,
});
export type GrantRevealInput = z.infer<typeof GrantRevealInput>;

// The two below take positional arguments rather than an object. They are
// modelled as objects anyway so every action validates through one parse of one
// whole input — a per-argument check would leave the shape of the call itself
// unvalidated, which is the case that throws before any field is read.

/** `revokeException` — take an active grant away, by id. */
export const RevokeExceptionInput = z.object({
  id: z.string(),
  reason: z.string(),
});
export type RevokeExceptionInput = z.infer<typeof RevokeExceptionInput>;

/** `rotateKey` — invalidate every grant, behind a typed confirmation. */
export const RotateKeyInput = z.object({
  confirmation: z.string(),
});
export type RotateKeyInput = z.infer<typeof RotateKeyInput>;

/** Why one whole-payload parse failed, in terms a caller can word a refusal from. */
export interface ActionInputFailure {
  /** The schema key that failed, or null when the input was not an object at all. */
  field: string | null;
  /**
   * The blamed issue was a TYPE mismatch, rather than a constraint on a value
   * of the right type. Reported separately because a caller cannot infer it:
   * every schema here is `z.string()` today, so every failure is a type
   * failure — but adding a `.min()`, `.regex()` or `.uuid()` to any field
   * produces a `too_small`/`invalid_format` issue on a value that IS text, and
   * a refusal hardcoded to "did not arrive as text" would then be false.
   */
  wrongType: boolean;
}

/**
 * Parse one whole action payload, reporting a failure as the name of the field
 * that failed — or null when the input was not an object at all and no field
 * can be named.
 *
 * The failure carries a schema KEY, never the payload: a value that arrives as
 * the wrong type is still a live credential, so nothing derived from it may
 * reach the message describing its rejection. Zod's own issue messages are not
 * passed through for the same reason — and neither is `unrecognized_keys`,
 * whose `keys` array holds caller-supplied names; it carries an empty path, so
 * it reports as an unnameable field rather than echoing what was sent.
 *
 * The parse lives here rather than at the call site so consumers need no direct
 * zod dependency to validate a boundary this package defines.
 */
export function parseActionInput<S extends z.ZodType>(
  schema: S,
  raw: unknown,
): { ok: true; data: z.infer<S> } | ({ ok: false } & ActionInputFailure) {
  const parsed = schema.safeParse(raw);
  if (parsed.success) return { ok: true, data: parsed.data };
  for (const issue of parsed.error.issues) {
    const [head] = issue.path;
    if (typeof head === 'string') {
      return { ok: false, field: head, wrongType: issue.code === 'invalid_type' };
    }
  }
  return { ok: false, field: null, wrongType: false };
}
