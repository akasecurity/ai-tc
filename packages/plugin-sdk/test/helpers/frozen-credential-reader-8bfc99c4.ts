import { z } from 'zod';

// ─── FROZEN. NEVER EDIT. ─────────────────────────────────────────────────────
//
// The credential reader as it stood at 8bfc99c4, a commit from before scoped
// attachments existed: `AttachedCredential` and its version constant verbatim
// from @akasecurity/schema's `src/zod/control-plane.ts` (:47, :77-89), and the
// classification step of @akasecurity/persistence's
// `readControlPlaneCredentialFile` (`src/control-plane-credential.ts` :207-215).
//
// It is not a model of a reader. It is the reader every release up to that
// commit runs, and those releases keep running on machines next to newer ones,
// because the CLI and each plugin are installed separately and each bundles its
// own copy. The releases cut after it and before the reader accepted v2 parse a
// v1 member that the drift guard in `frozen-credential-reader.test.ts` holds to
// this exact shape (a `.strict()` aside), so whatever this copy refuses, they
// refuse too.
//
// What is NOT copied: the file gate (symlink, owner, mode) and the endpoint
// checks that follow the parse. They treat every version alike, so they cannot
// decide what an older build makes of a newer credential, and that question
// is the only reason this file exists.
//
// It lives in this package rather than beside the reader because a verbatim
// copy needs `zod`, and this is the one library package that already declares
// both `zod` and @akasecurity/persistence (whose real writer the suite drives).

const ATTACHED_CREDENTIAL_SPEC_VERSION = 1;

export const FrozenAttachedCredential = z.object({
  specVersion: z.literal(ATTACHED_CREDENTIAL_SPEC_VERSION),
  // The control-plane endpoint this credential was minted against.
  endpoint: z.string().min(1),
  // The bearer credential itself. Never logged, never rendered — status
  // surfaces show `keyPrefix` and nothing else.
  apiKey: z.string().min(1),
  // First few characters of the key, safe to display so a user can match the
  // credential against their organization's key list.
  keyPrefix: z.string().min(1).max(16).optional(),
  mintedAt: z.iso.datetime().optional(),
});

export type FrozenCredentialRead =
  | { usable: true; credential: z.infer<typeof FrozenAttachedCredential> }
  | { usable: false; reason: 'malformed' };

/** The file's bytes, classified exactly as the shipped reader classified them. */
export function frozenClassifyCredential(raw: string): FrozenCredentialRead {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { usable: false, reason: 'malformed' };
  }

  const result = FrozenAttachedCredential.safeParse(parsed);
  if (!result.success) return { usable: false, reason: 'malformed' };

  return { usable: true, credential: result.data };
}
