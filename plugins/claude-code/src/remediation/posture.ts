/**
 * The standing 'secret' posture step of the secret-leak remediation
 * flow. After the redaction decision the flow offers a standing posture for
 * future secret detections; this module owns both halves of that step:
 *
 *  - `presentStandingSecretPosture` — the palette the standing-posture prompt offers: exactly
 *    Redact / Warn / Block / Monitor, in that order.
 *  - `writeStandingSecretPosture` — persists the chosen level to the POLICIES
 *    store (the enforcement store detections read) via `applyCategoryPosture`,
 *    NOT settings.json (which holds only the onboarding answers). It writes the
 *    'secret' category in `overwrite` mode — the same shape onboard.ts and
 *    triage/writeback.ts use for an explicit, user-confirmed posture choice — so
 *    future secret detections are governed by the standing posture.
 *
 * The write is FAIL-OPEN: a policies-store write failure is caught rather than
 * thrown, so it never breaks the Claude session, and the honest failure result
 * carries no persisted level — the caller cannot claim a false success off a
 * write that did not land.
 *
 * The 'secret' → redact write also backs the "Set 'secret' to redact"
 * shortcut: the same mechanism, so choosing it persists the standing posture
 * with no artifact redacted and no deliverable generated — this module writes
 * posture and nothing else.
 */
import { applyCategoryPosture } from '@akasecurity/plugin-sdk';
import { BUILTIN_POLICIES, type BuiltinPolicyId } from '@akasecurity/schema';

import type { CategoryPolicyWriter } from '../triage/writeback.ts';

// The prompt heading the standing-posture step presents above the palette.
const STANDING_POSTURE_PROMPT = "Set the 'secret' posture";

// The palette the standing-posture step offers, in its own display order — Redact, Warn,
// Block, Monitor — which is deliberately distinct from the catalog's canonical
// least-to-most order (BUILTIN_ORDER). The strongest remediation for a leaked
// secret (Redact) leads.
const STANDING_POSTURE_ORDER: readonly BuiltinPolicyId[] = ['redact', 'warn', 'block', 'monitor'];

// One offered palette level of the standing-posture step: the BuiltinPolicyId the flow
// persists plus its user-facing label. A pure presentation descriptor (no schema
// equivalent — RemediationOptionChoice models the distinct remediation option enum), its
// label is sourced from the schema's built-in policy catalog so it never drifts.
export interface StandingPostureOption {
  level: BuiltinPolicyId;
  label: string;
}

export interface StandingSecretPostureStep {
  prompt: string;
  options: StandingPostureOption[];
}

// Build the standing 'secret' posture presentation: the prompt plus the four
// palette options in the Redact / Warn / Block / Monitor order.
export function presentStandingSecretPosture(): StandingSecretPostureStep {
  return {
    prompt: STANDING_POSTURE_PROMPT,
    options: STANDING_POSTURE_ORDER.map((level) => ({
      level,
      label: BUILTIN_POLICIES[level].name,
    })),
  };
}

// The honest outcome of the standing-posture write. A failed write carries no
// level, so the caller cannot report the posture as persisted when it did not
// land (fail-open, no false success).
export type StandingPostureResult =
  { persisted: true; level: BuiltinPolicyId } | { persisted: false };

// Persist the chosen standing 'secret' posture to the policies store via
// `applyCategoryPosture` in `overwrite` mode (an explicit standing choice
// replaces any existing row). Fail-open: a store-write throw is caught and
// reported as a non-persisted result rather than propagated.
export function writeStandingSecretPosture(
  level: BuiltinPolicyId,
  policies: CategoryPolicyWriter,
): StandingPostureResult {
  try {
    applyCategoryPosture({ secret: level }, policies, 'overwrite');
    return { persisted: true, level };
  } catch {
    return { persisted: false };
  }
}
