/**
 * Derives the surfaced secret-leak summaries the calibration frame carries into
 * the remediation chain — the genuine secret hits the model did NOT dismiss
 * as false positives, projected to the raw-free MaskedSecretFinding shape the
 * finding table renders from. Pure: it reads the parsed hits, the model verdict,
 * and the writeback plan, and produces masked/enum data only.
 *
 * RAW SAFETY: the masked token is re-derived from the raw value with
 * safeMaskedMatch (never the streamed maskedMatch), and the location is run
 * through the raw-egress gate — the same conventions join-file.ts uses — so no
 * raw key can ride into the persisted frame.
 */
import { assertRawFree, safeMaskedMatch } from '@akasecurity/plugin-sdk';
import type {
  MaskedSecretFinding,
  SecretFindingState,
  TriageHit,
  TriageRecommendation,
} from '@akasecurity/schema';

import type { TriageWritebackPlan } from './writeback.ts';

// A leaked key's live/revoked status is genuinely unknowable on this machine: the
// OSS product makes no network call, so it cannot authenticate a key to check.
// The honest default is 'unknown' rather than an unverifiable 'still valid'.
const DEFAULT_STATE: SecretFindingState = 'unknown';

// Stand-in when a hit streamed no source path — the location is honestly absent,
// not fabricated.
const UNKNOWN_LOCATION = '(location unavailable)';

// The provider label, read from the raw-free ruleId (e.g. `secrets/aws-access-key`
// -> `aws`): the rule that fired names the provider/kind of secret, so this reads
// only metadata and never the raw key. Handles the `namespace/slug` and
// `namespace.slug` id shapes present in the tree.
export function deriveProvider(ruleId: string): string {
  const slug = (ruleId.split('/').pop() ?? ruleId).split('.').pop() ?? ruleId;
  const provider = slug.split('-')[0] ?? slug;
  return provider === '' ? 'unknown' : provider;
}

// Project the genuine secret hits into MaskedSecretFinding[]. Genuineness is the
// MODEL's per-hit verdict, not whether a suppression was actually written: a hit
// surfaces when it is a secret hit whose id the model did NOT list in the secret
// category's fpIds. Keying on the model's classification — never a fingerprint or
// a resolved suppression entry — means (a) a model-dismissed false positive that
// could not be keyed to a suppression (no fingerprint) still stays dismissed
// rather than surfacing as a live leak, and (b) a genuine same-value hit under a
// different rule is never wrongly hidden by an FP suppression sharing its
// fingerprint (suppressions are keyed by ruleId+fingerprint+keyVersion, not
// fingerprint alone). A secret category the plan distrusted (its reasoning echoed
// a raw value, so it carries no posture) surfaces nothing, staying consistent
// with the frame's surfacedCategories.
export function deriveSurfacedSecretFindings(
  hits: readonly TriageHit[],
  rec: TriageRecommendation,
  plan: TriageWritebackPlan,
): MaskedSecretFinding[] {
  if (plan.posture.secret === undefined) return [];

  const dismissedIds = new Set(
    rec.perCategory.filter((c) => c.category === 'secret').flatMap((c) => c.fpIds),
  );
  const rawValues = hits.map((h) => h.rawMatch);

  return hits
    .filter((h) => h.category === 'secret' && !(h.id !== undefined && dismissedIds.has(h.id)))
    .map((h) => ({
      provider: deriveProvider(h.ruleId),
      maskedToken: safeMaskedMatch(h.rawMatch),
      // A filePath is not a raw secret, but pass it through the egress gate as
      // defence-in-depth so only a raw-free location can cross into the frame.
      where: { filePath: assertRawFree(h.filePath ?? UNKNOWN_LOCATION, rawValues) },
      state: DEFAULT_STATE,
    }));
}
