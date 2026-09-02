// Model governance vocabulary — the curated, vendor-published facts a
// data-governance reviewer needs about a model: what it is good at, how long
// the vendor keeps the data, and whether the data trains the next model.
//
// Every value in this file is CURATED (read from a vendor's published policy by
// a human) rather than measured. Nothing here is derived from traffic: the
// event stream carries a raw model string and nothing else. The one rule the
// whole module exists to enforce is that an unknown fact is recorded as unknown
// and never as a plausible default.
import { z } from 'zod';

/**
 * A flagged specialisation, or `null` for a general-purpose model. `null` is a
 * curated statement ("reviewed, no flagged specialisation"), not an unfilled
 * field — entries carry a note saying so.
 */
export const ModelCapability = z.enum(['reasoning', 'code']);
export type ModelCapability = z.infer<typeof ModelCapability>;

/**
 * How long the serving platform retains request data.
 *
 *   zero_retention    — contractual zero-retention; nothing persisted
 *   no_storage        — not stored beyond the request lifetime
 *   configurable      — depends on the customer's own settings/contract
 *   on_device         — never leaves the caller's machine
 *   on_infrastructure — retained on infrastructure the customer controls
 *   unknown           — not verified. The honest default for any platform whose
 *                       terms we have not read; NEVER inferred from the vendor's
 *                       own posture, since a reseller's terms are its own.
 */
export const DataRetention = z.enum([
  'zero_retention',
  'no_storage',
  'configurable',
  'on_device',
  'on_infrastructure',
  'unknown',
]);
export type DataRetention = z.infer<typeof DataRetention>;

/** Whether the model is one this deployment onboarded, or one we merely observed. */
export const ModelSeen = z.enum(['managed', 'discovered']);
export type ModelSeen = z.infer<typeof ModelSeen>;

/**
 * Whether customer data is used to train the vendor's models.
 *
 * Tri-state rather than boolean because the answer is NOT a property of the
 * model — it is a property of (vendor policy x the plan the caller is on x
 * whether they exercised the opt-out/opt-in). The event stream tells us none of
 * those: a Claude Code session reports the same model id whether it is billed
 * against an API key or a Claude.ai subscription. So the honest default is
 * `unknown`, and it stays `unknown` until an operator declares the plan.
 *
 * A boolean cannot express this without asserting one of two unchecked
 * claims: `false` for a consumer-tier caller who opted in, or `true` for an
 * API caller covered by a no-training agreement.
 */
export const TrainsOnData = z.enum(['yes', 'no', 'unknown']);
export type TrainsOnData = z.infer<typeof TrainsOnData>;

/** How a customer changes their tier's training default, if they can at all. */
export const TrainingControl = z.enum([
  /** Off by default; the customer must switch it on. */
  'opt-in',
  /** On by default; the customer must switch it off. */
  'opt-out',
  /** Not customer-controllable. */
  'none',
  /** Not verified. */
  'unknown',
]);
export type TrainingControl = z.infer<typeof TrainingControl>;

/**
 * A vendor's published training policy, split by the plan the caller is on.
 * Curated from the vendor's own privacy documentation; `source` is the URL it
 * was read from so the next updater can re-verify rather than re-guess.
 *
 * Note this is the VENDOR's policy for its own first-party endpoints. It says
 * nothing about a model served through a cloud reseller, whose training and
 * retention terms belong to that reseller's contract — see `resolveTrainsOnData`.
 */
export const VendorTrainingPolicy = z.object({
  /** Does the vendor's first-party API train on customer data by default? */
  apiDefault: TrainsOnData,
  /** Does the vendor's consumer / pro / team subscription train by default? */
  consumerDefault: TrainsOnData,
  /** How a consumer-tier customer changes that default. */
  consumerControl: TrainingControl,
  /** Vendor documentation URL this was curated from. */
  source: z.string().nullable(),
});
export type VendorTrainingPolicy = z.infer<typeof VendorTrainingPolicy>;

/**
 * Which plan a caller's traffic is billed against. Never observable from the
 * event stream — an operator declares it, per tenant. `unknown` is the default
 * for every deployment that has not.
 */
export const PlanTier = z.enum(['api', 'consumer', 'enterprise', 'unknown']);
export type PlanTier = z.infer<typeof PlanTier>;

/**
 * An operator's declaration of how their organisation is billed and whether
 * they exercised the training control. This is the ONLY input that can turn a
 * `trainsOnData` of `unknown` into a definite answer.
 */
export const TrainingDeclaration = z.object({
  tier: PlanTier,
  /**
   * Whether the org exercised its tier's training control — `true` means opted
   * IN where the control is `opt-in`, and opted OUT where it is `opt-out`.
   * `null` means undeclared, which leaves the tier default in force.
   */
  controlExercised: z.boolean().nullable(),
});
export type TrainingDeclaration = z.infer<typeof TrainingDeclaration>;

/** The undeclared default — what every tenant reads as until an operator says otherwise. */
export const UNDECLARED_TRAINING: TrainingDeclaration = Object.freeze({
  tier: 'unknown',
  controlExercised: null,
});

/**
 * Resolve the effective `trainsOnData` for a model on a platform, given what
 * the operator has declared.
 *
 * The rules, in order:
 *
 *  1. A model running on the caller's own hardware sends nothing to a vendor,
 *     so it cannot train one. That is a fact about the deployment, not a policy
 *     claim — `'no'` regardless of any declaration.
 *  2. A model served by a cloud reseller is governed by that reseller's
 *     contract, which this catalog does not carry. `'unknown'` — the vendor's
 *     own posture describes the vendor's own endpoints and does not transfer.
 *  3. On a first-party endpoint the vendor's per-tier policy applies, selected
 *     by the declared tier. An undeclared tier is `'unknown'`: we cannot tell an
 *     API key from a consumer subscription by looking at a model id.
 *  4. A declared control flips the CONSUMER tier's default in the direction its
 *     `TrainingControl` allows. It applies to no other tier: `consumerControl`
 *     describes the consumer tier only, and `VendorTrainingPolicy` carries no
 *     equivalent for the API tier, so there is nothing legitimate for an
 *     api/enterprise declaration to consult.
 */
export function resolveTrainsOnData(input: {
  hosting: ModelHostingLike;
  firstParty: boolean;
  policy: VendorTrainingPolicy | null;
  declaration: TrainingDeclaration;
}): TrainsOnData {
  const { hosting, firstParty, policy, declaration } = input;

  // (1) Self-hosted weights never reach a vendor.
  if (hosting === 'local') return 'no';

  // (2) Reseller/gateway terms are not the vendor's terms.
  if (!firstParty) return 'unknown';

  if (policy === null) return 'unknown';

  // (3) Tier default.
  const tierDefault: TrainsOnData =
    declaration.tier === 'api' || declaration.tier === 'enterprise'
      ? policy.apiDefault
      : declaration.tier === 'consumer'
        ? policy.consumerDefault
        : 'unknown';

  if (tierDefault === 'unknown') return 'unknown';

  // (4) An exercised control flips the default the one way its control allows.
  // Consumer tier only — see rule 4 above.
  if (declaration.tier === 'consumer' && declaration.controlExercised === true) {
    if (policy.consumerControl === 'opt-in') return 'yes';
    if (policy.consumerControl === 'opt-out') return 'no';
  }

  return tierDefault;
}

/**
 * Structural stand-in for `ModelHosting` so this module does not import
 * `providers.ts` purely for a type — the two are otherwise independent, and
 * keeping them so leaves the governance vocabulary reusable on its own.
 */
type ModelHostingLike = 'api' | 'gateway' | 'local';
