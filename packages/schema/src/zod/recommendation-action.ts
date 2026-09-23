// Wire contracts for the security page's Recommended Actions card.
//
// Same reasoning as the exception surface (see ./exception-action.ts): these
// arrive as untrusted JSON over an HTTP POST, so the TypeScript signature on
// the receiving function is a compile-time claim about a runtime that never
// checked it. Every field is `z.string()` — the narrowest useful claim, and the
// one that stops a non-string reaching a `.trim()`, a template literal, or a
// SQL bind parameter. Whether the rule exists, and whether the method names a
// disposition a human is allowed to write, are domain checks the action still
// makes against state this schema cannot see.
import { z } from 'zod';

import { ResolutionMethod } from './finding.ts';

/**
 * The retyped word that gates a dismissal, matching the vault purge and the key
 * rotation. A dismissal is one-way today — nothing re-opens a dismissed finding,
 * including a re-scan that detects it again — so it takes the same deliberate
 * confirmation every other irreversible action on this dashboard takes.
 */
export const DISMISS_CONFIRMATION = 'dismiss';

/**
 * The dispositions a person may record from the dashboard, as a narrowing of
 * {@link ResolutionMethod} rather than a fresh enum of the same strings — so
 * this set structurally cannot name a method the resolution vocabulary does not
 * define, and `insertResolution`'s own re-parse can never disagree with it.
 *
 * The four members left out are machine verdicts, and none of them is a human's
 * to claim: 'enforced-in-flight' and 'redetected' are written by the boundary
 * and the scanner, 'fixed-at-source' asserts a re-scan no longer finds the
 * value, and 'exception' asserts an approved grant covers it.
 */
export const DismissMethod = ResolutionMethod.extract(['acknowledged', 'false-positive']).meta({
  id: 'DismissMethod',
});
export type DismissMethod = z.infer<typeof DismissMethod>;

/**
 * `dismissRecommendation` — close out every open finding of ONE rule.
 *
 * Keyed by rule rather than by the card's category bucket deliberately. A row
 * reads `<ruleId> · N findings` and links to that rule's open list, so the set
 * the button writes against is the set its own label names and its own link
 * lands on. Dismissing the whole category would act on rules the row never
 * named and never counted.
 */
/**
 * The longest rule id in the bundled packs is 40 characters
 * (`secrets-infra/generic-high-entropy-secret`); 200 leaves generous headroom
 * for a pulled or custom pack while refusing an absurd one at the boundary.
 *
 * Bounded because this value does not stop at the query: it is stored verbatim
 * in the `evidence` of every row a dismissal writes, so an unbounded string is
 * unbounded storage per closed finding. A miss writes nothing today, which
 * makes the bound rest on a lookup failing rather than on validation — and the
 * next caller of this schema need not inherit that accident.
 */
const MAX_RULE_ID_LENGTH = 200;

export const DismissRecommendationInput = z.object({
  ruleId: z.string().max(MAX_RULE_ID_LENGTH),
  method: z.string(),
  confirmation: z.string(),
});
export type DismissRecommendationInput = z.infer<typeof DismissRecommendationInput>;

/**
 * The same dismissal once a person has answered it — what a view hands its
 * host, and the shape a host turns back into a {@link DismissRecommendationInput}
 * over the wire.
 *
 * It differs from the wire form in one field and for one reason: `method` is
 * `z.string()` there because that is what arrives over a POST and the narrowest
 * claim a boundary may make, while a view builds this from `DISMISS_METHODS`
 * and so already holds a real {@link DismissMethod}. Declared here rather than
 * in the view package so both halves of the round trip are defined in one
 * place, and a field added to one is a compile error at the other.
 */
export const DismissRecommendation = z.object({
  ruleId: z.string().max(MAX_RULE_ID_LENGTH),
  method: DismissMethod,
  confirmation: z.string(),
});
export type DismissRecommendation = z.infer<typeof DismissRecommendation>;
