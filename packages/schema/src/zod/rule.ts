// Rule file format specVersion 1 — versioned so the format can evolve without breaking community packs
import { z } from 'zod';

import { DetectionCategory, Severity } from './finding.ts';

export const MatcherType = z.enum(['keyword', 'regex', 'validator']).meta({ id: 'MatcherType' });
export type MatcherType = z.infer<typeof MatcherType>;

// The one-time ReDoS timing verdict for a regex rule, cached locally so a
// rule already measured is never re-measured on a later hook invocation.
// 'safe' means the rule passed the adversarial probe battery within budget;
// 'quarantined' means it was excluded from the active ruleset.
export const RuleProbeVerdict = z.enum(['safe', 'quarantined']).meta({ id: 'RuleProbeVerdict' });
export type RuleProbeVerdict = z.infer<typeof RuleProbeVerdict>;

export const KeywordMatcher = z.object({
  type: z.literal('keyword'),
  // An empty keyword matches at every position, yielding one zero-length span
  // per character. Rejected here because a keyword that matches everything is
  // never intentional.
  keywords: z.array(z.string().min(1)).min(1),
  caseSensitive: z.boolean().default(false),
});

// Rejects patterns before they ever reach the engine or the publish pipeline.
// `g`/`y` are stripped so exec() always starts at index 0, independent of a
// shared regex's mutable `lastIndex`.
function isValidRegex(pattern: string, flags: string): boolean {
  try {
    new RegExp(pattern, flags);
    return true;
  } catch {
    return false;
  }
}

// A whole-match pattern that can match the empty string (e.g. "\d*", "a?",
// "(?:)") re-matches at the same index forever under the schema-default "g"
// flag unless the caller advances past it — the engine's RegexMatcher does
// that defensively, but rejecting the pattern here stops it from ever being
// published or bundled. Scoped to whole-match only: a captureGroup rule may
// legitimately use "*"/"?" around its capture (e.g. `key=(\w*)`), since the
// overall match still requires the literal "key=" to advance.
function matchesEmptyString(pattern: string, flags: string): boolean {
  try {
    const re = new RegExp(pattern, flags.replace(/[gy]/g, ''));
    return re.exec('')?.[0].length === 0;
  } catch {
    return false;
  }
}

export const RegexMatcher = z
  .object({
    type: z.literal('regex'),
    pattern: z.string(),
    flags: z.string().default('gi'),
    captureGroup: z.number().int().nonnegative().optional(),
  })
  .refine((v) => isValidRegex(v.pattern, v.flags), {
    message: 'pattern/flags do not form a valid JavaScript regular expression',
    path: ['pattern'],
  })
  .refine((v) => v.captureGroup !== undefined || !matchesEmptyString(v.pattern, v.flags), {
    message:
      'a whole-match regex that can match the empty string (e.g. "\\d*", "a?", "(?:)") can hang the matcher — scope the quantifier to a captureGroup, or require at least one character',
    path: ['pattern'],
  });

export const ValidatorMatcher = z.object({
  type: z.literal('validator'),
  name: z.enum(['luhn', 'entropy', 'ssn-checksum']),
  config: z.record(z.string(), z.unknown()).optional(),
});

export const Matcher = z
  .discriminatedUnion('type', [KeywordMatcher, RegexMatcher, ValidatorMatcher])
  .meta({ id: 'Matcher' });
export type Matcher = z.infer<typeof Matcher>;

// Optional language/file scoping. When present, the engine runs the rule only
// against text whose file extension is in `extensions` — and still runs it when
// no file context exists at all (live prompt/response hooks), since pasted code
// in a prompt has no knowable language. Additive + optional, so specVersion
// stays 1 and existing/community rules remain valid.
export const AppliesTo = z
  .object({
    // Dot-prefixed, e.g. ".py" — matches the scanner's SOURCE_EXTENSIONS shape.
    extensions: z.array(z.string().regex(/^\.[A-Za-z0-9]+$/)).min(1),
  })
  .meta({ id: 'AppliesTo' });
export type AppliesTo = z.infer<typeof AppliesTo>;

// A post-validator reference: the bare name (engine defaults), or name + config
// for per-rule tuning (e.g. entropy over short password values). Additive — the
// bare-string form stays valid for existing rules.
export const PostValidatorRef = z
  .union([
    z.string(),
    z.object({
      name: z.string(),
      config: z.record(z.string(), z.unknown()).optional(),
    }),
  ])
  .meta({ id: 'PostValidatorRef' });
export type PostValidatorRef = z.infer<typeof PostValidatorRef>;

// Co-occurrence / proximity gate. When present on a rule, a candidate match is
// kept only if corroborated by another signal within `windowChars` of its span:
// another match whose category is in `categories`, another match whose ruleId is
// in `ruleIds`, or one of `labels` appearing (case-insensitively) in the
// surrounding text window. Additive + optional, so specVersion stays 1 and
// existing/community rules remain valid.
export const RequiresNearby = z
  .object({
    // Each array, when present, must be non-empty and contain non-empty strings —
    // an empty/blank criterion would either never fire or (for labels) match
    // everything.
    categories: z.array(DetectionCategory).min(1).optional(),
    ruleIds: z.array(z.string().min(1)).min(1).optional(),
    labels: z.array(z.string().min(1)).min(1).optional(),
    windowChars: z.number().int().positive().default(160),
    // Optional confidence bump applied when a gated match is corroborated. Capped
    // small: it nudges confidence, it does not assert certainty.
    confidenceBoost: z.number().min(0).max(0.3).optional(),
  })
  // At least one corroboration criterion must be supplied; otherwise the gate is
  // meaningless (no criteria ⇒ never corroborates).
  .refine(
    (v) => (v.categories?.length ?? 0) + (v.ruleIds?.length ?? 0) + (v.labels?.length ?? 0) > 0,
    { message: 'requiresNearby needs at least one of categories, ruleIds, or labels' },
  )
  .meta({ id: 'RequiresNearby' });
export type RequiresNearby = z.infer<typeof RequiresNearby>;

export const RuleFixture = z
  .object({
    label: z.string(),
    text: z.string().max(50_000),
    shouldMatch: z.boolean(),
    // Simulated file context for the scan, so fixtures can assert `appliesTo`
    // gating (e.g. a Python-only pattern must NOT fire in a .ts file).
    filePath: z.string().optional(),
    expectedSpans: z.array(z.object({ start: z.number(), end: z.number() })).optional(),
  })
  .meta({ id: 'RuleFixture' });
export type RuleFixture = z.infer<typeof RuleFixture>;

export const Rule = z
  .object({
    specVersion: z.literal(1),
    // `packId/ruleName` (e.g. `secrets/aws-access-key`). NOTE the first segment is
    // the PACK id, NOT a namespace — this is a DIFFERENT slug space from a
    // detection id (`namespace/packId`, decoded by splitDetectionId). A Rule.id
    // therefore carries no namespace and is not globally unique across publishers;
    // never feed one to splitDetectionId. `category` below (per-rule) is the
    // taxonomy axis; the pack's enforcement policy is installed_packs.policy_id.
    id: z.string().regex(/^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/),
    name: z.string(),
    category: DetectionCategory,
    severity: Severity,
    matcher: Matcher,
    appliesTo: AppliesTo.optional(),
    postValidators: z.array(PostValidatorRef).optional(),
    requiresNearby: RequiresNearby.optional(),
    examples: z.array(z.string()).optional(),
  })
  .meta({ id: 'Rule' });
export type Rule = z.infer<typeof Rule>;

// Attribution for a rule pack — who authored/maintains it. Optional so existing
// on-disk manifests stay valid; the registry surfaces it on published packs.
export const Author = z
  .object({
    name: z.string(),
    email: z.email().optional(),
    url: z.url().optional(),
  })
  .meta({ id: 'Author' });
export type Author = z.infer<typeof Author>;

export const PackManifest = z
  .object({
    specVersion: z.literal(1),
    id: z.string(),
    name: z.string(),
    version: z.string(),
    rules: z.array(z.string()),
    // Optional attribution/provenance — consumed by the rule marketplace.
    description: z.string().optional(),
    author: Author.optional(),
    license: z.string().optional(),
    sourceUrl: z.url().optional(),
  })
  .meta({ id: 'PackManifest' });
export type PackManifest = z.infer<typeof PackManifest>;
