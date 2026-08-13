// Rule file format specVersion 1 — versioned so the format can evolve without breaking community packs
import { z } from 'zod';

import { DetectionCategory, Severity } from './finding.ts';

export const MatcherType = z.enum(['keyword', 'regex', 'validator']).meta({ id: 'MatcherType' });
export type MatcherType = z.infer<typeof MatcherType>;

// The ReDoS timing verdict for a regex rule. 'safe' means the rule passed
// the adversarial probe battery within budget; 'quarantined' means it was
// excluded from the active ruleset.
export const RuleProbeVerdict = z.enum(['safe', 'quarantined']).meta({ id: 'RuleProbeVerdict' });
export type RuleProbeVerdict = z.infer<typeof RuleProbeVerdict>;

// Every object in the Rule tree is STRICT: an unrecognized key fails the parse
// rather than being stripped. A stripped key is the worst possible outcome for a
// rule author, because the rule still parses, still loads and still fires — with
// whatever the key was meant to configure simply absent. `postValidator` for
// `postValidators` silently drops a false-positive guard; `capture_group` for
// `captureGroup` silently widens the redacted span to the whole match; and a
// typo in `matcher` changes which side of the isolation boundary the rule lands
// on, since that partition reads `matcher.type`.
export const KeywordMatcher = z.strictObject({
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
// Flags for a one-shot probe. `g`/`y` are dropped so exec() always starts at
// index 0 rather than wherever a previous call left `lastIndex` — shared by
// every probe below, since all of them exec once and read the first match.
function probeFlags(flags: string): string {
  return flags.replace(/[gy]/g, '');
}

function matchesEmptyString(pattern: string, flags: string): boolean {
  try {
    const re = new RegExp(pattern, probeFlags(flags));
    return re.exec('')?.[0].length === 0;
  } catch {
    return false;
  }
}

// Does this matcher's span come from the whole match? Group 0 IS the whole
// match, so `captureGroup: 0` is spelled differently from omitting the field
// but means exactly the same thing — and must therefore face the same
// empty-string check, which it used to sidestep purely by being present.
function spansWholeMatch(captureGroup: number | undefined): boolean {
  return captureGroup === undefined || captureGroup === 0;
}

// How many capture groups `pattern` declares. Appending an empty alternative
// makes the pattern match the empty string whatever else it does, so exec()
// always returns a result — and its length, minus the whole-match entry at
// index 0, is the group count. Non-capturing groups and lookarounds are not
// counted, which is the point: they are exactly what an author miscounts.
//
// Returns undefined when the probe cannot be built. A pattern this cannot
// analyze is left alone rather than rejected — the validity refine above is
// what rejects a pattern that is genuinely malformed, and a limitation here
// must not read as an authoring error.
function captureGroupCount(pattern: string, flags: string): number | undefined {
  try {
    const probe = new RegExp(`${pattern}|`, probeFlags(flags));
    const result = probe.exec('');
    return result ? result.length - 1 : undefined;
  } catch {
    return undefined;
  }
}

// The longest pattern in the bundled rule packs is ~650 characters (a
// multi-alternative cloud-connection-string rule); 2000 leaves generous
// headroom for legitimate rules while still rejecting absurdly long patterns
// at the contract boundary before they ever reach the engine or a publish
// pipeline — both larger compile cost and more surface for pathological
// backtracking scale with pattern size.
const MAX_PATTERN_LENGTH = 2000;

export const RegexMatcher = z
  .strictObject({
    type: z.literal('regex'),
    pattern: z.string().min(1).max(MAX_PATTERN_LENGTH),
    flags: z.string().default('gi'),
    captureGroup: z.number().int().nonnegative().optional(),
  })
  .refine((v) => isValidRegex(v.pattern, v.flags), {
    message: 'pattern/flags do not form a valid JavaScript regular expression',
    path: ['pattern'],
  })
  .refine((v) => !spansWholeMatch(v.captureGroup) || !matchesEmptyString(v.pattern, v.flags), {
    message:
      'a whole-match regex that can match the empty string (e.g. "\\d*", "a?", "(?:)") can hang the matcher — scope the quantifier to a captureGroup, or require at least one character',
    path: ['pattern'],
  })
  // A group index past the last group is `undefined` at match time, so the
  // matcher records no span and the rule silently never fires — the one failure
  // mode a fixture suite catches only if the author wrote a positive fixture,
  // and nothing catches at all for a rule shipped without one. Rejecting it here
  // turns a rule that quietly detects nothing into a parse error that names the
  // group count.
  //
  // superRefine rather than refine so the count is computed once and the message
  // reads it from the validated value: a `refine` has to rebuild the count in a
  // separate error callback, off an `issue.input` it can only reach through an
  // unchecked cast — and a cast that ever missed would report "declares 0
  // capture group(s)", since `new RegExp('undefined|')` is itself valid.
  .superRefine((v, ctx) => {
    if (v.captureGroup === undefined) return;
    const groups = captureGroupCount(v.pattern, v.flags);
    if (groups === undefined || v.captureGroup <= groups) return;
    ctx.addIssue({
      code: 'custom',
      path: ['captureGroup'],
      message: `captureGroup ${String(v.captureGroup)} is out of range — the pattern declares ${String(groups)} capture group(s), so valid values are 0-${String(groups)}. An out-of-range group never matches, which would make the rule silently never fire.`,
    });
  });

export const ValidatorMatcher = z.strictObject({
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
  .strictObject({
    // Dot-prefixed, e.g. ".py" — matches the scanner's SOURCE_EXTENSIONS shape.
    extensions: z.array(z.string().regex(/^\.[A-Za-z0-9]+$/)).min(1),
  })
  .meta({ id: 'AppliesTo' });
export type AppliesTo = z.infer<typeof AppliesTo>;

// The post-validators the detection engine implements. Enumerated rather than
// left as a free string because a post-validator is a FALSE-POSITIVE guard: an
// unrecognized name used to parse happily and then be skipped at eval, so the
// rule went on firing with the check the author asked for simply absent — noisy
// in a way that reads as the rule working. `engine.ts` keys its validator table
// on this type, so a name here with no implementation (and an implementation
// here with no name) is a compile error rather than a silent runtime no-op.
export const PostValidatorName = z.enum(['entropy', 'luhn']).meta({ id: 'PostValidatorName' });
export type PostValidatorName = z.infer<typeof PostValidatorName>;

// A post-validator reference: the bare name (engine defaults), or name + config
// for per-rule tuning (e.g. entropy over short password values). Additive — the
// bare-string form stays valid for existing rules.
export const PostValidatorRef = z
  .union(
    [
      PostValidatorName,
      z.strictObject({
        name: PostValidatorName,
        config: z.record(z.string(), z.unknown()).optional(),
      }),
    ],
    {
      // A union reports one collapsed issue for every way its arms can fail, so
      // this has to describe the whole shape rather than just the name — it is
      // what an author sees for a misspelled name AND for a stray key in the
      // object form. The names come from the enum so the message cannot go
      // stale. Without it Zod says only "Invalid input", which is precisely the
      // no-feedback outcome this schema exists to remove.
      error: () =>
        `not a valid post-validator: use a bare name (${PostValidatorName.options
          .map((name) => JSON.stringify(name))
          .join(
            ' or ',
          )}) or { "name": ..., "config": { ... } }. An unrecognized name would be a false-positive guard that never runs.`,
    },
  )
  .meta({ id: 'PostValidatorRef' });
export type PostValidatorRef = z.infer<typeof PostValidatorRef>;

// Co-occurrence / proximity gate. When present on a rule, a candidate match is
// kept only if corroborated by another signal within `windowChars` of its span:
// another match whose category is in `categories`, another match whose ruleId is
// in `ruleIds`, or one of `labels` appearing (case-insensitively) in the
// surrounding text window. Additive + optional, so specVersion stays 1 and
// existing/community rules remain valid.
export const RequiresNearby = z
  .strictObject({
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
  .strictObject({
    label: z.string(),
    text: z.string().max(50_000),
    shouldMatch: z.boolean(),
    // Simulated file context for the scan, so fixtures can assert `appliesTo`
    // gating (e.g. a Python-only pattern must NOT fire in a .ts file).
    filePath: z.string().optional(),
    expectedSpans: z.array(z.strictObject({ start: z.number(), end: z.number() })).optional(),
  })
  .meta({ id: 'RuleFixture' });
export type RuleFixture = z.infer<typeof RuleFixture>;

export const Rule = z
  .strictObject({
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
