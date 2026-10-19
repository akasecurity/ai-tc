import * as z from 'zod';

import { DetectionCategory } from './finding.ts';
import { PostValidatorName } from './rule.ts';

// Published, non-secret prefixes that name a credential's issuer and mode. A
// prefix outside this list is never reported, because a value's own leading
// characters are part of the secret.
export const KNOWN_PREFIXES = [
  'sk_live_',
  'sk_test_',
  'rk_live_',
  'rk_test_',
  'pk_live_',
  'pk_test_',
  'AKIA',
  'ASIA',
  'ghp_',
  'gho_',
  'ghs_',
  'github_pat_',
  'xoxb-',
  'xoxp-',
  'AIza',
  'sk-ant-',
  'sk-proj-',
  'glpat-',
  'npm_',
] as const;

export const KnownPrefix = z.enum(KNOWN_PREFIXES);
export type KnownPrefix = z.infer<typeof KnownPrefix>;

export const PathClass = z.enum([
  'test',
  'fixture',
  'example',
  'docs',
  'env',
  'config',
  'source',
  'unknown',
]);
export type PathClass = z.infer<typeof PathClass>;

/** What a model needs from a word near a match, or from a variable name, without the word. */
export const NameBucket = z.enum(['test_like', 'secret_like', 'other']);
export type NameBucket = z.infer<typeof NameBucket>;

export const CharClass = z.enum(['digit', 'lower', 'symbol', 'upper']);
export type CharClass = z.infer<typeof CharClass>;

export const EntropyBucket = z.enum(['low', 'medium', 'high']);
export type EntropyBucket = z.infer<typeof EntropyBucket>;

/**
 * What a false-positive model may know about one match. Every field is a class,
 * a count or a member of a fixed list, and every object is strict: nothing in it
 * is the matched value, a variable name, a path or other scanned text, and
 * nothing extra can ride along, so it can leave the machine as it is.
 */
export const MatchFeatures = z
  .object({
    ruleId: z.string().min(1),
    category: DetectionCategory,
    /** The post-validators this match passed: every one its rule applies. */
    validators: z.array(PostValidatorName),
    /** True when the rule only fires with a corroborating signal nearby, which this match had. */
    corroborated: z.boolean(),
    shape: z
      .object({
        length: z.number().int().nonnegative(),
        classes: z.array(CharClass),
        /** A prefix from {@link KNOWN_PREFIXES} the value starts with, or `null`. */
        knownPrefix: KnownPrefix.nullable(),
        entropyBucket: EntropyBucket,
      })
      .strict(),
    /** The value looks like a sample, not a live credential: repeats, sequences, sample words. */
    placeholder: z.boolean(),
    pathClass: PathClass,
    /** The bucket of the name the value is assigned to, or `null` when it has none. */
    name: NameBucket.nullable(),
    /** The buckets of the words on the match's line, apart from the value and its name. */
    nearby: z.array(NameBucket),
  })
  .strict();
export type MatchFeatures = z.infer<typeof MatchFeatures>;
