import type { DetectionCategory, PostValidatorName, Rule } from '@akasecurity/schema';

import type { MatchResult } from './types.ts';
import { shannonEntropy } from './validators/entropy.ts';

export type PathClass =
  'test' | 'fixture' | 'example' | 'docs' | 'env' | 'config' | 'source' | 'unknown';

export type NameBucket = 'test_like' | 'secret_like' | 'other';

export type CharClass = 'digit' | 'lower' | 'symbol' | 'upper';

export type EntropyBucket = 'low' | 'medium' | 'high';

/**
 * What a correctness model may know about one match. Every field is a class, a
 * count or a member of a fixed public list: nothing in it is the matched value,
 * the variable name, the path or any other text taken from the scanned content,
 * so it can leave the device as it is.
 */
export interface MatchFeatures {
  ruleId: string;
  category: DetectionCategory;
  /** The post-validators this match passed: every one its rule applies. */
  validators: PostValidatorName[];
  /** True when the rule only fires with a corroborating signal nearby, which this match had. */
  corroborated: boolean;
  shape: {
    length: number;
    classes: CharClass[];
    /** A prefix from {@link KNOWN_PREFIXES} the value starts with, or `null`. */
    knownPrefix: string | null;
    entropyBucket: EntropyBucket;
  };
  /** The value looks like a sample, not a live credential: repeats, sequences, sample words. */
  placeholder: boolean;
  pathClass: PathClass;
  /** The bucket of the name the value is assigned to, or `null` when it has none. */
  name: NameBucket | null;
}

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

const TEST_WORDS = /(test|spec|mock|fake|dummy|stub|sample|example|placeholder|fixture)/i;
const SECRET_WORDS = /(secret|token|passw|pwd|apikey|api_key|api-key|auth|credential|private|key)/i;

/** The bucket of a variable name: what a model needs from it, without the name. */
export function nameBucket(name: string): NameBucket {
  if (TEST_WORDS.test(name)) return 'test_like';
  if (SECRET_WORDS.test(name)) return 'secret_like';
  return 'other';
}

/** The kind of file a path points at, from its directory names and file name only. */
export function classifyPath(path: string): PathClass {
  const parts = path
    .replace(/\\/g, '/')
    .toLowerCase()
    .split('/')
    .filter((p) => p !== '');
  const file = parts.at(-1) ?? '';
  const dirs = parts.slice(0, -1);
  const hasDir = (names: readonly string[]): boolean => dirs.some((d) => names.includes(d));

  if (hasDir(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e'])) return 'test';
  if (/[._-](test|spec)\.[a-z0-9]+$/.test(file) || /^test_.+\.py$/.test(file)) return 'test';
  if (hasDir(['fixtures', '__fixtures__', 'testdata', 'test-data', 'mocks', '__mocks__'])) {
    return 'fixture';
  }
  if (hasDir(['examples', 'example', 'samples', 'sample', 'demo', 'demos'])) return 'example';
  if (/\.(example|sample|template|dist)(\.[a-z0-9]+)?$/.test(file)) return 'example';
  if (hasDir(['docs', 'doc', 'documentation'])) return 'docs';
  if (
    /^(readme|changelog|contributing)(\.[a-z0-9]+)?$/.test(file) ||
    /\.(md|mdx|rst)$/.test(file)
  ) {
    return 'docs';
  }
  if (file === '.env' || file.startsWith('.env.')) return 'env';
  if (/\.(ya?ml|toml|ini|cfg|conf|json|properties)$/.test(file)) return 'config';
  return 'source';
}

function charClasses(value: string): CharClass[] {
  const classes = new Set<CharClass>();
  for (const ch of value) {
    if (/[0-9]/.test(ch)) classes.add('digit');
    else if (/[a-z]/.test(ch)) classes.add('lower');
    else if (/[A-Z]/.test(ch)) classes.add('upper');
    else classes.add('symbol');
  }
  return [...classes].sort();
}

function entropyBucket(value: string): EntropyBucket {
  const bits = shannonEntropy(value);
  if (bits < 3) return 'low';
  if (bits < 4) return 'medium';
  return 'high';
}

// Not 'test': a credential's own test mode (`sk_test_`) is a real, live value, and
// the known prefix already reports it.
const SAMPLE_WORDS =
  /(example|sample|dummy|fake|changeme|change_me|placeholder|your[_-]|replace|xxx|redacted)/i;

function looksLikePlaceholder(fullValue: string): boolean {
  const prefix = KNOWN_PREFIXES.find((p) => fullValue.startsWith(p));
  const value = prefix === undefined ? fullValue : fullValue.slice(prefix.length);
  if (value.length > 0 && new Set(value).size <= 2) return true;
  if (
    /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde)/i.test(value) &&
    shannonEntropy(value) < 3.5
  ) {
    return true;
  }
  return SAMPLE_WORDS.test(value);
}

/**
 * The wire-safe description of one match, from the match, the rule that produced
 * it and where it was found. Pure: no I/O, and nothing it returns is text taken
 * from the scanned content.
 */
export function matchFeatures(
  match: MatchResult,
  rule: Rule,
  context: { filePath?: string },
): MatchFeatures {
  const value = match.rawMatch;
  const validators = (rule.postValidators ?? []).map((ref) =>
    typeof ref === 'string' ? ref : ref.name,
  );
  return {
    ruleId: match.ruleId,
    category: match.category,
    validators,
    corroborated: rule.requiresNearby !== undefined,
    shape: {
      length: value.length,
      classes: charClasses(value),
      knownPrefix: KNOWN_PREFIXES.find((p) => value.startsWith(p)) ?? null,
      entropyBucket: entropyBucket(value),
    },
    placeholder: looksLikePlaceholder(value),
    pathClass: context.filePath === undefined ? 'unknown' : classifyPath(context.filePath),
    name: match.variableName === undefined ? null : nameBucket(match.variableName),
  };
}
