import {
  type CharClass,
  type EntropyBucket,
  KNOWN_PREFIXES,
  type MatchFeatures,
  type NameBucket,
  type PathClass,
  type Rule,
} from '@akasecurity/schema';

import type { MatchResult } from './types.ts';
import { shannonEntropy } from './validators/entropy.ts';

export type { CharClass, EntropyBucket, MatchFeatures, NameBucket, PathClass };
export { KNOWN_PREFIXES };

// A whole word from the list, with the inflections that mean the same thing:
// anchored at both ends, so `attestation`, `keyboard` and `testify` say
// nothing, while `tests`, `mocked` and `passwords` still do. A trailing
// number stays part of the word (`password1`, `key2`).
const TEST_WORDS =
  /^(tests?|testing|testdata|specs?|mocks?|mocked|fakes?|dummy|dummies|stubs?|samples?|examples?|placeholders?|fixtures?)\d*$/;
const SECRET_WORDS =
  /^(secrets?|tokens?|passwords?|passwd|passphrase|pwd|apikeys?|auth|credentials?|private|privkey|privatekey|secretkey|keys?)\d*$/;

/** A name's words: split on separators and at each lower-to-upper camelCase step. */
function wordsOf(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((w) => w !== '');
}

/** The bucket of a variable name: what a model needs from it, without the name. */
export function nameBucket(name: string): NameBucket {
  const words = wordsOf(name);
  if (words.some((w) => TEST_WORDS.test(w))) return 'test_like';
  if (words.some((w) => SECRET_WORDS.test(w))) return 'secret_like';
  return 'other';
}

/** The kind of file a path points at, from its directory names and file name only. */
export function classifyPath(path: string): PathClass {
  const parts = path
    .replace(/\\/g, '/')
    .toLowerCase()
    .split('/')
    .filter((p, i) => p !== '' && !(i === 0 && /^[a-z]:$/.test(p)));
  // A path with no segment besides a drive says nothing about the file.
  if (parts.length === 0) return 'unknown';
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

/** The published prefix a value starts with, if any: one rule for both callers. */
function knownPrefixOf(value: string): (typeof KNOWN_PREFIXES)[number] | null {
  return KNOWN_PREFIXES.find((p) => value.startsWith(p)) ?? null;
}

/**
 * The shortest run of consecutive characters (`abcdefgh`, `87654321`, each step
 * one code point within one of digits, lower case or upper case) that marks a
 * value as typed by hand. A random base62 value starts a run this long at a given
 * position about once in 10^12, so a run of it is not chance.
 */
export const FABRICATED_RUN = 8;

function charClassOf(ch: string): number {
  if (ch >= '0' && ch <= '9') return 0;
  if (ch >= 'a' && ch <= 'z') return 1;
  if (ch >= 'A' && ch <= 'Z') return 2;
  return 3;
}

function longestSequentialRun(value: string): number {
  let best = value.length === 0 ? 0 : 1;
  let up = 1;
  let down = 1;
  for (let i = 1; i < value.length; i += 1) {
    const cls = charClassOf(value[i] ?? '');
    const sameClass = cls !== 3 && cls === charClassOf(value[i - 1] ?? '');
    const step = value.charCodeAt(i) - value.charCodeAt(i - 1);
    up = sameClass && step === 1 ? up + 1 : 1;
    down = sameClass && step === -1 ? down + 1 : 1;
    best = Math.max(best, up, down);
  }
  return best;
}

/**
 * True when a matched value is a made-up credential rather than an issued one:
 * after its published prefix it is one or two characters repeated, or it holds a
 * run of {@link FABRICATED_RUN} consecutive characters. Narrower than the
 * `placeholder` feature on purpose: no sample words, since a random value can
 * contain `xxx` by chance, and nothing an issued credential produces at a
 * meaningful rate.
 */
export function looksFabricated(fullValue: string): boolean {
  const prefix = knownPrefixOf(fullValue) ?? undefined;
  const value = prefix === undefined ? fullValue : fullValue.slice(prefix.length);
  if (value.length === 0) return false;
  if (new Set(value).size <= 2) return true;
  return longestSequentialRun(value) >= FABRICATED_RUN;
}

/**
 * True when a finding is a provider-token rule's match on a fabricated value.
 * Scoped to the `secrets` pack, whose rules match issued tokens: a password or
 * a generic secret is chosen by a person and can hold `12345678` while live.
 */
export function isFabricatedCredential(match: Pick<MatchResult, 'ruleId' | 'rawMatch'>): boolean {
  return match.ruleId.startsWith('secrets/') && looksFabricated(match.rawMatch);
}

function looksLikePlaceholder(fullValue: string): boolean {
  const prefix = knownPrefixOf(fullValue) ?? undefined;
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

/** How far either side of a match counts as nearby, in characters. */
export const NEARBY_WINDOW = 200;

/**
 * The buckets of the words near the match — within {@link NEARBY_WINDOW}
 * characters either side, and never past a line break — apart from the value
 * itself and the name it is assigned to. Sorted and unique, so a set.
 *
 * Bounded by the window rather than the line, so the work per match is the same
 * on a one-line bundle holding thousands of matches as on a short line. A word
 * the window cuts in half at its far edge is left out rather than bucketed by a
 * fragment.
 */
function nearbyBuckets(text: string, match: MatchResult): NameBucket[] {
  const fromAt = Math.max(0, match.span.start - NEARBY_WINDOW);
  let left = text.slice(fromAt, match.span.start);
  const leftBreak = left.lastIndexOf('\n');
  if (leftBreak !== -1) left = left.slice(leftBreak + 1);
  else if (fromAt > 0) left = left.replace(/^[A-Za-z0-9_]*/, '');

  const toAt = Math.min(text.length, match.span.end + NEARBY_WINDOW);
  let right = text.slice(match.span.end, toAt);
  const rightBreak = right.indexOf('\n');
  if (rightBreak !== -1) right = right.slice(0, rightBreak);
  else if (toAt < text.length) right = right.replace(/[A-Za-z0-9_]*$/, '');

  const buckets = new Set<NameBucket>();
  for (const word of `${left} ${right}`.split(/[^A-Za-z0-9_]+/)) {
    if (word.length < 3 || word === match.variableName) continue;
    const bucket = nameBucket(word);
    if (bucket !== 'other') buckets.add(bucket);
  }
  return [...buckets].sort();
}

/**
 * The wire-safe description of one match, from the match, the rule that produced
 * it and where it was found. Pure: no I/O, and nothing it returns is text taken
 * from the scanned content.
 */
export function matchFeatures(
  match: MatchResult,
  rule: Rule,
  context: { filePath?: string; text?: string },
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
      knownPrefix: knownPrefixOf(value),
      entropyBucket: entropyBucket(value),
    },
    placeholder: looksLikePlaceholder(value),
    pathClass: context.filePath === undefined ? 'unknown' : classifyPath(context.filePath),
    name: match.variableName === undefined ? null : nameBucket(match.variableName),
    nearby: context.text === undefined ? [] : nearbyBuckets(context.text, match),
  };
}
