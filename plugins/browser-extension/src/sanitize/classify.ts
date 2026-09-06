// The value classifier and the two preservation predicates that decide what a
// sanitised capture fixture may keep verbatim.
//
// Imports NOTHING — this file has to stay trivially unit-testable and free of
// every dependency the rest of the sanitiser carries, so a mistake here is
// never hidden behind a fake detector or a fake filesystem.

/** What a string leaf structurally looks like. */
export type ValueClass =
  | 'empty'
  | 'uuid'
  | 'jwt'
  | 'iso-datetime'
  | 'url'
  | 'email'
  | 'hex'
  | 'base64ish'
  | 'numeric-string'
  | 'vocabulary'
  | 'text';

/** Classes whose surrogate is a pure function of (class, ordinal, original). */
export type SimpleValueClass = Exclude<ValueClass, 'url' | 'empty'>;

/**
 * The longest a preservable VOCABULARY value may be. One decimal digit above
 * this is not "slightly less safe" — it is the boundary that keeps this whole
 * mechanism from ever preserving a sentence: a real message body, a system
 * prompt, a person's full name are all far longer than 40 characters, so they
 * cannot clear this gate no matter what an approval file says.
 */
export const VOCABULARY_MAX_LENGTH = 40;

/** The longest an object key may be and still be considered for preservation. */
export const KEY_MAX_LENGTH = 64;

/**
 * The Shannon-entropy floor (bits/character) above which a candidate reads as
 * random rather than structural, applied only once a candidate is long enough
 * that entropy is a meaningful measurement (see ENTROPY_MIN_LENGTH).
 */
export const ENTROPY_THRESHOLD = 3.0;

/**
 * The length ABOVE which the entropy gate applies. At and below this length
 * entropy is too noisy a signal to trust — an ordinary structural token (a
 * site's own path segment, a scope name) can carry a mixed alphabet and still
 * read as "high entropy" by a per-character measure. `conversation` (length
 * 12) computes to 3.25 bits/char, above ENTROPY_THRESHOLD, and is exactly the
 * kind of value the vocabulary allowlist exists to approve. The gate is
 * applied for anything LONGER than this floor, which is where it starts
 * catching genuinely random runs (a truncated token, a key fragment) that
 * happen to fall short of base64ish's own 16-character floor.
 */
export const ENTROPY_MIN_LENGTH = 12;

/**
 * The length above which a KEY's entropy is measured over the whole
 * identifier as well as per word.
 *
 * Measured over the field names a ChatGPT/Claude request body carries, the
 * longest structural name is `history_and_training_disabled` at 29
 * characters; above 32 an identifier reads as a blob rather than a name. This
 * floor is what the per-word measure below gives away — a random run broken
 * up by hyphens has short words and clears the per-word gate — so the two are
 * applied together rather than either alone.
 */
export const KEY_WHOLE_ENTROPY_MIN_LENGTH = 32;

/** An object key eligible for preservation, structurally. */
export const SAFE_KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;

/** The characters that split a structural identifier into words. */
const KEY_WORD_SEPARATORS = /[_.-]/;

/** A string a vocabulary candidate may be built from, structurally. */
const VOCABULARY_PATTERN = /^[A-Za-z0-9[\]_.:/+-]+$/;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Three non-empty base64url segments joined by dots — the shape a JWT's
// header/payload/signature always takes, whatever they encode.
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const ISO_DATETIME_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NUMERIC_STRING_PATTERN = /^-?\d+$/;
const HEX_PATTERN = /^[0-9a-fA-F]+$/;
const BASE64ISH_PATTERN = /^[A-Za-z0-9+/=_-]{16,}$/;

function looksLikeUrl(value: string): boolean {
  if (!/^https?:\/\//i.test(value)) return false;
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

/** Shannon entropy of `value`, in bits per character (log base 2). */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Classify a string leaf's structural shape.
 *
 * Branch order is load-bearing and MUST be:
 * empty → uuid → jwt → iso-datetime → url → email → numeric-string → hex →
 * base64ish → vocabulary → text.
 * A uuid also satisfies base64ish (hyphens are in its charset); a jwt also
 * satisfies base64ish (dots are not, but each segment alone would). The first
 * match wins, so reordering silently changes what a value becomes.
 */
export function classifyString(value: string): ValueClass {
  if (value === '') return 'empty';
  if (UUID_PATTERN.test(value)) return 'uuid';
  if (JWT_PATTERN.test(value)) return 'jwt';
  if (ISO_DATETIME_PATTERN.test(value)) return 'iso-datetime';
  if (looksLikeUrl(value)) return 'url';
  if (EMAIL_PATTERN.test(value)) return 'email';
  if (NUMERIC_STRING_PATTERN.test(value)) return 'numeric-string';
  if (HEX_PATTERN.test(value)) return 'hex';
  if (BASE64ISH_PATTERN.test(value)) return 'base64ish';
  if (VOCABULARY_PATTERN.test(value)) return 'vocabulary';
  return 'text';
}

/**
 * True only for a string that MAY survive verbatim given approval.
 *
 * Requires ALL of: no whitespace anywhere; length 1..VOCABULARY_MAX_LENGTH;
 * matches the vocabulary charset; not high-entropy (the entropy gate applies
 * only once the value is longer than ENTROPY_MIN_LENGTH — see that constant's
 * own doc comment for why the boundary sits there); and `classifyString`
 * agrees the value is structurally a vocabulary token rather than, say, a
 * base64-shaped blob that happens to contain no special characters.
 */
export function isVocabularyCandidate(value: string): boolean {
  if (/\s/.test(value)) return false;
  if (value.length < 1 || value.length > VOCABULARY_MAX_LENGTH) return false;
  if (!VOCABULARY_PATTERN.test(value)) return false;
  const highEntropy =
    value.length > ENTROPY_MIN_LENGTH && shannonEntropy(value) >= ENTROPY_THRESHOLD;
  if (highEntropy) return false;
  return classifyString(value) === 'vocabulary';
}

/**
 * True only for an object key that MAY survive verbatim given approval.
 *
 * Requires SAFE_KEY_PATTERN, length <= KEY_MAX_LENGTH, and not high-entropy —
 * measured per WORD, not over the whole identifier.
 *
 * Per-character entropy of a snake_case name rises with the number of
 * distinct words it carries, regardless of how random any of them is. Over
 * the whole identifier that refuses half of the ordinary field names a
 * request body is made of — `conversation_id` (3.51), `parent_message_id`
 * (3.45), `completion_tokens` (3.45) all clear ENTROPY_THRESHOLD while every
 * word in them is a dictionary word — and a refused key cannot be rescued by
 * an approval file, because this predicate is consulted BEFORE the approvals
 * are. A fixture that cannot carry `conversation_id` cannot carry the paths
 * an adapter's `requiredPaths` are written against, which pushes the operator
 * toward hand-writing one. Measuring each word instead keeps the gate
 * pointed at what it is for: a genuinely random run used as a key.
 *
 * Both floors apply. The per-word measure is blind to a random run broken up
 * by separators (`Xk9f-Q2mW-7pL4` has only short words), so the whole-string
 * measure is kept above KEY_WHOLE_ENTROPY_MIN_LENGTH, which sits clear of
 * every structural name measured. Neither gate is the last line: an
 * unapproved key is replaced whatever this returns, and an approved one is
 * still scanned by the detector and still had to be written into a file a
 * human reviewed.
 */
export function isPreservableKey(key: string): boolean {
  if (!SAFE_KEY_PATTERN.test(key)) return false;
  if (key.length > KEY_MAX_LENGTH) return false;
  if (key.length > KEY_WHOLE_ENTROPY_MIN_LENGTH && shannonEntropy(key) >= ENTROPY_THRESHOLD) {
    return false;
  }
  for (const word of key.split(KEY_WORD_SEPARATORS)) {
    if (word.length > ENTROPY_MIN_LENGTH && shannonEntropy(word) >= ENTROPY_THRESHOLD) return false;
  }
  return true;
}
