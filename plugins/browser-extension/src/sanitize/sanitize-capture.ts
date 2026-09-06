// The sanitiser core: a pure document walker that turns a raw web-chat capture
// into a shape-preserving, vocabulary-free fixture. See the module's own tests
// for the leak surfaces this is built to close.
//
// No node:*, no clock, no RNG, no filesystem — every surrogate is a
// deterministic function of (class, ordinal, length/shape), never of the
// original value's content, and the whole run is a pure function of its input.
import type { SimpleValueClass, ValueClass } from './classify.ts';
import { classifyString, isPreservableKey, isVocabularyCandidate } from './classify.ts';

export const FIXTURE_SCHEMA_ID = 'aka-web-capture-fixture/1';

// One decimal digit has no capacity for an identifier, so an integer this
// small is kept rather than replaced.
export const NUMBER_KEEP_MAX = 9;

// The shortest run of a non-preserved original that still counts as a
// disclosure if it survives into the output text.
export const RESIDUE_RUN = 8;

// A subtree past this depth is replaced whole rather than walked further —
// both ordinary object/array nesting and a string that recursively decodes as
// nested JSON share this one counter.
export const MAX_DEPTH = 64;

// A document carrying more scalar leaves than this refuses rather than
// running to completion on an unbounded payload.
export const MAX_LEAVES = 200_000;

// 32 MiB. A capture over this size refuses before any parsing is attempted.
export const MAX_INPUT_BYTES = 32 * 1024 * 1024;

export type FixtureKind = 'conversation' | 'account';
export type FixtureDirection = 'request' | 'response';
export type CaptureFormat = 'json' | 'sse' | 'ndjson' | 'urlencoded' | 'text';

export interface FixtureEnvelope {
  readonly $schema: typeof FIXTURE_SCHEMA_ID;
  readonly site: string;
  readonly kind: FixtureKind;
  readonly direction: FixtureDirection;
  readonly url: string;
  readonly format: CaptureFormat;
  readonly chunks: readonly string[];
  readonly surrogates: {
    readonly strings: readonly string[];
    readonly numbers: readonly number[];
  };
}

/** Rule ids for anything the detection engine finds in `text`. */
export type Detect = (text: string) => readonly string[];

export interface SanitizeInput {
  readonly raw: string;
  readonly url: string;
  readonly site: string;
  readonly kind: FixtureKind;
  readonly direction: FixtureDirection;
  readonly format: CaptureFormat;
  /** Hosts that may appear verbatim in a URL. Anything else -> host-<n>.invalid. */
  readonly allowedHosts: readonly string[];
  readonly approvedKeys: ReadonlySet<string>;
  readonly approvedValues: ReadonlySet<string>;
  /**
   * REQUIRED — no default, deliberately. A default would read as safe at every
   * call site that omits it, which is every call site until somebody remembers.
   */
  readonly detect: Detect;
}

export interface SanitizeReport {
  readonly preservedKeys: readonly string[];
  readonly candidateKeys: readonly string[];
  readonly flaggedKeys: readonly { readonly ruleIds: readonly string[] }[];
  readonly preservedValues: readonly string[];
  readonly candidateValues: readonly string[];
  readonly flaggedValues: readonly { readonly ruleIds: readonly string[] }[];
  readonly replaced: Readonly<Record<ValueClass, number>>;
  /**
   * Leaves kept VERBATIM by the small-scalar carve-outs. An integer with
   * |n| <= NUMBER_KEEP_MAX and every boolean survive unchanged and are not
   * accounted anywhere else — the carve-out is bounded per leaf and unbounded
   * per document, so a long enough sequence of them is a channel no other
   * layer of this tool can see. Reported so an operator reviewing a fixture
   * reads "N small integers and M booleans preserved verbatim" rather than
   * nothing.
   */
  readonly smallIntegersKept: number;
  readonly booleansKept: number;
  readonly leaves: number;
}

export type SanitizeRefusal =
  | 'detector-unavailable'
  | 'envelope-not-a-body'
  | 'input-too-large'
  | 'too-many-leaves'
  | 'unparseable-input'
  | 'unparseable-url'
  | 'unrepresentable-number'
  | 'residue-run'
  | 'residue-detected';

export type SanitizeResult =
  | {
      readonly ok: true;
      readonly fixture: FixtureEnvelope;
      readonly text: string;
      readonly report: SanitizeReport;
    }
  | {
      readonly ok: false;
      readonly refusal: SanitizeRefusal;
      /** Names the path/class/rule id. NEVER a value from the input. */
      readonly error: string;
      readonly report: SanitizeReport | null;
    };

/** Whether `text` is longer than `max` bytes, without encoding when it need not. */
function exceedsBytes(text: string, max: number): boolean {
  if (text.length > max) return true;
  return new TextEncoder().encode(text).byteLength > max;
}

// Internal control-flow signal for a run-level refusal reached mid-walk. Never
// escapes this module.
class SanitizeAbort extends Error {
  constructor(
    readonly refusal: SanitizeRefusal,
    message: string,
  ) {
    super(message);
  }
}

const HEX_CHARS = '0123456789abcdef';
const ALNUM_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const BASE64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

function syntheticRun(alphabet: string, length: number, seed: number, stride: number): string {
  let out = '';
  for (let i = 0; i < length; i += 1) {
    out += alphabet.charAt((seed + i * stride + 3) % alphabet.length);
  }
  return out;
}

function syntheticDigits(length: number, seed: number): string {
  let out = '';
  for (let i = 0; i < length; i += 1) out += String((seed + i * 3 + 1) % 10);
  return out;
}

// A leading '0' in an integer part, or a trailing '0' in a decimal part, is
// silently dropped the moment the digit string is round-tripped through the
// JS `number` type (`Number('0581')` is 581; `Number('3.50')` is 3.5) — which
// is exactly what numberSurrogate does. Left alone, that would break the
// "digit count preserved" guarantee for whichever ordinal happened to land a
// zero at the edge. The specific digit value carries no meaning (surrogates
// never read the original's content), so nudging an edge zero to '1' costs
// nothing and keeps the count exact.
function protectEdgeZero(digits: string, edge: 'leading' | 'trailing'): string {
  if (digits.length === 0) return digits;
  const index = edge === 'leading' ? 0 : digits.length - 1;
  if (digits[index] !== '0') return digits;
  const chars = digits.split('');
  chars[index] = '1';
  return chars.join('');
}

/**
 * The surrogate for a class + ordinal. MUST NOT read `original`'s CONTENT —
 * only its length (hex, base64ish, jwt, numeric-string) and its decimal shape
 * (numbers, handled by numberSurrogate below). A content-derived surrogate is
 * a recoverable fingerprint of the original and is forbidden.
 */
export function surrogateFor(
  valueClass: SimpleValueClass,
  ordinal: number,
  original: string,
): string {
  switch (valueClass) {
    case 'text':
      return `TEXT_${String(ordinal)}`;
    case 'vocabulary':
      return `TOKEN_${String(ordinal)}`;
    case 'uuid':
      return `00000000-0000-4000-8000-${String(ordinal).padStart(12, '0')}`;
    case 'jwt': {
      const segments = original.split('.');
      return segments
        .map((segment, index) => syntheticRun(BASE64URL_CHARS, segment.length, ordinal + index, 13))
        .join('.');
    }
    case 'iso-datetime': {
      const base = Date.UTC(2024, 0, 1);
      return new Date(base + ordinal * 1000).toISOString();
    }
    case 'email':
      return `user-${String(ordinal)}@example.invalid`;
    case 'hex':
      return syntheticRun(HEX_CHARS, original.length, ordinal, 7);
    case 'base64ish': {
      const trailingEquals = /=+$/.exec(original)?.[0].length ?? 0;
      const bodyLength = original.length - trailingEquals;
      return syntheticRun(ALNUM_CHARS, bodyLength, ordinal, 11) + '='.repeat(trailingEquals);
    }
    case 'numeric-string':
      return syntheticDigits(original.length, ordinal);
  }
}

/**
 * Integers with |value| <= NUMBER_KEEP_MAX are returned unchanged. Otherwise a
 * surrogate preserving sign, integer-ness, integer digit count and
 * decimal-place count. Throws for exponential notation or a non-finite value.
 */
export function numberSurrogate(value: number, ordinal: number): number {
  if (Number.isInteger(value) && Math.abs(value) <= NUMBER_KEEP_MAX) return value;
  const magnitudeText = String(Math.abs(value));
  if (!Number.isFinite(value) || /e/i.test(magnitudeText)) {
    throw new Error(`number at ordinal ${String(ordinal)} is not representable`);
  }
  const negative = value < 0;
  const parts = magnitudeText.split('.');
  const intPart = parts[0] ?? '';
  const decPart = parts[1] ?? '';
  const intDigits = protectEdgeZero(syntheticDigits(intPart.length, ordinal), 'leading');
  const decDigits =
    decPart.length > 0
      ? protectEdgeZero(syntheticDigits(decPart.length, ordinal + 97), 'trailing')
      : '';
  const literal = decDigits.length > 0 ? `${intDigits}.${decDigits}` : intDigits;
  const magnitude = Number(literal);
  return negative ? -magnitude : magnitude;
}

const TEXT_SURROGATE_FORM = /^TEXT_\d+$/;
const TOKEN_SURROGATE_FORM = /^TOKEN_\d+$/;
const KEY_SURROGATE_FORM = /^KEY_\d+$/;
const UUID_SURROGATE_FORM = /^00000000-0000-4000-8000-\d{12}$/;
const ISO_SURROGATE_FORM = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/;
const EMAIL_SURROGATE_FORM = /^user-\d+@example\.invalid$/;
const HOST_SURROGATE_FORM = /^host-\d+\.invalid$/;

/**
 * Whether `value` is a run `syntheticRun` could have produced: every
 * character is in `alphabet` and consecutive characters advance by `stride`
 * positions, which is exactly what `(seed + i * stride + 3) % length` does.
 */
function isSyntheticRun(value: string, alphabet: string, stride: number): boolean {
  if (value.length === 0) return false;
  let previous = alphabet.indexOf(value.charAt(0));
  if (previous < 0) return false;
  const step = stride % alphabet.length;
  for (let i = 1; i < value.length; i += 1) {
    const index = alphabet.indexOf(value.charAt(i));
    if (index < 0) return false;
    if ((index - previous + alphabet.length) % alphabet.length !== step) return false;
    previous = index;
  }
  return true;
}

/**
 * Whether `digits` is a run `syntheticDigits` could have produced. `nudged`
 * names the one edge `protectEdgeZero` is allowed to have rewritten to '1'.
 */
function isSyntheticDigits(digits: string, nudged: 'leading' | 'trailing' | 'none'): boolean {
  if (!/^\d+$/.test(digits)) return false;
  for (let i = 1; i < digits.length; i += 1) {
    const previous = digits.charCodeAt(i - 1) - 48;
    const current = digits.charCodeAt(i) - 48;
    if ((current - previous + 10) % 10 === 3) continue;
    if (nudged === 'leading' && i === 1 && digits.startsWith('1')) continue;
    if (nudged === 'trailing' && i === digits.length - 1 && digits.charAt(i) === '1') continue;
    return false;
  }
  return true;
}

/**
 * Whether `value` has the SHAPE of something this module emits.
 *
 * Derived from `surrogateFor`, `replaceKeyFallback` and `hostSurrogate`
 * rather than restated: the synthetic classes are arithmetic progressions
 * through a known alphabet, so a real identifier of the same length matches
 * with probability that falls off exponentially in its length.
 *
 * A shape check is NEVER a substitute for set membership — on its own it
 * would fail OPEN the moment a real id happened to look like one. It is a
 * tightening to layer ON TOP, so that a fixture cannot buy its way past a
 * membership check by declaring its own raw values as surrogates.
 */
export function looksLikeSurrogateString(value: string): boolean {
  if (TEXT_SURROGATE_FORM.test(value)) return true;
  if (TOKEN_SURROGATE_FORM.test(value)) return true;
  if (KEY_SURROGATE_FORM.test(value)) return true;
  if (UUID_SURROGATE_FORM.test(value)) return true;
  if (ISO_SURROGATE_FORM.test(value)) return true;
  if (EMAIL_SURROGATE_FORM.test(value)) return true;
  if (HOST_SURROGATE_FORM.test(value)) return true;
  const jwtSegments = value.split('.');
  if (
    jwtSegments.length === 3 &&
    jwtSegments.every((segment) => isSyntheticRun(segment, BASE64URL_CHARS, 13))
  ) {
    return true;
  }
  const trailingEquals = /=+$/.exec(value)?.[0].length ?? 0;
  const body = value.slice(0, value.length - trailingEquals);
  if (isSyntheticRun(body, ALNUM_CHARS, 11)) return true;
  if (trailingEquals > 0) return false;
  if (isSyntheticRun(value, HEX_CHARS, 7)) return true;
  // numeric-string surrogates carry no edge-zero protection: that applies
  // only to a NUMBER, whose digits round-trip through the JS number type.
  return isSyntheticDigits(value, 'none');
}

/** Whether `value` has the SHAPE `numberSurrogate` emits. See above on layering. */
export function looksLikeSurrogateNumber(value: number): boolean {
  if (!Number.isFinite(value)) return false;
  const magnitude = String(Math.abs(value));
  if (/e/i.test(magnitude)) return false;
  const parts = magnitude.split('.');
  const intPart = parts[0] ?? '';
  const decPart = parts[1];
  if (!isSyntheticDigits(intPart, 'leading')) return false;
  return decPart === undefined || isSyntheticDigits(decPart, 'trailing');
}

interface Bucket<K> {
  counter: number;
  assigned: Map<K, string>;
}

interface Context {
  approvedKeys: ReadonlySet<string>;
  approvedValues: ReadonlySet<string>;
  allowedHosts: ReadonlySet<string>;
  detect: Detect;
  leaves: number;
  stringAllocators: Map<SimpleValueClass, Bucket<string>>;
  keyAllocator: Bucket<string>;
  hostAllocator: Bucket<string>;
  numberAllocator: { counter: number; assigned: Map<number, number> };
  emittedStrings: Set<string>;
  emittedNumbers: Set<number>;
  // Strings the sanitiser deliberately wrote into the output that are NOT
  // surrogates: a host kept verbatim because it is allow-listed, and the
  // `<scheme>://` scaffolding a sanitised URL is rebuilt from. Preserved keys
  // and values join these at the end (they are already reported separately).
  // Together with `emittedStrings` this is the set the residue verifier
  // subtracts before deciding a run is a survival rather than an emission.
  accountedVerbatim: Set<string>;
  // Original values that were REPLACED (never those kept verbatim), each
  // mapped to the label the refusal may NAME — a class and an ordinal, never
  // the value itself.
  originalsAtRisk: Map<string, string>;
  report: {
    preservedKeys: string[];
    candidateKeys: string[];
    flaggedKeys: { ruleIds: string[] }[];
    preservedValues: string[];
    candidateValues: string[];
    flaggedValues: { ruleIds: string[] }[];
    replaced: Record<ValueClass, number>;
    smallIntegersKept: number;
    booleansKept: number;
  };
}

const IDENTITY_CLASSES: readonly SimpleValueClass[] = [
  'uuid',
  'jwt',
  'iso-datetime',
  'email',
  'hex',
  'base64ish',
  'numeric-string',
];

function newBucket<K>(): Bucket<K> {
  return { counter: 0, assigned: new Map<K, string>() };
}

function createContext(input: SanitizeInput): Context {
  const stringAllocators = new Map<SimpleValueClass, Bucket<string>>();
  const classes: SimpleValueClass[] = [
    'text',
    'vocabulary',
    'uuid',
    'jwt',
    'iso-datetime',
    'email',
    'hex',
    'base64ish',
    'numeric-string',
  ];
  for (const cls of classes) stringAllocators.set(cls, newBucket<string>());

  const replaced = {} as Record<ValueClass, number>;
  const allClasses: ValueClass[] = [...classes, 'url', 'empty'];
  for (const cls of allClasses) replaced[cls] = 0;

  return {
    approvedKeys: input.approvedKeys,
    approvedValues: input.approvedValues,
    allowedHosts: new Set(input.allowedHosts),
    detect: input.detect,
    leaves: 0,
    stringAllocators,
    keyAllocator: newBucket<string>(),
    hostAllocator: newBucket<string>(),
    numberAllocator: { counter: 0, assigned: new Map<number, number>() },
    emittedStrings: new Set<string>(),
    emittedNumbers: new Set<number>(),
    accountedVerbatim: new Set<string>(),
    originalsAtRisk: new Map<string, string>(),
    report: {
      preservedKeys: [],
      candidateKeys: [],
      flaggedKeys: [],
      preservedValues: [],
      candidateValues: [],
      flaggedValues: [],
      replaced,
      smallIntegersKept: 0,
      booleansKept: 0,
    },
  };
}

/**
 * `ctx.detect`, with an engine that could not answer turned into a run-level
 * refusal rather than a clean report. See src/sanitize/detector.ts for why the
 * real detector throws instead of returning no findings.
 */
function detect(ctx: Context, text: string): readonly string[] {
  try {
    return ctx.detect(text);
  } catch {
    throw new SanitizeAbort(
      'detector-unavailable',
      'the detection engine could not scan a value — refusing rather than reporting it clean',
    );
  }
}

function checkLeavesBudget(ctx: Context): void {
  ctx.leaves += 1;
  if (ctx.leaves > MAX_LEAVES) {
    throw new SanitizeAbort(
      'too-many-leaves',
      `input carries more than ${String(MAX_LEAVES)} leaves`,
    );
  }
}

function replaceAsClass(cls: SimpleValueClass, value: string, ctx: Context): string {
  ctx.report.replaced[cls] += 1;
  const bucket = ctx.stringAllocators.get(cls);
  if (bucket === undefined) throw new Error(`no allocator for class "${cls}"`);
  const existing = bucket.assigned.get(value);
  if (existing !== undefined) return existing;
  bucket.counter += 1;
  const surrogate = surrogateFor(cls, bucket.counter, value);
  bucket.assigned.set(value, surrogate);
  ctx.emittedStrings.add(surrogate);
  ctx.originalsAtRisk.set(value, `${cls} #${String(bucket.counter)}`);
  return surrogate;
}

function replaceKeyFallback(key: string, ctx: Context): string {
  const cls = classifyString(key);
  if ((IDENTITY_CLASSES as readonly ValueClass[]).includes(cls)) {
    return replaceAsClass(cls as SimpleValueClass, key, ctx);
  }
  const existing = ctx.keyAllocator.assigned.get(key);
  if (existing !== undefined) return existing;
  ctx.keyAllocator.counter += 1;
  const surrogate = `KEY_${String(ctx.keyAllocator.counter)}`;
  ctx.keyAllocator.assigned.set(key, surrogate);
  ctx.emittedStrings.add(surrogate);
  ctx.originalsAtRisk.set(key, `key #${String(ctx.keyAllocator.counter)}`);
  return surrogate;
}

function sanitizeKeyText(key: string, ctx: Context): string {
  if (isPreservableKey(key)) {
    const findings = detect(ctx, key);
    if (findings.length > 0) {
      ctx.report.flaggedKeys.push({ ruleIds: [...findings] });
      return replaceKeyFallback(key, ctx);
    }
    if (ctx.approvedKeys.has(key)) {
      ctx.report.preservedKeys.push(key);
      return key;
    }
    ctx.report.candidateKeys.push(key);
    return replaceKeyFallback(key, ctx);
  }
  return replaceKeyFallback(key, ctx);
}

function sanitizeOrdinaryString(value: string, ctx: Context): string {
  const cls = classifyString(value);
  if (cls === 'empty') return '';
  if (cls === 'vocabulary' && isVocabularyCandidate(value)) {
    const findings = detect(ctx, value);
    if (findings.length > 0) {
      ctx.report.flaggedValues.push({ ruleIds: [...findings] });
      return replaceAsClass('vocabulary', value, ctx);
    }
    if (ctx.approvedValues.has(value)) {
      ctx.report.preservedValues.push(value);
      return value;
    }
    ctx.report.candidateValues.push(value);
    return replaceAsClass('vocabulary', value, ctx);
  }
  if (cls === 'vocabulary') return replaceAsClass('vocabulary', value, ctx);
  if (cls === 'url') {
    try {
      return sanitizeUrl(value, ctx);
    } catch {
      // classifyString already proved this parses as a URL, so this is not
      // expected to be reached — but a body value is never worth aborting the
      // whole run over, so it falls back to an ordinary text replacement.
      return replaceAsClass('text', value, ctx);
    }
  }
  return replaceAsClass(cls, value, ctx);
}

/** Try to read `value` as nested JSON. `undefined` unless it is an object/array. */
function tryParseNestedJson(value: string): unknown {
  const trimmed = value.trim();
  if (trimmed.length === 0) return undefined;
  const first = trimmed[0];
  if (first !== '{' && first !== '[') return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return undefined;
  }
  if (parsed !== null && typeof parsed === 'object') return parsed;
  return undefined;
}

function sanitizeStringLeaf(value: string, depth: number, ctx: Context): string {
  const nested = tryParseNestedJson(value);
  if (nested !== undefined) {
    try {
      const sanitizedNested = sanitizeValue(nested, depth + 1, ctx);
      return JSON.stringify(sanitizedNested);
    } catch (err) {
      if (err instanceof SanitizeAbort) throw err;
      return replaceAsClass('text', value, ctx);
    }
  }
  return sanitizeOrdinaryString(value, ctx);
}

// `JSON.stringify` is typed as always returning `string`, but at runtime it
// returns `undefined` for a value with no JSON representation (`undefined`
// itself, a function, a symbol) — a real case here, since this is the
// fallback for a value none of sanitizeValue's other branches recognised.
function stringifyForSurrogate(value: unknown): string | undefined {
  return JSON.stringify(value);
}

function textSurrogateForValue(value: unknown, ctx: Context): string {
  let rendered: string;
  try {
    rendered = stringifyForSurrogate(value) ?? 'null';
  } catch {
    rendered = String(value);
  }
  return replaceAsClass('text', rendered, ctx);
}

function sanitizeNumber(value: number, ctx: Context): number {
  if (Number.isInteger(value) && Math.abs(value) <= NUMBER_KEEP_MAX) {
    ctx.report.smallIntegersKept += 1;
    return value;
  }
  const existing = ctx.numberAllocator.assigned.get(value);
  if (existing !== undefined) return existing;
  ctx.numberAllocator.counter += 1;
  const ordinal = ctx.numberAllocator.counter;
  let surrogate: number;
  try {
    surrogate = numberSurrogate(value, ordinal);
  } catch {
    throw new SanitizeAbort(
      'unrepresentable-number',
      `a number at ordinal ${String(ordinal)} is not representable (exponential or non-finite)`,
    );
  }
  ctx.numberAllocator.assigned.set(value, surrogate);
  ctx.emittedNumbers.add(surrogate);
  return surrogate;
}

function sanitizeValue(value: unknown, depth: number, ctx: Context): unknown {
  if (depth > MAX_DEPTH) {
    checkLeavesBudget(ctx);
    return textSurrogateForValue(value, ctx);
  }
  if (value === null) return null;
  if (typeof value === 'boolean') {
    ctx.report.booleansKept += 1;
    return value;
  }
  if (typeof value === 'number') {
    checkLeavesBudget(ctx);
    return sanitizeNumber(value, ctx);
  }
  if (typeof value === 'string') {
    checkLeavesBudget(ctx);
    return sanitizeStringLeaf(value, depth, ctx);
  }
  if (Array.isArray(value)) {
    return value.map((v) => sanitizeValue(v, depth + 1, ctx));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      const newKey = sanitizeKeyText(key, ctx);
      out[newKey] = sanitizeValue((value as Record<string, unknown>)[key], depth + 1, ctx);
    }
    return out;
  }
  checkLeavesBudget(ctx);
  return textSurrogateForValue(value, ctx);
}

// A top-level HAR or a headers/cookies dump — refused rather than sanitised,
// since the fixture format carries no field for headers and nothing reads
// them. Top-level only: a nested `headers` key inside a body is an ordinary
// object and is walked like any other.
function checkEnvelopeGuard(parsed: unknown): void {
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return;
  const obj = parsed as Record<string, unknown>;
  const log = obj.log;
  if (log !== null && typeof log === 'object' && !Array.isArray(log) && 'entries' in log) {
    throw new SanitizeAbort(
      'envelope-not-a-body',
      'input looks like a HAR (top-level log.entries) — extract the request/response body instead',
    );
  }
  for (const key of ['headers', 'requestHeaders', 'responseHeaders', 'cookies']) {
    if (key in obj) {
      throw new SanitizeAbort(
        'envelope-not-a-body',
        `input carries a top-level "${key}" key — extract the body rather than pasting headers`,
      );
    }
  }
}

function sanitizeUrlComponent(value: string, ctx: Context): string {
  return sanitizeOrdinaryString(value, ctx);
}

function hostSurrogate(ctx: Context, host: string): string {
  const existing = ctx.hostAllocator.assigned.get(host);
  if (existing !== undefined) return existing;
  ctx.hostAllocator.counter += 1;
  const surrogate = `host-${String(ctx.hostAllocator.counter)}.invalid`;
  ctx.hostAllocator.assigned.set(host, surrogate);
  ctx.emittedStrings.add(surrogate);
  ctx.originalsAtRisk.set(host, `host #${String(ctx.hostAllocator.counter)}`);
  return surrogate;
}

function sanitizeUrl(rawUrl: string, ctx: Context): string {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SanitizeAbort('unparseable-url', 'url does not parse as an absolute URL');
  }

  let host: string;
  if (ctx.allowedHosts.has(parsed.hostname)) {
    host = parsed.hostname;
    // Kept verbatim on purpose, so the residue verifier must not read it back
    // as an original that survived — a body value merely CONTAINING an allowed
    // host would otherwise refuse the whole run.
    ctx.accountedVerbatim.add(parsed.hostname);
  } else {
    host = hostSurrogate(ctx, parsed.hostname);
  }
  // The scheme scaffolding is rebuilt rather than carried, and `https://` is
  // itself RESIDUE_RUN characters long — so any replaced prose leaf that
  // merely mentions a URL would collide with it.
  ctx.accountedVerbatim.add(`${parsed.protocol}//`);

  const segments = parsed.pathname.split('/');
  const pathOut = segments
    .map((segment) => (segment.length === 0 ? '' : sanitizeUrlComponent(segment, ctx)))
    .join('/');

  const outParams = new URLSearchParams();
  for (const [key, value] of parsed.searchParams.entries()) {
    const newKey = sanitizeKeyText(key, ctx);
    const newValue = sanitizeUrlComponent(value, ctx);
    outParams.append(newKey, newValue);
  }
  const paramList = [...outParams];
  const searchOut = paramList.length > 0 ? `?${outParams.toString()}` : '';

  const fragment = parsed.hash.length > 1 ? parsed.hash.slice(1) : '';
  const hashOut = fragment.length > 0 ? `#${sanitizeUrlComponent(fragment, ctx)}` : '';

  return `${parsed.protocol}//${host}${pathOut}${searchOut}${hashOut}`;
}

function sanitizeJsonText(raw: string, ctx: Context): string {
  const parsed: unknown = JSON.parse(raw);
  checkEnvelopeGuard(parsed);
  const sanitized = sanitizeValue(parsed, 0, ctx);
  return JSON.stringify(sanitized);
}

function sanitizeUrlEncodedBody(raw: string, ctx: Context): string {
  const params = new URLSearchParams(raw);
  const out = new URLSearchParams();
  for (const [key, value] of params.entries()) {
    checkLeavesBudget(ctx);
    const newKey = sanitizeKeyText(key, ctx);
    const newValue = sanitizeStringLeaf(value, 0, ctx);
    out.append(newKey, newValue);
  }
  return out.toString();
}

function sanitizeSseEvent(eventText: string, ctx: Context): string {
  const lines = eventText.split('\n');
  const outLines: string[] = [];
  const dataLines: string[] = [];
  for (const line of lines) {
    if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).replace(/^ /, ''));
      continue;
    }
    const colonIndex = line.indexOf(':');
    if (
      colonIndex > 0 &&
      (line.startsWith('event:') || line.startsWith('id:') || line.startsWith('retry:'))
    ) {
      const field = line.slice(0, colonIndex);
      const value = line.slice(colonIndex + 1).replace(/^ /, '');
      checkLeavesBudget(ctx);
      outLines.push(`${field}: ${sanitizeStringLeaf(value, 0, ctx)}`);
      continue;
    }
    if (line.trim().length > 0) {
      checkLeavesBudget(ctx);
      outLines.push(sanitizeStringLeaf(line, 0, ctx));
    }
  }
  if (dataLines.length > 0) {
    const joined = dataLines.join('\n');
    let parsed: unknown;
    let isJsonBody: boolean;
    try {
      parsed = JSON.parse(joined);
      isJsonBody = typeof parsed === 'object';
    } catch {
      isJsonBody = false;
    }
    const dataOut = isJsonBody
      ? JSON.stringify(sanitizeValue(parsed, 1, ctx))
      : sanitizeStringLeaf(joined, 0, ctx);
    outLines.push(`data: ${dataOut}`);
  }
  return outLines.join('\n');
}

function sanitizeSse(raw: string, ctx: Context): string[] {
  const events = raw
    .split(/\n\n+/)
    .map((e) => e.trim())
    .filter((e) => e.length > 0);
  return events.map((eventText) => `${sanitizeSseEvent(eventText, ctx)}\n\n`);
}

function buildChunks(input: SanitizeInput, ctx: Context): string[] {
  switch (input.format) {
    case 'json':
      return [sanitizeJsonText(input.raw, ctx)];
    case 'urlencoded':
      return [sanitizeUrlEncodedBody(input.raw, ctx)];
    case 'sse':
      return sanitizeSse(input.raw, ctx);
    case 'ndjson': {
      const lines = input.raw.split('\n').filter((l) => l.trim().length > 0);
      return lines.map((line) => {
        let parsed: unknown;
        try {
          parsed = JSON.parse(line);
        } catch {
          checkLeavesBudget(ctx);
          return sanitizeStringLeaf(line, 0, ctx);
        }
        return JSON.stringify(sanitizeValue(parsed, 0, ctx));
      });
    }
    case 'text':
      checkLeavesBudget(ctx);
      return [sanitizeStringLeaf(input.raw, 0, ctx)];
  }
}

function buildReport(ctx: Context): SanitizeReport {
  return {
    preservedKeys: [...ctx.report.preservedKeys],
    candidateKeys: [...ctx.report.candidateKeys],
    flaggedKeys: ctx.report.flaggedKeys.map((f) => ({ ruleIds: [...f.ruleIds] })),
    preservedValues: [...ctx.report.preservedValues],
    candidateValues: [...ctx.report.candidateValues],
    flaggedValues: ctx.report.flaggedValues.map((f) => ({ ruleIds: [...f.ruleIds] })),
    replaced: { ...ctx.report.replaced },
    smallIntegersKept: ctx.report.smallIntegersKept,
    booleansKept: ctx.report.booleansKept,
    leaves: ctx.leaves,
  };
}

// Characters that carry no information about a discarded value's CONTENT — pure
// JSON syntax and whitespace. A subtree past MAX_DEPTH is discarded as one raw
// JSON.stringify() dump (see textSurrogateForValue), so its own closing-brace
// tail is exactly as long as its own nesting depth — and any sufficiently deep,
// legitimately-sanitized document reproduces the SAME run of punctuation on its
// own account. An 8-character window drawn entirely from this set is therefore
// guaranteed to recur across unrelated documents and is never itself a
// disclosure, so the residue check skips it rather than treating every deeply
// nested JSON payload as a self-inflicted leak.
const STRUCTURAL_RUN_CHARS = new Set(['{', '}', '[', ']', '"', ':', ',', ' ', '\t', '\n', '\r']);

function isStructuralRun(run: string): boolean {
  for (const ch of run) {
    if (!STRUCTURAL_RUN_CHARS.has(ch)) return false;
  }
  return true;
}

/** One surviving original, named by class and ordinal — never by its value. */
export interface ResidueFinding {
  /** e.g. `vocabulary #3`, `key #1`, `host #2`. */
  readonly label: string;
  /** Which part of the output it was found in, e.g. `chunks[0]` or `url`. */
  readonly where: string;
}

// Characters a sanitised output is JOINED with rather than filled with: JSON
// punctuation plus the separators a rebuilt URL carries. A window covering
// only these and material the sanitiser emitted is scaffolding, never a
// survival. `.` and `-` are deliberately absent — they occur inside real
// values, and nothing here needs them to classify a boundary.
const COVERAGE_FILLER = new Set([...STRUCTURAL_RUN_CHARS, '/', '?', '&', '=', '#']);

/**
 * Which characters of `text` the sanitiser can account for: every position
 * inside an occurrence of a string it emitted, plus every joining character.
 *
 * Positions rather than a set of substrings, because a run straddles them: the
 * host `chatgpt.com` and the path surrogate after it are both accounted, and
 * the eight characters `gpt.com/` that span the two are accounted only if the
 * question is asked per position.
 */
function accountedCoverage(text: string, accounted: readonly string[]): Uint8Array {
  const covered = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) {
    if (COVERAGE_FILLER.has(text.charAt(i))) covered[i] = 1;
  }
  const byLength = new Map<number, Set<string>>();
  const firstChars = new Set<string>();
  for (const token of accounted) {
    if (token.length === 0) continue;
    let bucket = byLength.get(token.length);
    if (bucket === undefined) {
      bucket = new Set<string>();
      byLength.set(token.length, bucket);
    }
    bucket.add(token);
    firstChars.add(token.charAt(0));
  }
  const lengths = [...byLength.keys()];
  for (let i = 0; i < text.length; i += 1) {
    if (!firstChars.has(text.charAt(i))) continue;
    for (const length of lengths) {
      if (i + length > text.length) continue;
      if (byLength.get(length)?.has(text.slice(i, i + length)) !== true) continue;
      for (let j = i; j < i + length; j += 1) covered[j] = 1;
    }
  }
  return covered;
}

/** True when every character of `text[at, at+length)` is accounted for. */
function fullyCovered(covered: Uint8Array, at: number, length: number): boolean {
  for (let i = at; i < at + length; i += 1) {
    if (covered[i] !== 1) return false;
  }
  return true;
}

/** Whether `run` occurs in `text` anywhere the sanitiser cannot account for it. */
function occursUnaccounted(text: string, covered: Uint8Array, run: string): boolean {
  let from = text.indexOf(run);
  while (from !== -1) {
    if (!fullyCovered(covered, from, run.length)) return true;
    from = text.indexOf(run, from + 1);
  }
  return false;
}

/**
 * The last backstop: no RESIDUE_RUN-character run of a REPLACED original may
 * survive into the sanitised output.
 *
 * Two things about the haystack are load-bearing, and getting either wrong
 * refuses the exact traffic this tool exists to process.
 *
 * It is the CAPTURE-DERIVED output only — the sanitised chunks and the
 * sanitised url — never the envelope. `site`, `kind`, `direction`, `format`
 * and `$schema` are chosen by the operator on the command line, not extracted
 * from the capture, so they can disclose nothing; searching them means the
 * path segment `conversation` collides with the literal `"kind":
 * "conversation"` and every canonical capture refuses.
 *
 * And a run the sanitiser ITSELF emitted is not a survival. `accounted` is
 * every surrogate, every approved key and value kept verbatim, every
 * allow-listed host and the url's own scheme scaffolding; a match landing
 * entirely on those (or on the punctuation joining them) is skipped. Without
 * that the fixed uuid surrogate (`00000000-…`) refuses any original carrying
 * an eight-zero run, an allow-listed host refuses any body value that
 * mentions it, and `https://` refuses any prose that quotes a link.
 *
 * The direction of error is still over-refusal — a match is skipped only
 * where every one of its characters is sanitiser-emitted — but the
 * over-refusals above are the ones with no workaround, so they are the ones
 * that had to go.
 *
 * Chunks are themselves JSON text, so a leaked value carrying a quote,
 * backslash or control character appears there ESCAPED; each run is searched
 * in both forms.
 */
export function findResidueRun(
  parts: readonly { readonly where: string; readonly text: string }[],
  originals: ReadonlyMap<string, string>,
  accounted: Iterable<string>,
): ResidueFinding | null {
  const tokens = [...accounted];
  const scanned = parts.map((part) => ({
    ...part,
    covered: accountedCoverage(part.text, tokens),
  }));
  for (const [original, label] of originals) {
    if (original.length < RESIDUE_RUN) continue;
    for (let i = 0; i + RESIDUE_RUN <= original.length; i += 1) {
      const run = original.slice(i, i + RESIDUE_RUN);
      if (isStructuralRun(run)) continue;
      const escaped = JSON.stringify(run).slice(1, -1);
      for (const part of scanned) {
        if (
          occursUnaccounted(part.text, part.covered, run) ||
          (escaped !== run && occursUnaccounted(part.text, part.covered, escaped))
        ) {
          return { label, where: part.where };
        }
      }
    }
  }
  return null;
}

function refuse(
  refusal: SanitizeRefusal,
  error: string,
  report: SanitizeReport | null,
): SanitizeResult {
  return { ok: false, refusal, error, report };
}

export function sanitizeCapture(input: SanitizeInput): SanitizeResult {
  if (exceedsBytes(input.raw, MAX_INPUT_BYTES)) {
    return refuse('input-too-large', `input exceeds ${String(MAX_INPUT_BYTES)} bytes`, null);
  }

  const ctx = createContext(input);

  let sanitizedUrl: string;
  try {
    sanitizedUrl = sanitizeUrl(input.url, ctx);
  } catch (err) {
    if (err instanceof SanitizeAbort) return refuse(err.refusal, err.message, null);
    return refuse('unparseable-url', 'url does not parse as an absolute URL', null);
  }

  let chunks: string[];
  try {
    chunks = buildChunks(input, ctx);
  } catch (err) {
    if (err instanceof SanitizeAbort) return refuse(err.refusal, err.message, buildReport(ctx));
    return refuse('unparseable-input', `input does not parse as ${input.format}`, null);
  }

  const fixture: FixtureEnvelope = {
    $schema: FIXTURE_SCHEMA_ID,
    site: input.site,
    kind: input.kind,
    direction: input.direction,
    url: sanitizedUrl,
    format: input.format,
    chunks,
    surrogates: {
      strings: [...ctx.emittedStrings].sort(),
      numbers: [...ctx.emittedNumbers].sort((a, b) => a - b),
    },
  };
  const text = `${JSON.stringify(fixture, null, 2)}\n`;

  const residue = findResidueRun(
    [
      ...chunks.map((chunk, i) => ({ where: `chunks[${String(i)}]`, text: chunk })),
      { where: 'url', text: sanitizedUrl },
    ],
    ctx.originalsAtRisk,
    [
      ...ctx.emittedStrings,
      ...ctx.accountedVerbatim,
      ...ctx.report.preservedKeys,
      ...ctx.report.preservedValues,
    ],
  );
  if (residue !== null) {
    return refuse(
      'residue-run',
      // Names the class and ordinal so the operator knows WHICH replacement
      // failed and can find it in the survey — never the value, which is the
      // thing this whole run exists to keep out of anything a human reads.
      `sanitized ${residue.where} still contains a ${String(RESIDUE_RUN)}-character run of ` +
        `a replaced original (${residue.label}); this is a sanitiser defect, not an approval gap`,
      buildReport(ctx),
    );
  }

  let residueFindings: readonly string[];
  try {
    residueFindings = input.detect(text);
  } catch {
    return refuse(
      'detector-unavailable',
      'the detection engine could not scan the sanitized output — refusing rather than reporting it clean',
      buildReport(ctx),
    );
  }
  if (residueFindings.length > 0) {
    return refuse(
      'residue-detected',
      `sanitized output was flagged by the detector (${residueFindings.join(', ')})`,
      buildReport(ctx),
    );
  }

  return { ok: true, fixture, text, report: buildReport(ctx) };
}
