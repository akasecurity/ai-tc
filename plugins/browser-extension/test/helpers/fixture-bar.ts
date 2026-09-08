// The fixture bar's shared constants, message wording and validators — one
// file, so the number a reader quotes ("EXPECTED_DECLARING_ADAPTERS") and the
// suite that enforces it can never drift apart. This is a helper, not a
// suite: its own behaviour is pinned by fixture-bar.test.ts.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { SOURCE_TOOL } from '@akasecurity/schema';

import type { WebSourceTool } from '../../src/native-host/protocol.ts';
import { isPreservableKey, isVocabularyCandidate } from '../../src/sanitize/classify.ts';
import type { Detect, FixtureEnvelope } from '../../src/sanitize/sanitize-capture.ts';
import {
  FIXTURE_SCHEMA_ID,
  looksLikeSurrogateNumber,
  looksLikeSurrogateString,
  NUMBER_KEEP_MAX,
} from '../../src/sanitize/sanitize-capture.ts';

export const FIXTURE_ROOT = fileURLToPath(new URL('../fixtures', import.meta.url));
export const REQUEST_FIXTURE = 'request.json';
export const STREAM_FIXTURE = 'stream.json';
export const ACCOUNT_FIXTURE = 'account.json';
export const APPROVED_KEYS_FILE = 'approved-keys.txt';
export const APPROVED_VALUES_FILE = 'approved-values.txt';

/** The fewest chunks a conversation STREAM fixture may carry. See the doc below. */
export const MIN_STREAM_CHUNKS = 2;

/**
 * The adapters that declare at least one endpoint, pinned EXACTLY — empty
 * today.
 *
 * A reported count changes nothing when it changes: it prints, CI stays
 * green, and the day somebody declares a guessed endpoint the reviewer sees
 * the same green tick this whole task exists to prevent. An exact pinned set
 * is a ratchet in both directions, the same shape this repo already uses for
 * `DOCUMENTED_OPT_OUTS`, `EXPECTED_INLINE_DISABLES` and
 * `GRANDFATHERED_PLATFORM_GUARDS`: declaring an endpoint reds the suite until
 * the author adds the adapter here and ships its fixtures, and REMOVING a
 * declaration reds it too, so the fixtures cannot quietly stop being
 * required once they exist. Never widen this to make a red suite quiet —
 * ship the fixtures instead.
 */
export const EXPECTED_DECLARING_ADAPTERS: readonly WebSourceTool[] = [];

/**
 * Every protocol token an adapter declares, pinned EXACTLY — empty arrays for
 * both sites today.
 *
 * Same shape and same reason as `EXPECTED_DECLARING_ADAPTERS`: a ratchet in
 * both directions. A token added to `ProviderAdapter.protocolTokens` reds
 * this suite until the author lists it here too, and a token REMOVED from an
 * adapter reds it just the same, so the pin cannot silently drift out of step
 * with what the adapter really declares in either direction. Never widen this
 * to quiet a red suite — update the adapter's own declaration and this pin
 * together, in the same diff.
 *
 * Annotated `Record<WebSourceTool, …>` rather than a partial map so a third
 * web tool added to the vocabulary fails to compile here until someone names
 * it (CLAUDE.md §2). Keyed by computed member (`[SOURCE_TOOL.ClaudeAi]`)
 * rather than a literal, per the same section.
 *
 * WHAT A DIFF HERE IS AGREEING TO, measured against the real engine so the
 * reviewer does not have to derive it. `isDeclarableToken` admits any run of
 * 1–40 characters from the vocabulary charset that classifies 'vocabulary'
 * or 'base64ish' — which for a run of 16 or more is every base64URL string
 * (`=` is outside the charset, so padded base64 is not reachable). The
 * detector is the only automated gate on the class, and it catches a PREFIXED
 * credential shape and not an unprefixed one: measured,
 * `pk_live_wDlmi91dAAKCRu1JBy89Xaq3RZ` is flagged `secrets/stripe-live-key`,
 * while a 32-character opaque run of the same charset returns no findings at
 * all. So a declaration is bounded — never a message body, a prompt, a URL, a
 * uuid or a full name — but a session-token-shaped string is inside the
 * bound, and nothing that inspects a string alone can tell one from a
 * `case` label. Two things are what actually keep a declaration honest: this
 * pin's diff, and PT6's requirement that the token appear in the adapter's
 * own parsing source, which a value pasted out of a capture cannot satisfy.
 */
export const EXPECTED_PROTOCOL_TOKENS: Readonly<Record<WebSourceTool, readonly string[]>> = {
  [SOURCE_TOOL.ChatGpt]: [],
  [SOURCE_TOOL.ClaudeAi]: [],
};

export interface Approvals {
  readonly keys: ReadonlySet<string>;
  readonly values: ReadonlySet<string>;
}

/** What a fixture is judged against beyond its own contents. */
export interface FixtureBarOptions {
  /** The declaring adapter's own hostnames — the only hosts a url may name verbatim. */
  readonly allowedHosts: readonly string[];
  /**
   * REQUIRED, and for the same reason `SanitizeInput.detect` is: a default
   * reads as safe at every call site that omits it. The bar re-runs the real
   * engine over the COMMITTED artifact, so a fixture that cleared the packs
   * as they stood the day it was produced is re-judged as they stand today.
   */
  readonly detect: Detect;
  /**
   * The declaring adapter's own `protocolTokens` — REQUIRED, same reason as
   * `detect`. Unioned into the bar's allowed VALUES only (never keys): a
   * fixture the tool produced with this declaration must pass the bar judged
   * against the SAME declaration, or the tool's own honest output fails its
   * own bar.
   */
  readonly protocolTokens: ReadonlySet<string>;
}

const VALID_KINDS = new Set(['conversation', 'account']);
const VALID_DIRECTIONS = new Set(['request', 'response']);
const VALID_FORMATS = new Set(['json', 'sse', 'ndjson', 'urlencoded', 'text']);

export function fixtureDir(site: WebSourceTool): string {
  return path.join(FIXTURE_ROOT, site);
}

export function fixtureExists(site: WebSourceTool, file: string): boolean {
  return existsSync(path.join(fixtureDir(site), file));
}

/**
 * The artifacts a site owes given the endpoint kinds it declares, and which
 * of them are absent.
 *
 * One implementation, so the per-adapter block below and the synthetic case
 * that drives it TODAY run the same code. With the declaring set empty, the
 * per-adapter block generates no test at all — a bar nothing exercises is a
 * bar nobody has seen fire, which is the shape this whole file exists to
 * avoid.
 */
export function missingFixtures(
  site: WebSourceTool,
  conversationEndpointCount: number,
  accountEndpointCount: number,
): string[] {
  const missing: string[] = [];
  if (conversationEndpointCount > 0) {
    if (!fixtureExists(site, REQUEST_FIXTURE)) missing.push(`${site}/${REQUEST_FIXTURE}`);
    if (!fixtureExists(site, STREAM_FIXTURE)) missing.push(`${site}/${STREAM_FIXTURE}`);
  }
  const accountFixturePresent = fixtureExists(site, ACCOUNT_FIXTURE);
  if (accountEndpointCount > 0 && !accountFixturePresent) {
    missing.push(`${site}/${ACCOUNT_FIXTURE}`);
  }
  if (accountEndpointCount === 0 && accountFixturePresent) {
    missing.push(`${site}/${ACCOUNT_FIXTURE} must be ABSENT (no account endpoint declared)`);
  }
  if (!fixtureExists(site, APPROVED_KEYS_FILE)) missing.push(`${site}/${APPROVED_KEYS_FILE}`);
  if (!fixtureExists(site, APPROVED_VALUES_FILE)) missing.push(`${site}/${APPROVED_VALUES_FILE}`);
  return missing;
}

function parseApprovalFile(filePath: string): ReadonlySet<string> {
  if (!existsSync(filePath)) return new Set();
  const lines = readFileSync(filePath, 'utf8').split('\n');
  const out = new Set<string>();
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith('#')) continue;
    out.add(line);
  }
  return out;
}

export function loadApprovals(site: WebSourceTool): Approvals {
  return {
    keys: parseApprovalFile(path.join(fixtureDir(site), APPROVED_KEYS_FILE)),
    values: parseApprovalFile(path.join(fixtureDir(site), APPROVED_VALUES_FILE)),
  };
}

export function loadFixture(site: WebSourceTool, file: string): FixtureEnvelope {
  const text = readFileSync(path.join(fixtureDir(site), file), 'utf8');
  const parsed: unknown = JSON.parse(text);
  assertValidFixture(`${site}/${file}`, parsed);
  return parsed;
}

/**
 * Every entry of an approvals file must be something the SANITISER would have
 * been willing to preserve, and must be clean under the detector.
 *
 * Without this the approvals files are an unbounded hole in the bar: they are
 * unioned into the allowed set on nothing but their presence, so pasting an
 * unpruned `--survey` output — raw candidate strings lifted straight out of a
 * real capture — makes every one of them legal. The tool's own predicates are
 * the right judge, because a value the sanitiser would never emit verbatim
 * has no business being accepted in a file that claims it did.
 *
 * The failure NAMES the entry, which is safe only because an entry that fails
 * this check is by construction one the sanitiser refused to preserve — it is
 * quoted here so the operator can find and delete the line.
 */
export function assertApprovalsAreApprovable(
  where: string,
  approvals: Approvals,
  detect: Detect,
): void {
  for (const key of approvals.keys) {
    if (!isPreservableKey(key)) {
      throw new Error(
        `${where}: ${APPROVED_KEYS_FILE} lists a key the sanitiser would never preserve: ${JSON.stringify(key)}`,
      );
    }
    const findings = detect(key);
    if (findings.length > 0) {
      throw new Error(
        `${where}: ${APPROVED_KEYS_FILE} lists a key the detector flags (${findings.join(', ')})`,
      );
    }
  }
  for (const value of approvals.values) {
    if (!isVocabularyCandidate(value)) {
      throw new Error(
        `${where}: ${APPROVED_VALUES_FILE} lists a value the sanitiser would never preserve: ${JSON.stringify(value)}`,
      );
    }
    const findings = detect(value);
    if (findings.length > 0) {
      throw new Error(
        `${where}: ${APPROVED_VALUES_FILE} lists a value the detector flags (${findings.join(', ')})`,
      );
    }
  }
}

/**
 * Every declared protocol token must be clean under the REAL detection
 * engine, failing with the flagged rule ids — never the token itself.
 *
 * Without this, a declaration the engine flags is merely replaced at
 * sanitise time (the detector still gates, per `sanitizeOrdinaryString`) and
 * the author finds out only when a real capture's replay looks wrong. This
 * catches it at review time instead, against the packs as they stand today —
 * not as they stood when the token was declared.
 */
export function assertDeclarationsAreDetectorClean(
  site: string,
  tokens: readonly string[],
  detect: Detect,
): void {
  for (const token of tokens) {
    const findings = detect(token);
    if (findings.length > 0) {
      throw new Error(
        `${site}: a declared protocol token is flagged by the detector (${findings.join(', ')})`,
      );
    }
  }
}

/**
 * Where each adapter's own implementation lives, relative to src/providers/.
 *
 * An adapter's id is not its filename (`claude-ai` -> claude.ts), so the pair
 * is written down rather than derived. `Record<WebSourceTool, …>` for the
 * same reason `EXPECTED_PROTOCOL_TOKENS` is: a third web tool fails to
 * compile here until someone names its file, rather than silently reading
 * nobody's source and passing.
 */
export const ADAPTER_SOURCE: Readonly<Record<WebSourceTool, string>> = {
  [SOURCE_TOOL.ChatGpt]: 'chatgpt.ts',
  [SOURCE_TOOL.ClaudeAi]: 'claude.ts',
};

/** The declaring adapter's own source text, read off disk. */
export function adapterSource(site: WebSourceTool): string {
  return readFileSync(
    path.join(fileURLToPath(new URL('../../src/providers', import.meta.url)), ADAPTER_SOURCE[site]),
    'utf8',
  );
}

// A single- or double-quoted occurrence of `token` in TypeScript source.
// Backticks are excluded on purpose: this package writes code spans in doc
// comments as `` `content_block_delta` ``, so counting them would let a
// mention in the prose above a declaration stand in for a use in the code
// below it.
function quotedOccurrences(source: string, token: string): number {
  let count = 0;
  for (const quote of ["'", '"']) {
    const needle = `${quote}${token}${quote}`;
    let from = 0;
    for (;;) {
      const at = source.indexOf(needle, from);
      if (at === -1) break;
      count += 1;
      from = at + needle.length;
    }
  }
  return count;
}

/**
 * Every declared protocol token must appear as a quoted string literal in the
 * declaring adapter's own source at least TWICE — once in `protocolTokens`
 * itself, and once more somewhere the parsers can reach it.
 *
 * `ProviderAdapter.protocolTokens` describes itself as the strings the
 * adapter's parsers switch on, and nothing but review was holding that: the
 * array is a plain `readonly string[]`, so a value lifted straight out of a
 * capture clears `isDeclarableToken`, is detector-clean, and survives
 * verbatim. Requiring a SECOND occurrence in the same file is the structural
 * half — a token that must also be written into the dispatch cannot be a
 * pasted capture value, because pasting it twice is a deliberate act a
 * reviewer reads as one.
 *
 * The count is 2 rather than 1 because the declaration itself is in that
 * file, so a one-occurrence bar would be satisfied by the declaration alone
 * and would assert nothing. PT1's distinctness assertion is what stops the
 * second occurrence being a duplicate entry in the same array.
 *
 * What this does NOT reach: an occurrence inside a single-quoted comment,
 * which is indistinguishable from code without parsing. It is a ratchet on
 * the cheapest way to get this wrong, not a proof the parser reads the token.
 */
export function assertDeclarationsAppearInSource(
  site: string,
  tokens: readonly string[],
  source: string,
): void {
  for (const token of tokens) {
    const count = quotedOccurrences(source, token);
    if (count < 2) {
      throw new Error(
        `${site}: a declared protocol token appears ${String(count)} time(s) as a quoted ` +
          `literal in the adapter's own source; it must appear at least twice — once in ` +
          `protocolTokens and once where a parser reads it`,
      );
    }
  }
}

/** Validates the envelope's own shape. Never inspects what the strings/numbers ARE. */
export function assertValidFixture(
  where: string,
  value: unknown,
): asserts value is FixtureEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${where}: fixture must be a JSON object`);
  }
  const obj = value as Record<string, unknown>;

  if (obj.$schema !== FIXTURE_SCHEMA_ID) {
    throw new Error(
      `${where}: $schema must be "${FIXTURE_SCHEMA_ID}", got ${JSON.stringify(obj.$schema)}`,
    );
  }
  if (typeof obj.site !== 'string' || obj.site.length === 0) {
    throw new Error(`${where}: site must be a non-empty string`);
  }
  if (typeof obj.kind !== 'string' || !VALID_KINDS.has(obj.kind)) {
    throw new Error(`${where}: kind must be one of ${[...VALID_KINDS].join('/')}`);
  }
  if (typeof obj.direction !== 'string' || !VALID_DIRECTIONS.has(obj.direction)) {
    throw new Error(`${where}: direction must be one of ${[...VALID_DIRECTIONS].join('/')}`);
  }
  if (typeof obj.format !== 'string' || !VALID_FORMATS.has(obj.format)) {
    throw new Error(`${where}: format must be one of ${[...VALID_FORMATS].join('/')}`);
  }
  if (typeof obj.url !== 'string') {
    throw new Error(`${where}: url must be a string`);
  }
  try {
    new URL(obj.url);
  } catch {
    throw new Error(`${where}: url does not parse as an absolute URL`);
  }

  if (!Array.isArray(obj.chunks) || obj.chunks.length === 0) {
    throw new Error(`${where}: chunks must be a non-empty array`);
  }
  for (const [i, chunk] of obj.chunks.entries()) {
    if (typeof chunk !== 'string') {
      throw new Error(`${where}: chunks[${String(i)}] must be a string`);
    }
  }

  if (
    typeof obj.surrogates !== 'object' ||
    obj.surrogates === null ||
    Array.isArray(obj.surrogates)
  ) {
    throw new Error(`${where}: surrogates must be an object`);
  }
  const surrogates = obj.surrogates as Record<string, unknown>;

  if (!Array.isArray(surrogates.strings)) {
    throw new Error(`${where}: surrogates.strings must be an array`);
  }
  const strings = surrogates.strings;
  for (const [i, s] of strings.entries()) {
    if (typeof s !== 'string') {
      throw new Error(`${where}: surrogates.strings[${String(i)}] must be a string`);
    }
  }
  const sortedStrings = [...(strings as string[])].sort();
  for (const [i, s] of (strings as string[]).entries()) {
    if (s !== sortedStrings[i]) {
      throw new Error(`${where}: surrogates.strings must be sorted`);
    }
  }
  if (new Set(strings as string[]).size !== strings.length) {
    throw new Error(`${where}: surrogates.strings must be distinct`);
  }
  // Layered ON TOP of the membership check in assertFixtureFullySanitised,
  // never in place of it. Membership alone draws its allowed set from the
  // file under test, so any fixture passes by listing its own raw values
  // here; requiring each entry to have the SHAPE the sanitiser emits is what
  // that self-certification cannot satisfy.
  for (const s of strings as string[]) {
    if (!looksLikeSurrogateString(s)) {
      throw new Error(
        `${where}: surrogates.strings carries something the sanitiser would never emit: ${JSON.stringify(s)}`,
      );
    }
  }

  if (!Array.isArray(surrogates.numbers)) {
    throw new Error(`${where}: surrogates.numbers must be an array`);
  }
  const numbers = surrogates.numbers;
  for (const [i, n] of numbers.entries()) {
    if (typeof n !== 'number') {
      throw new Error(`${where}: surrogates.numbers[${String(i)}] must be a number`);
    }
  }
  const sortedNumbers = [...(numbers as number[])].sort((a, b) => a - b);
  for (const [i, n] of (numbers as number[]).entries()) {
    if (n !== sortedNumbers[i]) {
      throw new Error(`${where}: surrogates.numbers must be sorted`);
    }
  }
  if (new Set(numbers as number[]).size !== numbers.length) {
    throw new Error(`${where}: surrogates.numbers must be distinct`);
  }
  for (const n of numbers as number[]) {
    if (!looksLikeSurrogateNumber(n)) {
      throw new Error(
        `${where}: surrogates.numbers carries something the sanitiser would never emit: ${String(n)}`,
      );
    }
  }
}

/**
 * One decoded chunk: the parsed payload, plus — for SSE — the metadata lines
 * that are not `data:`.
 *
 * Keeping only the `data:` lines is what left `event:`, `id:`, `retry:` and
 * comment lines unchecked by the bar even though `sanitizeSseEvent` sanitises
 * every one of them. Those are exactly the lines an operator has a reason to
 * hand-edit — making a replay go green needs the site's real event names — so
 * they must be checked like any other leaf.
 */
function decodeChunks(fixture: FixtureEnvelope): readonly unknown[] {
  switch (fixture.format) {
    case 'json':
    case 'ndjson':
      return fixture.chunks.map((c) => JSON.parse(c) as unknown);
    case 'urlencoded':
      return fixture.chunks.map((c) => Object.fromEntries(new URLSearchParams(c)));
    case 'sse':
      return fixture.chunks.map((c) => {
        const dataLines: string[] = [];
        const otherLeaves: string[] = [];
        for (const line of c.split('\n')) {
          if (line.startsWith('data:')) {
            dataLines.push(line.slice(5).replace(/^ /, ''));
            continue;
          }
          if (line.trim().length === 0) continue;
          const colonIndex = line.indexOf(':');
          if (
            colonIndex > 0 &&
            (line.startsWith('event:') || line.startsWith('id:') || line.startsWith('retry:'))
          ) {
            otherLeaves.push(line.slice(colonIndex + 1).replace(/^ /, ''));
            continue;
          }
          otherLeaves.push(line);
        }
        const joined = dataLines.join('\n');
        let payload: unknown = joined;
        if (dataLines.length > 0) {
          try {
            payload = JSON.parse(joined) as unknown;
          } catch {
            payload = joined;
          }
        }
        return dataLines.length > 0 ? [payload, ...otherLeaves] : otherLeaves;
      });
    case 'text':
      return [...fixture.chunks];
  }
}

/**
 * Every string leaf in the fixture's decoded chunks and its `url` must be a
 * surrogate or an approved VALUE; every object key must be a surrogate or an
 * approved KEY; every number must be an integer with `|n| <= NUMBER_KEEP_MAX`
 * or a member of `surrogates.numbers`. Every URL host must be one of
 * `options.allowedHosts` or a `host-<n>.invalid` surrogate.
 *
 * Keys and values are judged against their OWN approvals file. Unioning the
 * two makes an approved key legal as a value and vice versa, which is a
 * widening neither file's reviewer agreed to.
 *
 * Exact set membership — never a regex over surrogate shapes ALONE, which
 * would fail OPEN the moment a real id happened to look like one. The shape
 * check `assertValidFixture` runs over `surrogates.strings` is the other half
 * of the same pair: membership stops a value that looks like a surrogate,
 * shape stops a fixture declaring its own raw values as surrogates, and
 * neither is sufficient by itself.
 *
 * A string leaf that itself parses as nested JSON (starts with `{`/`[` and
 * round-trips through JSON.parse to an object/array) is walked recursively
 * instead of being checked as one opaque string — mirroring exactly what
 * sanitizeCapture does with a nested-JSON leaf, so a legitimately-nested
 * fixture is not rejected for the container string never itself being a
 * surrogate.
 */
export function assertFixtureFullySanitised(
  where: string,
  fixture: FixtureEnvelope,
  approvals: Approvals,
  options: FixtureBarOptions,
): void {
  const surrogates = new Set<string>(fixture.surrogates.strings);
  const allowedKeys = new Set<string>([...surrogates, ...approvals.keys, '']);
  // protocolTokens is unioned in HERE ONLY — never into allowedKeys. Keys have
  // their own file and their own reviewer; widening that too is a widening
  // neither agreed to.
  const allowedValues = new Set<string>([
    ...surrogates,
    ...approvals.values,
    ...options.protocolTokens,
    '',
  ]);
  const allowedNumbers = new Set<number>(fixture.surrogates.numbers);
  const allowedHosts = new Set<string>(options.allowedHosts.map((h) => h.toLowerCase()));

  function checkKey(label: string, value: string): void {
    if (allowedKeys.has(value)) return;
    throw new Error(
      `${where}: ${label} is not a surrogate or an approved key: ${JSON.stringify(value)}`,
    );
  }

  function checkString(label: string, value: string): void {
    if (allowedValues.has(value)) return;
    throw new Error(
      `${where}: ${label} is not a surrogate or an approved value: ${JSON.stringify(value)}`,
    );
  }

  function checkNumber(label: string, value: number): void {
    if (Number.isInteger(value) && Math.abs(value) <= NUMBER_KEEP_MAX) return;
    if (allowedNumbers.has(value)) return;
    throw new Error(
      `${where}: ${label} is not a small integer or a surrogate number: ${String(value)}`,
    );
  }

  // A URL — whether the fixture's own top-level `url` or a body value the
  // sanitiser recognised as one — is a composite of a deliberately verbatim
  // allow-listed host plus sanitised path/query/fragment components, so it is
  // decomposed rather than checked as one opaque string (which a legitimately
  // sanitised URL would then always fail, being no single surrogate itself).
  //
  // The HOST is checked, not skipped. `sanitizeUrl` replaces any host outside
  // the allow-list with `host-<n>.invalid`, so a tool-produced fixture's every
  // URL host is either allow-listed or a surrogate — and a URL whose path,
  // query and fragment are all empty is otherwise examined by nothing at all,
  // which makes the host the only place content could hide.
  function checkUrlComponents(label: string, parsedUrl: URL): void {
    const host = parsedUrl.hostname.toLowerCase();
    if (!allowedHosts.has(host) && !surrogates.has(host)) {
      throw new Error(
        `${where}: ${label} host is neither an allowed host nor a host surrogate: ${JSON.stringify(host)}`,
      );
    }
    parsedUrl.pathname.split('/').forEach((segment, i) => {
      if (segment.length === 0) return;
      checkString(`${label} path segment [${String(i)}]`, segment);
    });
    for (const [key, value] of parsedUrl.searchParams.entries()) {
      checkKey(`${label} query key`, key);
      checkString(`${label} query value`, value);
    }
    if (parsedUrl.hash.length > 1) {
      checkString(`${label} fragment`, parsedUrl.hash.slice(1));
    }
  }

  function tryParseAbsoluteUrl(value: string): URL | null {
    if (!/^https?:\/\//i.test(value)) return null;
    try {
      return new URL(value);
    } catch {
      return null;
    }
  }

  function walk(label: string, value: unknown): void {
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'number') {
      checkNumber(label, value);
      return;
    }
    if (typeof value === 'string') {
      const trimmed = value.trim();
      const first = trimmed[0];
      if (trimmed.length > 0 && (first === '{' || first === '[')) {
        let nested: unknown;
        try {
          nested = JSON.parse(trimmed);
        } catch {
          nested = undefined;
        }
        if (nested !== null && typeof nested === 'object') {
          walk(`${label} (nested)`, nested);
          return;
        }
      }
      const asUrl = tryParseAbsoluteUrl(value);
      if (asUrl !== null) {
        checkUrlComponents(label, asUrl);
        return;
      }
      checkString(label, value);
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => {
        walk(`${label}[${String(i)}]`, v);
      });
      return;
    }
    if (typeof value === 'object') {
      for (const key of Object.keys(value)) {
        checkKey(`${label} key`, key);
        walk(`${label}.${key}`, (value as Record<string, unknown>)[key]);
      }
    }
  }

  decodeChunks(fixture).forEach((doc, i) => {
    walk(`chunks[${String(i)}]`, doc);
  });

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(fixture.url);
  } catch {
    throw new Error(`${where}: url does not parse as an absolute URL: ${fixture.url}`);
  }
  checkUrlComponents('url', parsedUrl);

  // The detector, re-run over the COMMITTED artifact. Nothing else here would
  // notice a value that is secret-shaped but declared — nor a rule pack that
  // grew a rule after the fixture was produced. The message names the rules,
  // never the match.
  const findings = options.detect(JSON.stringify(fixture));
  if (findings.length > 0) {
    throw new Error(`${where}: the detector flags the committed fixture (${findings.join(', ')})`);
  }
}

/**
 * A conversation stream fixture must carry more than one chunk.
 *
 * The robustness cases replay `[...chunks].reverse()` and a re-split of the
 * joined text; over a one-element array the reverse is byte-identical to the
 * ordinary replay, so that case asserts nothing the previous one did not, and
 * the assembler's cross-chunk framing is never reached at all. This is the
 * same rule `packages/detections/test/helpers/fixture-bar.ts` draws for
 * detection fixtures: a bar counts DISTINCT cases.
 */
export function assertStreamFixtureIsMultiChunk(where: string, fixture: FixtureEnvelope): void {
  if (fixture.chunks.length < MIN_STREAM_CHUNKS) {
    throw new Error(
      `${where}: a conversation stream fixture must carry at least ${String(MIN_STREAM_CHUNKS)} ` +
        `chunks (got ${String(fixture.chunks.length)}) — with one chunk the reverse-order and ` +
        `re-split robustness cases replay the ordinary one and assert nothing new. Capture the ` +
        `whole stream rather than one event.`,
    );
  }
  if (fixture.format === 'sse') {
    const events = new Set(fixture.chunks.map((c) => c.trim()).filter((c) => c.length > 0));
    if (events.size < MIN_STREAM_CHUNKS) {
      throw new Error(
        `${where}: an SSE stream fixture must carry at least ${String(MIN_STREAM_CHUNKS)} ` +
          `DISTINCT events (got ${String(events.size)}) — a repeated event exercises nothing ` +
          `the first one did not.`,
      );
    }
  }
}

/** The bar's one message form: name the subject, say what was found, say what is owed. */
export function belowFixtureBar(
  site: string,
  endpointCount: number,
  missing: readonly string[],
): string {
  const plural = endpointCount === 1 ? '' : 's';
  // The remediation names what is actually MISSING rather than a fixed list:
  // a fixed `{request,stream}.json` reads as the whole answer even when the
  // absent file is account.json, which is the one thing a reviewer looks at
  // when the bar fires.
  return (
    `adapter "${site}" declares ${String(endpointCount)} endpoint${plural} but is missing: ` +
    `${missing.join(', ')}. Add '${site}' to EXPECTED_DECLARING_ADAPTERS in test/helpers/fixture-bar.ts ` +
    `and ship the missing artifact(s) under test/fixtures/, produced by ` +
    `scripts/sanitize-capture.mjs. Do not hand-write a fixture.`
  );
}
