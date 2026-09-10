// Static egress extraction for one source file's text: URL literals and bare
// public IPv4 addresses, each carrying a transport, an evidence-based HTTP
// method, and a redacted snippet.
//
// Pure like everything in @akasecurity/detections: no I/O, no Node-API
// imports — line numbers come from counting newlines in the raw text. Callers
// gate what reaches extractEgress: code files only (EGRESS_CODE_EXTENSIONS),
// never lockfiles, never text containing NUL bytes.
import type { HttpMethod, Transport } from '@akasecurity/schema';

import { isPrivateOrReservedIPv4, isValidIPv4 } from './registry.ts';

/** One URL or bare-IP destination reference found in a file's text. */
export interface RawEndpointHit {
  /** Normalized: no userinfo, query, or fragment; placeholders as `${var}`. */
  url: string;
  /** Lowercased, without the port. */
  host: string;
  port: number | null;
  transport: Transport;
  /** A verb only where the surrounding text proves one; otherwise 'REF'. */
  method: HttpMethod;
  /** True when the URL carried a placeholder span. */
  template: boolean;
  /** 1-based, counted in the raw text. */
  line: number;
  /** Redacted, capped at SNIPPET_MAX characters. */
  snippet: string;
}

// Source extensions URL/IP extraction runs on, mirroring the scanner's walker
// list. Compared against extname() output, so the leading dots are required.
export const EGRESS_CODE_EXTENSIONS: ReadonlySet<string> = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.py',
  '.java',
  '.rb',
  '.cs',
  '.php',
  '.go',
  '.rs',
]);

const SNIPPET_MAX = 200;
// Matches what the chained `.replace` wrote before the passes became a list.
const WHITESPACE = /\s/;
const MASK = '••••';

// URL literals in raw source text. Template spans are admitted as explicit
// alternatives so `${x}`, `{x}` and printf verbs do not terminate the match.
const URL_CANDIDATE =
  /(https?|wss?|sftp|grpcs?|smtp):\/\/(?:[^\s'"`<>()[\]{},;]|\$\{[^}\s]{1,64}\}|\{[A-Za-z_]\w{0,63}\}|%[sd])+/gi;

// The placeholder spans above, collapsed to one token per candidate. Applied
// as a single left-to-right pass so a replacement is never rewritten.
const PLACEHOLDER = /\$\{[^}\s]{1,64}\}|\{[A-Za-z_]\w{0,63}\}|%[sd]/g;
const VAR_TOKEN = '${var}';

// Stand-in for VAR_TOKEN while the candidate goes through the URL parser:
// lowercase alphanumerics survive both host lowercasing and path encoding
// unchanged, so it can be swapped back verbatim afterwards.
const VAR_SENTINEL = 'akaegressvar0';

// Sentence punctuation a URL literal may pick up from the prose around it,
// stripped by scanning from the END rather than with a `+$` pattern. That
// pattern is quadratic on a candidate whose punctuation run does not reach the
// end: every start position consumes the run and then fails the anchor. A URL
// candidate is file content, bounded only by the walker's 1 MB cap, so a repo
// carrying one long run is enough. Measured on a URL followed by 64K dots and
// one letter: 1,471 ms before, 0 ms after. The result is identical for every
// input — the scan simply cannot backtrack.
const TRAILING_PUNCTUATION = '.,;:\'"';

function stripTrailingPunctuation(value: string): string {
  let end = value.length;
  // `charAt` rather than an index read: it returns '' past the end rather
  // than `undefined`, so the loop needs no non-null assertion.
  while (end > 0 && TRAILING_PUNCTUATION.includes(value.charAt(end - 1))) end -= 1;
  return end === value.length ? value : value.slice(0, end);
}

// Scheme to transport. 'grpcs' collapses onto 'grpc'; the stored URL is
// rebuilt from the transport so the two can never disagree.
const TRANSPORT_BY_SCHEME: Readonly<Record<string, Transport>> = {
  http: 'http',
  https: 'https',
  ws: 'ws',
  wss: 'wss',
  sftp: 'sftp',
  grpc: 'grpc',
  grpcs: 'grpc',
  smtp: 'smtp',
};

// Method evidence. Windows are measured in raw characters and may cross
// newlines: a call's URL and its options object routinely sit on different
// lines.
const BEFORE_WINDOW = 200;
const AFTER_WINDOW = 300;
const VERB_METHOD_OPENER = /\.\s*(get|post|put|delete)\s*\(\s*['"`]*$/i;
// A closing bracket between the verb and the URL means the verb's own list or
// call ended first, so the verb belongs to something else — a `['GET','POST']`
// constant, a `case 'GET', 'POST':`, a SQL VALUES tuple. The capture feeds the
// same statement-locality gate the after-window rule uses.
const VERB_FIRST_ARGUMENT = /["'](GET|POST|PUT|DELETE)["']\s*,([^)\]};]{0,150})$/i;
const OPTIONS_METHOD = /method\s*[:=]\s*['"](GET|POST|PUT|DELETE)/i;
const CLIENT_OPENER = /\b(fetch|urlopen|got|ky)\s*\(\s*['"`]*$/i;
const ANY_METHOD_KEY = /\bmethod\s*[:=]/i;

// End of the statement the URL sits in: a semicolon, or a line break starting a
// new binding or block. A `method:` key past one of these describes a later,
// unrelated expression, so it proves nothing about this URL.
const STATEMENT_BREAK =
  /;|\n\s*(?:(?:const|let|var|val|function|func|fn|def|class|return|export|import|if|for|while|switch|try|public|private)\b|\w+\s*=[^=])/;

// Bare dotted-quad literals, with an optional port.
const IPV4_CANDIDATE = /\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b/g;
const IP_HOST_CONTEXT = /\b(host|hostname|server|address|endpoint|ip|url|uri)\b/i;
const IP_SFTP_CONTEXT = /\bs(ftp|cp|sh)\b/i;
const IP_SMTP_CONTEXT = /\b(smtp|mail)\b/i;

// Redaction. Values are masked, keys are kept readable. The quote class
// covers backtick-quoted (template literal) values the same as single- and
// double-quoted ones.

// Field names whose value is a credential, shared by both value rules below so
// the two can never cover different key sets.
const SECRET_KEY_NAMES =
  'api[_-]?key|apikey|private[_-]?key|access[_-]?key|access[_-]?token|token|secret|credentials?|password|passwd|pwd|authorization|sig|signature|sas|assertion';

// HTTP authorization schemes that place the credential after the scheme
// keyword. Any scheme here keeps its keyword readable and loses its credential.
const AUTH_SCHEMES = 'Bearer|Basic|Token|Digest|ApiKey|SSWS|AWS4-HMAC-SHA256';

const USERINFO = /:\/\/[^@/\s]+@/g;

// `<field>: <value>`. A value that opens with a scheme keyword followed by a
// space, quote, or backtick is left to AUTH_SCHEME_VALUE, which keeps the
// keyword visible; a scheme-prefixed value with no such delimiter (`Bearer-x`,
// `Bearer.x`) names no separate credential and is masked whole here.
const SECRET_VALUE = new RegExp(
  `((?:${SECRET_KEY_NAMES})['"\`]?\\s*[:=]\\s*['"\`]?)(?!(?:${AUTH_SCHEMES})[\\s'"\`])[^\\s'"\`&]+`,
  'gi',
);

// `Authorization: <scheme> <credential>`. Anchored on the field name so an
// ordinary sentence opening with a scheme word ("token bucket refill rate")
// keeps its next word.
const AUTH_SCHEME_VALUE = new RegExp(
  `((?:${SECRET_KEY_NAMES})['"\`]?\\s*[:=]\\s*['"\`]?)(${AUTH_SCHEMES})\\s+[^\\s'"\`]+`,
  'gi',
);

// A bearer token carrying no field name in front of it.
const BEARER_TOKEN = /\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi;

// Webhook endpoints whose URL path segments ARE the credential: anyone holding
// the full path can post to the channel. The routing prefix stays readable and
// everything after it is masked, in the stored URL and in the snippet alike.
const WEBHOOK_SECRET_PATHS: readonly { hosts: readonly string[]; prefix: string }[] = [
  { hosts: ['hooks.slack.com'], prefix: '/services/' },
  {
    hosts: ['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com'],
    prefix: '/api/webhooks/',
  },
  { hosts: ['hooks.zapier.com'], prefix: '/hooks/' },
  { hosts: ['outlook.office.com', 'outlook.office365.com'], prefix: '/webhook/' },
];

function escapeRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Built from WEBHOOK_SECRET_PATHS so the snippet rule and the URL rule can
// never drift apart. The tail class mirrors URL_CANDIDATE's terminator set.
const WEBHOOK_URL = new RegExp(
  `(https?://(?:${WEBHOOK_SECRET_PATHS.flatMap((entry) =>
    entry.hosts.map((host) => `${escapeRegExp(host)}${escapeRegExp(entry.prefix)}`),
  ).join('|')}))[^\\s'"\`<>()[\\]{},;]+`,
  'gi',
);

// Mask the credential-bearing tail of a known webhook path, or return the path
// untouched when the host/prefix pair is not one of them.
function maskWebhookPath(host: string, pathname: string): string {
  for (const entry of WEBHOOK_SECRET_PATHS) {
    if (entry.hosts.includes(host) && pathname.startsWith(entry.prefix)) {
      return `${entry.prefix}${MASK}`;
    }
  }
  return pathname;
}

const VENDORED_PATH = /(^|\/)(vendor|third_party|external)\//;

/** True when a stored file path sits under a vendored dependency tree. */
export function isVendoredPath(file: string): boolean {
  return VENDORED_PATH.test(file);
}

// The redaction chain, as a list so each pass can record WHERE it edited rather
// than only what it produced. The replacement strings the chained `.replace`
// calls used are spelled as functions: `$1` is the first group, `$2` the second.
// All five patterns are global, which is what makes one pass one left-to-right
// sweep with non-overlapping edits.
const REDACTION_PASSES: readonly {
  readonly pattern: RegExp;
  readonly replace: (match: RegExpMatchArray) => string;
}[] = [
  { pattern: USERINFO, replace: () => '://' },
  { pattern: WEBHOOK_URL, replace: (m) => `${m[1] ?? ''}${MASK}` },
  { pattern: SECRET_VALUE, replace: (m) => `${m[1] ?? ''}${MASK}` },
  { pattern: AUTH_SCHEME_VALUE, replace: (m) => `${m[1] ?? ''}${m[2] ?? ''} ${MASK}` },
  { pattern: BEARER_TOKEN, replace: () => `Bearer ${MASK}` },
];

/**
 * What one pass did to its input, as parallel arrays sorted by `at` and
 * non-overlapping — a global replace consumes left to right, so it cannot
 * produce anything else.
 *
 * `before[i]` is the output-minus-input length of every edit BEFORE i, and
 * `after[i]` includes i. Those two are what turn "an offset in this pass's
 * input" into "the same place in its output" without rescanning anything.
 */
interface PassEdits {
  readonly at: number[];
  readonly end: number[];
  readonly before: number[];
  readonly after: number[];
}

function runPass(
  input: string,
  pass: (typeof REDACTION_PASSES)[number],
): { output: string; edits: PassEdits } {
  const at: number[] = [];
  const end: number[] = [];
  const before: number[] = [];
  const after: number[] = [];
  let output = '';
  let copied = 0;
  let shift = 0;
  for (const match of input.matchAll(pass.pattern)) {
    const start = match.index;
    const matched = match[0];
    const replacement = pass.replace(match);
    output += input.slice(copied, start) + replacement;
    at.push(start);
    end.push(start + matched.length);
    before.push(shift);
    shift += replacement.length - matched.length;
    after.push(shift);
    copied = start + matched.length;
  }
  // Nothing matched: hand back the input itself rather than a rebuilt copy.
  if (at.length === 0) return { output: input, edits: { at, end, before, after } };
  return { output: output + input.slice(copied), edits: { at, end, before, after } };
}

// Where `offset` — a position in this pass's INPUT — ends up in its output. An
// offset inside an edit collapses to the start of what replaced it, because a
// masked span has no interior left to point at.
function throughPass(edits: PassEdits, offset: number): number {
  let low = 0;
  let high = edits.at.length - 1;
  let found = -1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    if ((edits.at[mid] ?? 0) <= offset) {
      found = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  if (found === -1) return offset;
  if (offset < (edits.end[found] ?? 0)) return (edits.at[found] ?? 0) + (edits.before[found] ?? 0);
  return offset + (edits.after[found] ?? 0);
}

/**
 * One source line with its credentials and secret values already stripped, plus
 * what placing a window into it needs.
 *
 * Split out from `redactSnippet` because this half depends on the LINE ALONE
 * and is the whole cost — each pass walks the line, and so does each trim.
 * A hit's snippet is taken per HIT, and a minified bundle puts every hit in a
 * file on ONE line, so recomputing this per hit is quadratic in the number of
 * hits. Measured on an ordinary 128 KB single-line file carrying 3,283 URLs:
 * 1,955 ms before, against 5 ms for the same bytes and the same hits split over
 * short lines. That is benign input, not a crafted one.
 *
 * `edits` is the other half of that, and it is what makes the SECRET-bearing
 * bundle linear too. Mapping a hit's offset into the redacted line used to mean
 * redacting the whole prefix again, per hit — so a masked value anywhere on a
 * long line put the quadratic straight back, on exactly the file this product
 * is pointed at on purpose. Measured on a 500 KB bundle carrying one token:
 * 15,333 ms before, against 13 ms for the same bundle with no token.
 */
interface RedactedLine {
  redacted: string;
  /**
   * Only populated once `redacted` is long enough to need a window. A line that
   * fits under SNIPPET_MAX is returned whole and never reads them.
   */
  window?: { trimmed: string; edits: readonly PassEdits[]; lead: number };
}

function redactedLineOf(line: string): RedactedLine {
  const trimmed = line.trim();
  const edits: PassEdits[] = [];
  let text = trimmed;
  for (const pass of REDACTION_PASSES) {
    const result = runPass(text, pass);
    text = result.output;
    edits.push(result.edits);
  }
  if (text.length <= SNIPPET_MAX) return { redacted: text };
  return {
    redacted: text,
    window: { trimmed, edits, lead: line.length - line.trimStart().length },
  };
}

function snippetWindow({ redacted, window }: RedactedLine, anchor: number): string {
  if (window === undefined) return redacted;
  const { trimmed, edits, lead } = window;
  // Masking only ever shortens, so an unchanged length means nothing matched
  // and offsets carry over untouched.
  let mapped = Math.max(0, anchor - lead);
  if (redacted.length !== trimmed.length) {
    // The chain begins with a `.trim()`, so a prefix ending in whitespace lost
    // it. Back the offset off that run rather than mapping into it — the runs
    // before two different hits cannot overlap, so this stays linear over a
    // line however many hits it carries.
    while (mapped > 0 && WHITESPACE.test(trimmed.charAt(mapped - 1))) mapped -= 1;
    for (const pass of edits) mapped = throughPass(pass, mapped);
  }
  const start = Math.min(
    Math.max(0, mapped - Math.floor(SNIPPET_MAX / 2)),
    redacted.length - SNIPPET_MAX,
  );
  return redacted.slice(start, start + SNIPPET_MAX);
}

/**
 * Strip credentials and secret values out of one source line and cap it at
 * SNIPPET_MAX characters. `Authorization: <scheme> <credential>` keeps the
 * scheme keyword and masks the credential; a webhook URL keeps its routing
 * prefix and loses the path segments that authorize posting to it.
 *
 * `anchor` is the hit's offset within `line`; the cap window is centered on it
 * so a hit far along a very long line — a minified bundle puts a whole file on
 * one line — still lands inside the stored evidence. Redaction always runs over
 * the whole line first, so masking never depends on where the window falls.
 *
 * A caller taking many snippets from ONE line must memoize `redactedLineOf` and
 * call `snippetWindow` instead — see extractEgress.
 */
export function redactSnippet(line: string, anchor = 0): string {
  return snippetWindow(redactedLineOf(line), anchor);
}

/**
 * Pull every URL literal and bare public IPv4 reference out of one file's
 * text, sorted ascending by line, then by url (never by match order).
 */
export function extractEgress(text: string): RawEndpointHit[] {
  const lineStarts = lineStartOffsets(text);
  const urlSpans: (readonly [number, number])[] = [];
  const hits: RawEndpointHit[] = [];
  // Derived once per line rather than once per hit: a minified bundle puts
  // every hit in a file on a single very long line.
  const lineTextOf = memoizeByLine((index) => lineTextAt(text, lineStarts, index));
  const ipContextOf = memoizeByLine((index) => ipLineContext(lineTextOf(index)));
  // Per LINE, like the two above and for the same reason: the redaction pass is
  // the cost of a snippet, and every hit on a minified bundle's single line
  // would otherwise pay it again.
  const redactedOf = memoizeByLine((index) => redactedLineOf(lineTextOf(index)));
  const snippetAt = (index: number, offset: number): string =>
    snippetWindow(redactedOf(index), offset - (lineStarts[index] ?? 0));

  for (const match of text.matchAll(URL_CANDIDATE)) {
    const start = match.index;
    const matched = match[0];
    urlSpans.push([start, start + matched.length]);

    const scheme = match[1];
    if (scheme === undefined) continue;
    const candidate = stripTrailingPunctuation(matched);
    if (candidate === '') continue;

    const parsed = parseCandidate(candidate, scheme);
    if (parsed === null) continue;

    const index = lineIndexAt(lineStarts, start);
    hits.push({
      ...parsed,
      method: inferMethod(text, start, start + matched.length),
      line: index + 1,
      snippet: snippetAt(index, start),
    });
  }

  for (const match of text.matchAll(IPV4_CANDIDATE)) {
    const start = match.index;
    if (isInsideSpan(urlSpans, start)) continue;

    const index = lineIndexAt(lineStarts, start);
    const parsed = parseBareIp(match[0], ipContextOf(index));
    if (parsed === null) continue;

    hits.push({ ...parsed, method: 'REF', line: index + 1, snippet: snippetAt(index, start) });
  }

  return hits.sort(compareHits);
}

interface ParsedDestination {
  url: string;
  host: string;
  port: number | null;
  transport: Transport;
  template: boolean;
}

// Normalize one raw URL candidate: collapse placeholder spans to `${var}`,
// parse it, and rebuild it without userinfo, query, or fragment, masking the
// credential-bearing tail of a known webhook path on the way. Returns null
// for an unparseable candidate or a placeholder in the authority (a fully
// dynamic host names no destination).
function parseCandidate(candidate: string, scheme: string): ParsedDestination | null {
  const transport = TRANSPORT_BY_SCHEME[scheme.toLowerCase()];
  if (transport === undefined) return null;

  let placeholders = 0;
  const normalized = candidate.replace(PLACEHOLDER, () => {
    placeholders += 1;
    return VAR_TOKEN;
  });

  let parsed: URL;
  try {
    parsed = new URL(normalized.split(VAR_TOKEN).join(VAR_SENTINEL));
  } catch {
    return null;
  }

  // Non-special schemes (sftp, grpc, smtp) keep the authority's original
  // case, so lowercasing is this pass's job rather than the parser's.
  const host = parsed.hostname.toLowerCase();
  if (host === '' || host.includes(VAR_SENTINEL)) return null;

  const authority = parsed.host.toLowerCase();
  const path = maskWebhookPath(host, parsed.pathname);
  const url = `${transport}://${authority}${path}`.split(VAR_SENTINEL).join(VAR_TOKEN);

  return {
    url,
    host,
    port: parsed.port === '' ? null : Number(parsed.port),
    transport,
    template: placeholders > 0,
  };
}

// Keep a bare dotted-quad only when it is a valid public IPv4 literal named by
// a host-ish keyword on the same line. Transport comes from that line's
// context: no scheme means no TLS evidence, so plain http is the honest floor.
function parseBareIp(candidate: string, context: IpLineContext): ParsedDestination | null {
  const [address, port] = splitPort(candidate);
  if (!isValidIPv4(address) || isPrivateOrReservedIPv4(address)) return null;
  if (!context.named) return null;

  const { transport } = context;
  return {
    url: `${transport}://${address}${port === null ? '' : `:${String(port)}`}`,
    host: address,
    port,
    transport,
    template: false,
  };
}

// What one line says about the bare IPs on it: whether a host-ish keyword
// names them at all, and which transport its context implies.
interface IpLineContext {
  named: boolean;
  transport: Transport;
}

function ipLineContext(line: string): IpLineContext {
  const context = identifierWords(line);
  let transport: Transport = 'http';
  if (IP_SFTP_CONTEXT.test(context)) transport = 'sftp';
  else if (IP_SMTP_CONTEXT.test(context)) transport = 'smtp';
  return { named: IP_HOST_CONTEXT.test(context), transport };
}

// URL spans are non-overlapping and in increasing order, so only the last span
// starting at or before `offset` can contain it.
function isInsideSpan(spans: (readonly [number, number])[], offset: number): boolean {
  let low = 0;
  let high = spans.length - 1;
  let found = -1;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const span = spans[mid];
    if (span === undefined) break;
    if (span[0] <= offset) {
      found = mid;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  const span = found === -1 ? undefined : spans[found];
  return span !== undefined && offset < span[1];
}

function splitPort(candidate: string): [string, number | null] {
  const colon = candidate.indexOf(':');
  if (colon === -1) return [candidate, null];
  return [candidate.slice(0, colon), Number(candidate.slice(colon + 1))];
}

// Identifier separators and camelCase humps read as word boundaries, so
// SFTP_SERVER and mailRelayHost match the context keywords above.
function identifierWords(line: string): string {
  return line.replace(/[_-]+/g, ' ').replace(/([a-z0-9])([A-Z])/g, '$1 $2');
}

// Methods are evidence, never fabrication: a bare client call counts as GET
// only when the whole call is visible, the URL is its only argument, and it
// carries no method key. A `method:` key after the URL counts only while it is
// still inside the URL's own statement — otherwise a bare `const ENDPOINT =
// '…'` followed by an unrelated `{ method: 'POST' }` would borrow that verb.
// Anything the windows cannot prove is a plain reference — including a call
// that passes a second argument such as an options object, since that object's
// own contents (e.g. its HTTP method) sit outside the window this pass can see.
function inferMethod(text: string, start: number, end: number): HttpMethod {
  const before = text.slice(Math.max(0, start - BEFORE_WINDOW), start);
  const after = text.slice(end, end + AFTER_WINDOW);

  const opener = VERB_METHOD_OPENER.exec(before);
  if (opener?.[1] !== undefined) return verbOf(opener[1]);

  const firstArgument = VERB_FIRST_ARGUMENT.exec(before);
  if (firstArgument?.[1] !== undefined && !STATEMENT_BREAK.test(firstArgument[2] ?? '')) {
    return verbOf(firstArgument[1]);
  }

  const options = OPTIONS_METHOD.exec(after);
  if (options?.[1] !== undefined && !STATEMENT_BREAK.test(after.slice(0, options.index))) {
    return verbOf(options[1]);
  }

  if (CLIENT_OPENER.test(before)) {
    const close = callCloseIndex(after);
    if (
      close !== -1 &&
      isSoleArgument(after, close) &&
      !ANY_METHOD_KEY.test(after.slice(0, close))
    ) {
      return 'GET';
    }
  }

  return 'REF';
}

function verbOf(raw: string): HttpMethod {
  return raw.toUpperCase() as HttpMethod;
}

// Offset just past the ')' that closes the call the match sits inside, or -1
// when the call does not close within `span`. Depth starts at 1 because the
// span begins inside the argument list.
function callCloseIndex(span: string): number {
  let depth = 1;
  for (let i = 0; i < span.length; i += 1) {
    const char = span[i];
    if (char === '(') depth += 1;
    else if (char === ')') {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

// True when nothing sits between the URL match and the call's closing paren
// except an optional single trailing comma. A comma anywhere else in that
// span — including one that opens a nested call's own argument list — marks
// a second argument to the outer call, so the URL is not its sole argument.
function isSoleArgument(span: string, close: number): boolean {
  const between = span.slice(0, close - 1).trimEnd();
  const withoutTrailingComma = between.endsWith(',') ? between.slice(0, -1) : between;
  return !withoutTrailingComma.includes(',');
}

// Per-line derivations are computed on first use and reused by every later
// hit on that line.
function memoizeByLine<T>(compute: (index: number) => T): (index: number) => T {
  const cache = new Map<number, T>();
  return (index) => {
    const cached = cache.get(index);
    if (cached !== undefined) return cached;
    const value = compute(index);
    cache.set(index, value);
    return value;
  };
}

export function lineStartOffsets(text: string): number[] {
  const starts = [0];
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return starts;
}

// Index of the line containing `offset`, by binary search over line starts.
export function lineIndexAt(starts: number[], offset: number): number {
  let low = 0;
  let high = starts.length - 1;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if ((starts[mid] ?? 0) <= offset) low = mid;
    else high = mid - 1;
  }
  return low;
}

// Text of line `index`, without its terminator. A trailing '\r' is left for
// redactSnippet's trim to drop.
export function lineTextAt(text: string, starts: number[], index: number): string {
  const start = starts[index] ?? 0;
  const next = starts[index + 1];
  return next === undefined ? text.slice(start) : text.slice(start, next - 1);
}

function compareHits(a: RawEndpointHit, b: RawEndpointHit): number {
  if (a.line !== b.line) return a.line - b.line;
  if (a.url !== b.url) return a.url < b.url ? -1 : 1;
  return 0;
}
