// The credentials an egress call site uses, found inside its call expression:
// environment variables it reads, by name, and secret literals written in it,
// as sighting tokens the caller computed. Pure: no I/O.
import type { EgressCredentialRef, Span } from '@akasecurity/schema';
import { CREDENTIAL_REFS_PER_CALL_SITE_MAX, MAX_VARIABLE_NAME_LENGTH } from '@akasecurity/schema';

import type { RawEndpointHit } from './extract.ts';

/** A secret found in a file, already reduced to its sighting token. */
export interface TokenizedSecretSpan {
  start: number;
  end: number;
  ruleId: string;
  token: string;
}

// Both bounds keep the search linear in the number of hits on a minified line.
const CALL_LOOKBACK = 1_000;
const CALL_LOOKAHEAD = 4_000;
const CALLEE_WINDOW = 64;

const WORD_CHAR = /[\w$]/;
const CALLEE = /[\w$]+$/;
const SPACE = /\s/;

// Words that put a parenthesis after them without calling anything.
const NOT_A_CALLEE: ReadonlySet<string> = new Set([
  'if',
  'elif',
  'for',
  'while',
  'switch',
  'catch',
  'return',
  'await',
  'typeof',
  'yield',
  'in',
  'and',
  'or',
  'not',
  'with',
  'assert',
]);

// Calls that only build a URL; the call that sends it is the one around them.
const URL_BUILDERS: ReadonlySet<string> = new Set([
  'URL',
  'URI',
  'Uri',
  'urlparse',
  'urljoin',
  'parse',
  'Parse',
]);

const NAME = String.raw`([A-Za-z_][\w.-]*)`;
const ENV_READS: readonly RegExp[] = [
  /(?:\b(?:process|Bun)\.env|\bimport\.meta\.env)\.([A-Za-z_$][\w$]*)/g,
  new RegExp(
    String.raw`(?:\b(?:process|Bun)\.env|\bimport\.meta\.env|\bos\.environ|\bENV|\$_ENV)\s*\[\s*(['"\x60])${NAME}\1\s*\]`,
    'g',
  ),
  new RegExp(
    String.raw`(?:\bos\.(?:getenv|environ\.get|Getenv|LookupEnv)|\bSystem\.getenv|\bEnvironment\.GetEnvironmentVariable|\bENV\.fetch|\bDeno\.env\.get|\benv::var(?:_os)?|\benv!|\bgetenv)\s*\(\s*(['"\x60])${NAME}\1`,
    'g',
  ),
];

// Shared by every hit in one file, so a file of calls that never close costs a
// bounded amount of work in total rather than the full search per hit.
export interface CallSearchBudget {
  steps: number;
}

const CALL_SEARCH_STEPS_PER_FILE = 4_000_000;

/** A fresh search budget for one file. */
export function callSearchBudget(): CallSearchBudget {
  return { steps: CALL_SEARCH_STEPS_PER_FILE };
}

const BACKSLASH = 92;
const NEWLINE = 10;
const COMMA = 44;
const SEMICOLON = 59;
const OPEN_PAREN = 40;
const CLOSE_PAREN = 41;
const OPEN_BRACKET = 91;
const CLOSE_BRACKET = 93;
const OPEN_BRACE = 123;
const CLOSE_BRACE = 125;

function isQuote(code: number): boolean {
  return code === 39 || code === 34 || code === 96;
}

function isOpener(code: number): boolean {
  return code === OPEN_PAREN || code === OPEN_BRACKET || code === OPEN_BRACE;
}

function isCloser(code: number): boolean {
  return code === CLOSE_PAREN || code === CLOSE_BRACKET || code === CLOSE_BRACE;
}

function isEscaped(text: string, at: number): boolean {
  let slashes = 0;
  for (let i = at - 1; i >= 0 && text.charCodeAt(i) === BACKSLASH; i -= 1) slashes += 1;
  return slashes % 2 === 1;
}

// Where the backward search starts: before the quote that opens the string the
// URL sits in, when one opens on the same stretch of plain text.
function backwardStart(text: string, from: number, floor: number): number {
  for (let i = from - 1; i >= floor; i -= 1) {
    const code = text.charCodeAt(i);
    if (isQuote(code)) return i;
    if (code === NEWLINE || isOpener(code) || code === COMMA || code === SEMICOLON) return from;
  }
  return from;
}

function previousNonSpace(text: string, before: number): number {
  let i = before - 1;
  while (i >= 0 && SPACE.test(text.charAt(i))) i -= 1;
  return i;
}

function calleeOf(text: string, open: number): string {
  const head = text.slice(Math.max(0, open - CALLEE_WINDOW), open).trimEnd();
  return CALLEE.exec(head)?.[0] ?? '';
}

function isCall(text: string, open: number): boolean {
  const at = previousNonSpace(text, open);
  if (at < 0) return false;
  const char = text.charAt(at);
  if (char === '>') return text.charAt(at - 1) !== '=';
  if (char === '!' || char === ']' || char === ')') return true;
  if (!WORD_CHAR.test(char)) return false;
  return !NOT_A_CALLEE.has(calleeOf(text, open));
}

// An unmatched `{` after `)`, `=>` or a word opens a block, not an object.
function opensBlock(text: string, open: number): boolean {
  const at = previousNonSpace(text, open);
  if (at < 0) return true;
  const char = text.charAt(at);
  if (char === ')') return true;
  if (char === '>') return text.charAt(at - 1) === '=';
  return WORD_CHAR.test(char);
}

function openingParen(
  text: string,
  from: number,
  floor: number,
  budget: CallSearchBudget,
): number | undefined {
  let depth = 0;
  for (let i = from - 1; i >= floor; i -= 1) {
    if (--budget.steps < 0) return undefined;
    const code = text.charCodeAt(i);
    if (isQuote(code)) {
      if (isEscaped(text, i)) continue;
      let open = i - 1;
      while (open >= floor && (text.charCodeAt(open) !== code || isEscaped(text, open))) open -= 1;
      budget.steps -= i - open;
      if (open < floor) return undefined;
      i = open;
    } else if (isCloser(code)) {
      depth += 1;
    } else if (isOpener(code)) {
      if (depth > 0) depth -= 1;
      else if (code === OPEN_PAREN) return isCall(text, i) ? i : undefined;
      else if (code === OPEN_BRACE && opensBlock(text, i)) return undefined;
    } else if (code === SEMICOLON && depth === 0) {
      return undefined;
    }
  }
  return undefined;
}

function closingParen(text: string, open: number, budget: CallSearchBudget): number | undefined {
  const limit = Math.min(text.length, open + CALL_LOOKAHEAD);
  let depth = 0;
  for (let i = open + 1; i < limit; i += 1) {
    if (--budget.steps < 0) return undefined;
    const code = text.charCodeAt(i);
    if (isQuote(code)) {
      let close = i + 1;
      while (close < limit && (text.charCodeAt(close) !== code || isEscaped(text, close))) {
        close += 1;
      }
      budget.steps -= close - i;
      if (close >= limit) return undefined;
      i = close;
    } else if (isOpener(code)) {
      depth += 1;
    } else if (isCloser(code)) {
      if (depth === 0) return code === CLOSE_PAREN ? i + 1 : undefined;
      depth -= 1;
    }
  }
  return undefined;
}

/**
 * The innermost call expression around `[start, end)`, from its opening
 * parenthesis to just past its closing one, or undefined when the span is in
 * no call that opens and closes within the search bounds or the budget runs
 * out. A URL-building call such as `new URL(...)` gives way to the call around
 * it.
 */
export function enclosingCall(
  text: string,
  start: number,
  end: number,
  budget: CallSearchBudget = callSearchBudget(),
): Span | undefined {
  const floor = Math.max(0, start - CALL_LOOKBACK);
  let open = openingParen(text, backwardStart(text, start, floor), floor, budget);
  if (open === undefined) return undefined;
  if (URL_BUILDERS.has(calleeOf(text, open))) {
    open = openingParen(text, open, floor, budget) ?? open;
  }
  const close = closingParen(text, open, budget);
  return close !== undefined && close >= end ? { start: open, end: close } : undefined;
}

/** The environment variables `text` reads, by name, once each, in text order. */
export function variableReadsIn(text: string): string[] {
  const found: { at: number; name: string }[] = [];
  for (const pattern of ENV_READS) {
    for (const match of text.matchAll(pattern)) {
      const name = match[2] ?? match[1];
      if (name !== undefined && name.length <= MAX_VARIABLE_NAME_LENGTH) {
        found.push({ at: match.index, name });
      }
    }
  }
  found.sort((a, b) => a.at - b.at);
  return [...new Set(found.map((read) => read.name))];
}

/** Variable references for the call `call` in `text`, capped per call site. */
export function variableRefsOf(text: string, call: Span): EgressCredentialRef[] {
  return variableReadsIn(text.slice(call.start, call.end))
    .slice(0, CREDENTIAL_REFS_PER_CALL_SITE_MAX)
    .map((variableName) => ({ kind: 'variable', variableName }));
}

/**
 * `hits` with each secret whose span lies inside a hit's call expression added
 * to that hit's references as a literal, ahead of its variable references and
 * within the per-call-site cap.
 */
export function withLiteralCredentialRefs(
  hits: RawEndpointHit[],
  secrets: readonly TokenizedSecretSpan[],
): RawEndpointHit[] {
  if (secrets.length === 0) return hits;
  const ordered = [...secrets].sort((a, b) => a.start - b.start);
  return hits.map((hit) => {
    const { call } = hit;
    if (call === undefined) return hit;
    const tokens = new Set<string>();
    const literals: EgressCredentialRef[] = [];
    for (const secret of ordered) {
      if (secret.start < call.start || secret.end > call.end || tokens.has(secret.token)) continue;
      tokens.add(secret.token);
      literals.push({ kind: 'literal', token: secret.token, ruleId: secret.ruleId });
    }
    if (literals.length === 0) return hit;
    const refs = [...literals, ...(hit.credentialRefs ?? [])];
    return { ...hit, credentialRefs: refs.slice(0, CREDENTIAL_REFS_PER_CALL_SITE_MAX) };
  });
}
