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

const STRING_SPAN_MAX = 4_000;
const SPACE_RUN_MAX = 256;
const STACK_DEPTH_MAX = 1_000;
// The most call text one file's variable-read scan covers, in total.
const VARIABLE_SCAN_CHARS_PER_FILE = 2_000_000;

const BACKSLASH = 92;
const NEWLINE = 10;
const SEMICOLON = 59;
const OPEN_PAREN = 40;
const CLOSE_PAREN = 41;
const OPEN_BRACKET = 91;
const CLOSE_BRACKET = 93;
const OPEN_BRACE = 123;
const CLOSE_BRACE = 125;
const BACKTICK = 96;

function isQuote(code: number): boolean {
  return code === 39 || code === 34 || code === BACKTICK;
}

function previousNonSpace(text: string, before: number): number {
  const floor = Math.max(-1, before - 1 - SPACE_RUN_MAX);
  let i = before - 1;
  while (i > floor && SPACE.test(text.charAt(i))) i -= 1;
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

// Just past the quote that closes the string opened at `open`, or `open + 1`
// when it does not close: on its own line for `'` and `"`, within a bound for
// a backtick. An unclosed quote, such as an apostrophe in a comment, is then an
// ordinary character and cannot swallow the rest of the file.
function stringEnd(text: string, open: number): number {
  const quote = text.charCodeAt(open);
  const limit = Math.min(text.length, open + STRING_SPAN_MAX);
  for (let i = open + 1; i < limit; i += 1) {
    const code = text.charCodeAt(i);
    if (code === BACKSLASH) i += 1;
    else if (code === quote) return i + 1;
    else if (code === NEWLINE && quote !== BACKTICK) break;
  }
  return open + 1;
}

interface Frame {
  open: number;
  code: number;
  block: boolean;
  statementBreak: boolean;
  call?: boolean;
  waiting: number[];
}

function frameIsCall(text: string, frame: Frame): boolean {
  frame.call ??= isCall(text, frame.open);
  return frame.call;
}

// The frame a hit belongs to: the innermost call parenthesis above it, looking
// through array brackets and object braces, and past a URL-building call.
function targetFrame(text: string, stack: readonly Frame[]): Frame | undefined {
  let found: Frame | undefined;
  for (let i = stack.length - 1; i >= 0; i -= 1) {
    const frame = stack[i];
    if (frame === undefined || frame.statementBreak || frame.block) break;
    if (frame.code !== OPEN_PAREN) continue;
    if (!frameIsCall(text, frame)) break;
    if (found !== undefined) return frame;
    found = frame;
    if (!URL_BUILDERS.has(calleeOf(text, frame.open))) return frame;
  }
  return found;
}

/**
 * For each offset in `offsets`, the innermost call expression around it, from
 * its opening parenthesis to just past its closing one, or undefined when the
 * offset is in no call, or the call opens more than a lookback before it or is
 * longer than a lookahead. A URL-building call such as `new URL(...)` gives way
 * to the call around it. One pass over the text, whatever the number of offsets.
 */
export function enclosingCalls(text: string, offsets: readonly number[]): (Span | undefined)[] {
  const spans: (Span | undefined)[] = offsets.map(() => undefined);
  const order = offsets.map((_, i) => i).sort((x, y) => (offsets[x] ?? 0) - (offsets[y] ?? 0));
  const stack: Frame[] = [];
  let next = 0;
  const assign = (upTo: number): void => {
    while (next < order.length && (offsets[order[next] ?? 0] ?? 0) <= upTo) {
      const index = order[next] ?? 0;
      const frame = targetFrame(text, stack);
      if (frame !== undefined && (offsets[index] ?? 0) - frame.open <= CALL_LOOKBACK) {
        frame.waiting.push(index);
      }
      next += 1;
    }
  };
  // Brackets nested deeper than any call worth reading are counted, not kept.
  let overflow = 0;
  for (let i = 0; i < text.length;) {
    assign(i);
    const code = text.charCodeAt(i);
    if (isQuote(code)) {
      const end = stringEnd(text, i);
      assign(end - 1);
      i = end;
      continue;
    }
    if (code === OPEN_PAREN || code === OPEN_BRACKET || code === OPEN_BRACE) {
      if (stack.length >= STACK_DEPTH_MAX) {
        overflow += 1;
      } else {
        stack.push({
          open: i,
          code,
          block: code === OPEN_BRACE && opensBlock(text, i),
          statementBreak: false,
          waiting: [],
        });
      }
    } else if (code === CLOSE_PAREN || code === CLOSE_BRACKET || code === CLOSE_BRACE) {
      if (overflow > 0) {
        overflow -= 1;
      } else {
        const frame = stack.pop();
        if (frame !== undefined && code === CLOSE_PAREN && i + 1 - frame.open <= CALL_LOOKAHEAD) {
          for (const index of frame.waiting) spans[index] = { start: frame.open, end: i + 1 };
        }
      }
    } else if (code === SEMICOLON && overflow === 0) {
      const top = stack.at(-1);
      if (top !== undefined) top.statementBreak = true;
    }
    i += 1;
  }
  return spans;
}

/** The innermost call expression around `[start, end)`; see `enclosingCalls`. */
export function enclosingCall(text: string, start: number, end: number): Span | undefined {
  const span = enclosingCalls(text, [start])[0];
  return span !== undefined && span.end >= end ? span : undefined;
}

/** The variable-read scan budget for one file. */
export interface VariableScanBudget {
  chars: number;
}

export function variableScanBudget(): VariableScanBudget {
  return { chars: VARIABLE_SCAN_CHARS_PER_FILE };
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

/**
 * Variable references for the call `call` in `text`, capped per call site.
 * None once `budget` cannot cover the call's text.
 */
export function variableRefsOf(
  text: string,
  call: Span,
  budget: VariableScanBudget = variableScanBudget(),
): EgressCredentialRef[] {
  const length = call.end - call.start;
  if (length > budget.chars) return [];
  budget.chars -= length;
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
