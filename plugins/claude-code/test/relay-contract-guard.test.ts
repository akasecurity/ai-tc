/**
 * Static drift guard for the `/aka:setup` wizard's relay contract: every
 * USER-FACING stdout emit from a wizard script must pass through `show()` /
 * `showBlock()` (present.ts / setup-show.ts) so the harness's SHOW-region
 * relay pastes it verbatim, or be a `frameJsonBlock()` machine frame
 * (setup-frame-json.ts). Anything else on stdout is model-facing STATUS
 * (paths, fail() errors) that the model reads but never relays to the user.
 *
 * A raw `process.stdout.write(...)` / `deps.stdout(...)` call that emits
 * neither a SHOW region nor a FRAME is a silent contract violation: the text
 * reaches stdout but the relay chokepoint never wraps it, so it is never
 * shown to the user. This test statically scans a MAINTAINED list of the
 * wizard's user-facing script sources for every such call site and asserts
 * each one is accounted for by one of:
 *
 *   (a) the call passes through `show(` / `showBlock(`
 *   (b) the call is a `frameJsonBlock(`
 *   (c) the call is on the explicit ALLOWLIST below, keyed by file + a
 *       distinctive substring, each with a one-line reason
 *
 * The allowlist is the enumerated set of INTENTIONAL non-relayed emits, not a
 * catch-all — keep it minimal. A failure here names the file + line so a
 * developer either wraps the emit in `show(...)` or, if it is genuinely
 * status, adds it to the allowlist with a reason.
 */
import { existsSync, readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

// The wizard's user-facing emit surfaces. Add a new wizard script here when it
// starts writing to stdout — an unlisted file is invisible to this guard.
const FILES = [
  'src/intro.ts',
  'src/onboard.ts',
  'src/start-light.ts',
  'src/firstrun.ts',
  'src/firstrun-core.ts',
  'src/triage/adapter.ts',
  'src/remediation/entry.ts',
] as const;

const CALL_HEADS = ['process.stdout.write', 'deps.stdout'] as const;

interface EmitSite {
  file: string;
  line: number;
  // The full call expression text, e.g. `process.stdout.write(show(...))`.
  callText: string;
}

// Blank out every `//` line comment and `/* */` block comment in `source`,
// replacing their characters with spaces (newlines preserved) while leaving
// code and string/template literals byte-for-byte intact — so the result is
// the exact same length, with every index still lining up with `source`.
// Comment prose ("doesn't", "the wizard's `--posture` flag", `'redact-only'`)
// is full of apostrophes and stray parens that are NOT string literals or
// call parens; without this pass they get misread as one, throwing off the
// paren-depth count below. String/template literals are copied verbatim
// (not masked) so a real call's `(`/`)` balance is unaffected by this pass.
function maskComments(source: string): string {
  let out = '';
  let i = 0;
  while (i < source.length) {
    const ch = source[i];
    const next = source[i + 1];
    if (ch === '/' && next === '/') {
      while (i < source.length && source[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < source.length && !(source[i] === '*' && source[i + 1] === '/')) {
        out += source[i] === '\n' ? '\n' : ' ';
        i++;
      }
      out += '  ';
      i += 2;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const end = skipStringLiteral(source, i, ch);
      out += source.slice(i, end + 1);
      i = end + 1;
      continue;
    }
    out += source.charAt(i);
    i++;
  }
  return out;
}

// Find the index just past the matching close paren for the call opened at
// `openParenIndex` (which must point AT the '('), skipping over string/
// template literal contents (which may themselves contain unbalanced parens,
// e.g. `` `Plan saved to: ${x}` `` or `'AKA setup failed: ' + msg`) so they
// never perturb the depth count. Callers must run this over a
// comment-masked source (see maskComments) — a raw source's comment prose
// can itself contain unbalanced quotes/parens that would misread as code.
function matchingCloseParen(source: string, openParenIndex: number): number {
  let depth = 0;
  for (let i = openParenIndex; i < source.length; i++) {
    const ch = source[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipStringLiteral(source, i, ch);
      continue;
    }
    if (ch === '(') depth++;
    else if (ch === ')') {
      depth--;
      if (depth === 0) return i;
    }
  }
  throw new Error(`unbalanced parens scanning call at index ${String(openParenIndex)}`);
}

// Return the index of the unescaped closing quote matching `quote`, starting
// the scan right after the opening quote at `start`.
function skipStringLiteral(source: string, start: number, quote: string): number {
  let i = start + 1;
  for (; i < source.length; i++) {
    if (source[i] === '\\') {
      i++;
      continue;
    }
    if (source[i] === quote) return i;
  }
  return i;
}

// Every `process.stdout.write(...)` / `deps.stdout(...)` call site in
// `source`, in file order, with its 1-indexed source line and the full call
// expression text (spanning multiple lines is fine — callers only need the
// text to search, not a formatted statement). Call-head and paren-balance
// scanning runs over a comment-masked copy so comment prose can't be
// misread as code; the reported `callText` is sliced from the ORIGINAL
// source (same indices — masking preserves length and offsets) so
// violation messages show the real code, comments included.
function findEmitSites(file: string, source: string): EmitSite[] {
  const masked = maskComments(source);
  const sites: EmitSite[] = [];
  for (const head of CALL_HEADS) {
    let searchFrom = 0;
    for (;;) {
      const headIndex = masked.indexOf(head, searchFrom);
      if (headIndex === -1) break;
      const openParenIndex = masked.indexOf('(', headIndex + head.length);
      // Guard against a false hit like a `deps.stdout` property reference with
      // no immediately-following call (not expected in these files, but this
      // keeps the scan from throwing if one ever appears).
      if (
        openParenIndex === -1 ||
        masked.slice(headIndex + head.length, openParenIndex).trim() !== ''
      ) {
        searchFrom = headIndex + head.length;
        continue;
      }
      const closeParenIndex = matchingCloseParen(masked, openParenIndex);
      const line = source.slice(0, headIndex).split('\n').length;
      sites.push({
        file,
        line,
        callText: source.slice(headIndex, closeParenIndex + 1),
      });
      searchFrom = closeParenIndex + 1;
    }
  }
  return sites;
}

function passesThroughShow(callText: string): boolean {
  return /\bshow\(|\bshowBlock\(/.test(callText);
}

function isFrame(callText: string): boolean {
  return /\bframeJsonBlock\(/.test(callText);
}

interface AllowlistEntry {
  file: (typeof FILES)[number];
  substring: string;
  reason: string;
}

// The enumerated set of INTENTIONAL non-relayed stdout emits — model-facing
// STATUS, never user-facing copy. Keep this list explicit and minimal; a new
// entry needs a one-line reason a reviewer can check against the code.
const ALLOWLIST: AllowlistEntry[] = [
  {
    file: 'src/onboard.ts',
    substring: 'AKA setup failed:',
    reason:
      "fail()'s error line — a wizard-wiring/validation failure the model reads, never a relayed card.",
  },
  {
    file: 'src/start-light.ts',
    substring: 'AKA setup failed:',
    reason: "fail()'s error line — same as onboard.ts: model-facing STATUS, not user-facing copy.",
  },
  {
    file: 'src/firstrun.ts',
    substring: 'process.stdout.write(s)',
    reason:
      'The FirstRunDeps.stdout DI wiring: a pure passthrough callback. Its argument `s` is already ' +
      'wrapped in show(...)/frameJsonBlock(...) by firstrun-core.ts before it ever reaches this ' +
      'callback, so no raw content originates at this call site.',
  },
  {
    file: 'src/triage/adapter.ts',
    substring: 'Plan saved to:',
    reason:
      'The raw-free plan-file path printed for the wizard to hand to the confirm step — a ' +
      'model-facing STATUS path, not copy the user needs relayed.',
  },
  {
    file: 'src/triage/adapter.ts',
    substring: 'Re-run with:',
    reason:
      'The confirm re-run command line (apply-suppressions.js --confirmed --plan <path>) — ' +
      'model-facing STATUS instructing the model how to continue the chain, not user-facing copy.',
  },
];

function readSource(file: string): string {
  return readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
}

describe('wizard relay contract guard', () => {
  it.each(FILES)('scans an existing file: %s', (file) => {
    expect(existsSync(new URL(`../${file}`, import.meta.url))).toBe(true);
  });

  it('routes every stdout emit through show()/showBlock(), frameJsonBlock(), or the STATUS allowlist', () => {
    const violations: string[] = [];
    const usedAllowlistEntries = new Set<AllowlistEntry>();

    for (const file of FILES) {
      const source = readSource(file);
      for (const site of findEmitSites(file, source)) {
        if (passesThroughShow(site.callText) || isFrame(site.callText)) continue;

        const allow = ALLOWLIST.find(
          (entry) => entry.file === site.file && site.callText.includes(entry.substring),
        );
        if (allow) {
          usedAllowlistEntries.add(allow);
          continue;
        }

        violations.push(
          `${site.file}:${String(site.line)} — stdout emit is not wrapped in show()/showBlock(), ` +
            `is not a frameJsonBlock(), and matches no ALLOWLIST entry:\n` +
            `    ${site.callText.replace(/\s+/g, ' ').slice(0, 160)}\n` +
            `  Wrap it in show(...) (show(fenced(...)) for a card) if this is user-facing copy, ` +
            `or add it to ALLOWLIST in test/relay-contract-guard.test.ts with a one-line reason if ` +
            `it is genuinely model-facing STATUS.`,
        );
      }
    }

    expect(violations).toEqual([]);
  });

  it('keeps the STATUS allowlist minimal — every entry matches a real, current emit', () => {
    const stale: string[] = [];

    for (const entry of ALLOWLIST) {
      const source = readSource(entry.file);
      const sites = findEmitSites(entry.file, source);
      const stillMatches = sites.some(
        (site) =>
          !passesThroughShow(site.callText) &&
          !isFrame(site.callText) &&
          site.callText.includes(entry.substring),
      );
      if (!stillMatches) {
        stale.push(`${entry.file} — "${entry.substring}" (reason: ${entry.reason})`);
      }
    }

    expect(stale).toEqual([]);
  });
});
