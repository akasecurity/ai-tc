import { Linter } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';

import { noNetworkSyntax, reactSyntaxBans, tonalInkTokens } from '../src/index.js';

// The ambient-clock guard. A component under a `use client` directive is
// rendered twice — once on the server, once when the browser hydrates it — so a
// label derived from the clock can differ between the two renders whenever a
// rounding boundary falls between them, and React resolves that by discarding
// the server HTML for the subtree. The fix is a required `renderedAt` argument
// on the time helpers, which the compiler enforces; this ban is what stops the
// argument being satisfied with a fresh clock read at the call site, which
// typechecks perfectly and reintroduces the whole defect.
//
// Same shape as no-network.test.js and tonal-ink-tokens.test.js: lint snippets
// with the SHIPPED rule value imported from ../src/index.js, so weakening the
// ban in the config fails here rather than passing as a config-shape check.

const linter = new Linter();

/** The `no-restricted-syntax` value the three UI packages actually get. */
const SHIPPED_RULE = tonalInkTokens[0]?.rules?.['no-restricted-syntax'];

// The real parser, on a real .tsx filename. espree would do for the selectors
// themselves, but the directive-prologue node these are anchored on is produced
// by the PARSER, and typescript-eslint is the one that parses this repo's
// components. A selector that works under espree and not under this one would
// enforce nothing while every config assertion stayed green.
function lint(code, rule = SHIPPED_RULE) {
  return linter.verify(
    code,
    [
      {
        files: ['**/*.tsx'],
        languageOptions: {
          parser: tseslint.parser,
          ecmaVersion: 2024,
          sourceType: 'module',
          parserOptions: { ecmaFeatures: { jsx: true } },
        },
        rules: { 'no-restricted-syntax': rule },
      },
    ],
    'Component.tsx',
  );
}

const firedOn = (code, rule) => lint(code, rule).length;
const messagesFor = (code, rule) => lint(code, rule).map((m) => m.message);

const CLIENT = "'use client';\n";

describe('a client component may not read the clock', () => {
  it.each([
    ['Date.now() in the body', 'export function F() { return <b>{Date.now()}</b>; }'],
    ['a zero-argument new Date()', 'export function F() { return <b>{String(new Date())}</b>; }'],
    ['Date.now() in a nested closure', 'export const F = () => () => Date.now();'],
    ['Date.now() as a default argument', 'export function g(n = Date.now()) { return n; }'],
    [
      'Date.now() passed to a helper',
      'export function F() { return <b>{rel(x, Date.now())}</b>; }',
    ],
    [
      'a clock read inside a hook callback',
      'export function F() { useEffect(() => { setN(Date.now()); }); return null; }',
    ],
  ])('rejects %s', (_label, body) => {
    expect(firedOn(CLIENT + body)).toBe(1);
  });

  it('names the prop and the hook, so the fix is in the error', () => {
    const [message] = messagesFor(CLIENT + 'export function F() { return <b>{Date.now()}</b>; }');
    expect(message).toContain('renderedAt');
    expect(message).toContain('useRenderClock');
  });
});

// The two halves that make this usable rather than merely strict. Without the
// first, there would be nowhere left to capture an instant at all; without the
// second, every date the dashboard formats would be a violation.
describe('what it must NOT flag', () => {
  it('leaves a SERVER component alone — that is where an instant is captured', () => {
    expect(firedOn('export function Page() { const at = Date.now(); return <b>{at}</b>; }')).toBe(
      0,
    );
  });

  it.each([
    [
      'new Date(iso) — parses a value, reads no clock',
      'export function F({ x }) { return <b>{String(new Date(x))}</b>; }',
    ],
    ['Date.parse(iso)', 'export function F({ x }) { return <b>{Date.parse(x)}</b>; }'],
    [
      'a date built from explicit parts',
      'export function F() { return <b>{String(new Date(2026, 1, 1))}</b>; }',
    ],
    [
      'a member call that merely ends in now',
      'export function F({ c }) { return <b>{c.now()}</b>; }',
    ],
  ])('accepts %s in a client component', (_label, body) => {
    expect(firedOn(CLIENT + body)).toBe(0);
  });

  it('does not fire on a file that merely MENTIONS the directive as a value', () => {
    // A test or a build script may carry the string without being a client
    // module. The selector is anchored on the directive-prologue node, not on
    // the presence of the text.
    const code = "export const d = 'use client';\nexport function f() { return Date.now(); }\n";
    expect(firedOn(code)).toBe(0);
  });

  it('does NOT see a clock reached through a helper — a known, deliberate gap', () => {
    // Stated rather than fixed: an esquery selector cannot follow a binding.
    // The required `now` argument on the helpers is what covers this one.
    const code =
      CLIENT + 'import { clock } from "./clock";\nexport function F() { return <b>{clock()}</b>; }';
    expect(firedOn(code)).toBe(0);
  });
});

// A flat-config `rules` entry REPLACES this rule's options rather than merging
// them, so the assembled value has to carry every group at once — and the
// per-file opt-out has to be built the same way, or lifting one ban lifts four.
describe('the opt-out cannot become an opt-out for everything', () => {
  it('drops only the clock selectors, keeping the rest', () => {
    const withClock = reactSyntaxBans();
    const withoutClock = reactSyntaxBans({ allowAmbientClock: true });
    expect(withoutClock.length).toBe(withClock.length - 2);

    const kept = new Set(withoutClock.slice(1).map((e) => e.selector));
    for (const entry of withClock.slice(1)) {
      const isClockEntry = entry.selector.includes("directive='use client'");
      expect(kept.has(entry.selector)).toBe(!isClockEntry);
    }
  });

  it('still bans the network in a file that opted out of the clock ban', () => {
    const rule = reactSyntaxBans({ allowAmbientClock: true });
    expect(firedOn(CLIENT + "export const p = import('node:https');", rule)).toBe(1);
    expect(firedOn(CLIENT + 'export function F() { return Date.now(); }', rule)).toBe(0);
  });

  it('carries every selector noNetworkSyntax ships, not a subset', () => {
    const shipped = new Set(SHIPPED_RULE.slice(1).map((e) => e.selector));
    for (const entry of noNetworkSyntax().slice(1)) {
      expect(shipped.has(entry.selector)).toBe(true);
    }
  });

  it('is set to error, so it fails a lint run rather than warning', () => {
    expect(SHIPPED_RULE[0]).toBe('error');
  });
});
