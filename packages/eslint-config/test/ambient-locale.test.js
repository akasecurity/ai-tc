import { Linter } from 'eslint';
import tseslint from 'typescript-eslint';
import { describe, expect, it } from 'vitest';

import { reactSyntaxBans, tonalInkTokens, tonalInkTokensPresentational } from '../src/index.js';

// The ambient-locale guard. A component under a `use client` directive is
// rendered twice — once on the server, once when the browser hydrates it — and
// a number or date formatted with no locale reads each renderer's OWN locale, so
// a Node host on en-US emits `1,234` where a de-DE browser hydrates `1.234`. The
// fix is a required `locale` argument on the shared formatters, which the
// compiler enforces; this ban is what stops a call site formatting around them
// with a bare toLocaleString(), which typechecks perfectly.
//
// Same shape as ambient-clock.test.js: lint snippets against rule VALUES built
// from ../src/index.js, so a selector removed or broken in `reactSyntaxBans`
// fails here. What this suite cannot see is whether a package's config still
// applies the widened value — `PRESENTATIONAL_RULE` and `ROUTE_RULE` below are
// built here, not read from the config that ships them. That half is
// package-walls.test.js's, which resolves each package's REAL config.

const linter = new Linter();

/** The directive-scoped value every React UI package gets as its floor. */
const SHIPPED_RULE = tonalInkTokens[0]?.rules?.['no-restricted-syntax'];
/** The widened value `dashboard-ui`/`ui-kit` get under `src/**`. */
const PRESENTATIONAL_RULE = tonalInkTokensPresentational[0]?.rules?.['no-restricted-syntax'];
/** The widened value web-ui's eslint.config.mjs gives every module under `app/`. */
const ROUTE_RULE = reactSyntaxBans({ ambientLocaleEveryModule: true });

// The real parser, on a real .tsx filename — see ambient-clock.test.js for why
// espree is not a stand-in for the directive-prologue node these anchor on.
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

const CLIENT = "'use client';\n";

const DEFAULT_LOCALE_SHAPES = [
  ['n.toLocaleString()', 'export function F({ n }) { return <b>{n.toLocaleString()}</b>; }'],
  [
    'toLocaleString(undefined, options)',
    'export function F({ n }) { return <b>{n.toLocaleString(undefined, { maximumFractionDigits: 1 })}</b>; }',
  ],
  [
    'toLocaleString([], options) — the empty-array spelling',
    'export function F({ d }) { return <b>{d.toLocaleString([], { month: "short" })}</b>; }',
  ],
  ['toLocaleDateString()', 'export function F({ d }) { return <b>{d.toLocaleDateString()}</b>; }'],
  [
    'toLocaleTimeString([], options)',
    'export function F({ d }) { return <b>{d.toLocaleTimeString([], { hour: "2-digit" })}</b>; }',
  ],
  ['new Intl.NumberFormat()', 'export const f = new Intl.NumberFormat();'],
  [
    'new Intl.NumberFormat(undefined, options)',
    'export const f = new Intl.NumberFormat(undefined, { notation: "compact" });',
  ],
  ['Intl.NumberFormat() called without new', 'export const f = Intl.NumberFormat();'],
  [
    'new Intl.DateTimeFormat([], options)',
    'export const f = new Intl.DateTimeFormat([], { hour: "numeric" });',
  ],
  ['new Intl.RelativeTimeFormat()', 'export const f = new Intl.RelativeTimeFormat();'],
  ['new Intl.PluralRules()', 'export const f = new Intl.PluralRules();'],
  ['new Intl.ListFormat()', 'export const f = new Intl.ListFormat();'],
  [
    'new Intl.DisplayNames(undefined, options)',
    'export const f = new Intl.DisplayNames(undefined, { type: "region" });',
  ],
];

describe('a client component may not format in the runtime’s locale', () => {
  it.each(DEFAULT_LOCALE_SHAPES)('rejects %s', (_label, body) => {
    expect(firedOn(CLIENT + body)).toBe(1);
  });

  it('names the prop and the formatters, so the fix is in the error', () => {
    const [first] = lint(
      CLIENT + 'export function F({ n }) { return <b>{n.toLocaleString()}</b>; }',
    );
    expect(first?.message).toContain('locale');
    expect(first?.message).toContain('renderLocale()');
    expect(first?.message).toContain('formatNumber');
    expect(first?.message).toContain('formatDateTime');
  });
});

describe('what it must NOT flag', () => {
  it.each([
    [
      'a locale passed as a variable — the `locale` prop',
      'export function F({ n, locale }) { return <b>{n.toLocaleString(locale)}</b>; }',
    ],
    [
      'a pinned locale literal — compact notation is pinned to en-US',
      'export const f = new Intl.NumberFormat("en-US", { notation: "compact" });',
    ],
    [
      'Intl.DateTimeFormat with a locale variable',
      'export function F(locale) { return new Intl.DateTimeFormat(locale, { hour: "numeric" }); }',
    ],
    [
      'localeCompare, which collates rather than displays',
      'export function F(a, b) { return a.localeCompare(b); }',
    ],
    ['a member that merely starts with toLocale', 'export function F(o) { return o.toLocaleX(); }'],
  ])('accepts %s in a client component', (_label, body) => {
    expect(firedOn(CLIENT + body)).toBe(0);
  });

  it('leaves a module with no directive alone under the directive-scoped floor', () => {
    // A test file or a build script is not a client module; the floor's
    // selector is anchored on the directive-prologue node.
    expect(firedOn('export function f(n) { return n.toLocaleString(); }')).toBe(0);
  });
});

// The two widened forms. A presentational helper module carries no component
// and so no directive (format.ts, data.ts), and a Server Component carries none
// either while rendering in the Node process's locale — so both are invisible to
// the directive-scoped floor, which is exactly where the sites this replaced
// lived.
describe('the widened forms reach a module with no directive of its own', () => {
  it.each([
    ['the presentational packages', PRESENTATIONAL_RULE],
    ['web-ui routes', ROUTE_RULE],
  ])('rejects every default-locale shape in %s, directive or not', (_label, rule) => {
    for (const [, body] of DEFAULT_LOCALE_SHAPES) {
      expect(firedOn(body, rule)).toBe(1);
      expect(firedOn(CLIENT + body, rule)).toBe(1);
    }
  });

  it('the FLOOR does not catch a Server Component’s toLocaleString — the regression this closes', () => {
    const page =
      'export default async function Page() { const n = await count(); return <b>{n.toLocaleString()}</b>; }';
    expect(firedOn(page, SHIPPED_RULE)).toBe(0);
    expect(firedOn(page, ROUTE_RULE)).toBe(1);
  });

  it('keeps the clock ban directive-scoped in the route form, where a Server Component captures an instant', () => {
    expect(firedOn('export function Page() { return <b>{Date.now()}</b>; }', ROUTE_RULE)).toBe(0);
  });
});

describe('the opt-out cannot become an opt-out for everything', () => {
  const isLocaleEntry = (entry) => entry.message.includes('RENDERER');

  it('drops only the locale selectors, keeping the rest', () => {
    const withLocale = reactSyntaxBans();
    const withoutLocale = reactSyntaxBans({ allowAmbientLocale: true });
    const localeCount = withLocale.slice(1).filter(isLocaleEntry).length;
    expect(localeCount).toBe(6);
    expect(withoutLocale.length).toBe(withLocale.length - localeCount);
    expect(withoutLocale.slice(1).some(isLocaleEntry)).toBe(false);
  });

  it('still bans the network and the clock in a file that opted out of the locale ban', () => {
    const rule = reactSyntaxBans({ allowAmbientLocale: true });
    expect(firedOn(CLIENT + "export const p = import('node:https');", rule)).toBe(1);
    expect(firedOn(CLIENT + 'export function F() { return Date.now(); }', rule)).toBe(1);
    expect(firedOn(CLIENT + 'export function F(n) { return n.toLocaleString(); }', rule)).toBe(0);
  });

  it('allowAmbientLocale wins over ambientLocaleEveryModule', () => {
    const rule = reactSyntaxBans({ allowAmbientLocale: true, ambientLocaleEveryModule: true });
    expect(firedOn('export function f(n) { return n.toLocaleString(); }', rule)).toBe(0);
  });

  it('the route form still bans the network and Drizzle — the assembly is not a bare override', () => {
    expect(firedOn("export const p = import('node:https');", ROUTE_RULE)).toBe(1);
    expect(firedOn("await import('drizzle-orm');", ROUTE_RULE)).toBe(1);
  });
});
