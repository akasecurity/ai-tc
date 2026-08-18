import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { Linter } from 'eslint';
import { describe, expect, it } from 'vitest';

import { noNetworkSyntax, tonalInkTokens } from '../src/index.js';

// The tonal-token guard: `--color-X` is the HUE (charts, dots, bars) and
// `--color-X-ink` is TEXT on that family's tint. The hue is deliberately too light
// to read as text, so reaching it through `text-*` renders at around 2:1 and fails
// WCAG 1.4.3 — silently, because it compiles and renders. A one-time sweep fixed
// every site; this is what stops the next one being written.
//
// Same shape as no-network.test.js: lint snippets with the SHIPPED rule value
// imported from ../src/index.js and assert observable lint output, so weakening
// the ban in the config fails here rather than passing as a config-shape check.

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const linter = new Linter();
const LANG = { ecmaVersion: 'latest', sourceType: 'module' };

/** The `no-restricted-syntax` value the three UI packages actually get. */
const SHIPPED_RULE = tonalInkTokens[0]?.rules?.['no-restricted-syntax'];

function lintTonal(code, rule = SHIPPED_RULE) {
  return linter.verify(code, {
    languageOptions: LANG,
    rules: { 'no-restricted-syntax': rule },
  });
}

const messagesFor = (code, rule) => lintTonal(code, rule).map((m) => m.message);
const firedOn = (code, rule) => lintTonal(code, rule).length;

// Every family whose bare token is a hue. Hard-coded rather than imported from the
// config, so adding a family there without extending this list is a visible diff
// here instead of a silent coverage gap.
const HUE_FAMILIES = ['sev-critical', 'sev-high', 'sev-medium', 'sev-low', 'ok', 'teal', 'violet'];

describe('the hue half of a tonal pair cannot reach text', () => {
  it.each(HUE_FAMILIES)('rejects text-%s', (family) => {
    expect(firedOn(`const c = 'text-${family}';`)).toBe(1);
  });

  it.each(HUE_FAMILIES)('accepts text-%s-ink', (family) => {
    expect(firedOn(`const c = 'text-${family}-ink';`)).toBe(0);
  });

  it('names the -ink form in the message, so the fix is in the error', () => {
    const [message] = messagesFor("const c = 'text-sev-critical';");
    expect(message).toContain('-ink');
    expect(message).toContain('theme.css');
  });
});

describe('what it must NOT flag', () => {
  // The hue is correct for every non-text mark — that is the entire reason the pair
  // exists, so a guard that also banned these would push people back to one token.
  it.each([
    "const c = 'bg-sev-critical';",
    "const c = 'bg-ok';",
    "const c = 'border-sev-high';",
    "const c = 'bg-sev-low-fill';",
    "const c = 'bg-teal-fill text-teal-ink';",
    "const c = 'decoration-sev-medium';",
  ])('leaves a non-text use alone: %s', (code) => {
    expect(firedOn(code)).toBe(0);
  });

  // --color-primary reads the other way round: it IS the ink, --color-primary-solid
  // is its fill. `text-primary` is the correct spelling and must stay lintable.
  it.each([
    "const c = 'text-primary';",
    "const c = 'bg-primary-tint text-primary';",
    "const c = 'text-primary-solid';",
  ])('leaves the inverted primary pair alone: %s', (code) => {
    expect(firedOn(code)).toBe(0);
  });

  it.each([
    "const c = 'text-text-3';",
    "const c = 'text-on-accent';",
    "const c = 'text-code-ok';",
    "const c = 'text-mark-fg';",
  ])('leaves an unrelated foreground token alone: %s', (code) => {
    expect(firedOn(code)).toBe(0);
  });

  // A word merely ending in one of the family names is not a utility class.
  it('does not fire on a longer word that happens to end in a family name', () => {
    expect(firedOn("const s = 'pretext-ok';")).toBe(0);
    expect(firedOn("const s = 'context-teal';")).toBe(0);
  });
});

describe('the forms these classes are actually written in', () => {
  it('catches it mid-class-list, where almost every real one lives', () => {
    expect(firedOn("const c = 'inline-flex gap-1 text-ok font-semibold';")).toBe(1);
  });

  it('catches it behind a variant prefix', () => {
    expect(firedOn("const c = 'hover:text-teal';")).toBe(1);
    expect(firedOn("const c = 'dark:text-sev-high';")).toBe(1);
  });

  it('catches it in a template literal, not only a plain string', () => {
    expect(firedOn('const c = `mt-1 text-sev-critical ${extra}`;')).toBe(1);
  });

  it('catches it in a JSX className', () => {
    const messages = linter.verify('<span className="text-ok-fill text-sev-low" />', {
      languageOptions: { ...LANG, parserOptions: { ecmaFeatures: { jsx: true } } },
      rules: { 'no-restricted-syntax': SHIPPED_RULE },
    });
    expect(messages).toHaveLength(1);
  });

  // The limit, stated as a test so it is not mistaken for coverage: a hue handed
  // over as a CSS variable string is the same node as a fill handed over the same
  // way (iconColor= vs iconBg=), so a selector cannot tell them apart.
  it('does NOT see a hue passed as a var() string — a known, deliberate gap', () => {
    expect(firedOn('const c = { iconColor: "var(--color-ok)" };')).toBe(0);
  });
});

// The sharp edge. A flat-config `rules` entry REPLACES the rule's options rather
// than merging them, so `tonalInkTokens` has to carry base's network selectors
// forward. Drop that spread and these three packages silently lose the dynamic
// import ban — with no failing test anywhere else, because every other suite
// checks base rather than this override.
describe('re-spreading the network ban it overrides', () => {
  it.each(["await import('node:http');", "require('axios');", "await import('undici');"])(
    'still bans %s',
    (code) => {
      expect(firedOn(code)).toBe(1);
    },
  );

  it('carries every selector noNetworkSyntax ships, not a subset', () => {
    const shipped = noNetworkSyntax().slice(1);
    const carried = /** @type {unknown[]} */ (SHIPPED_RULE).slice(1);
    for (const entry of shipped) {
      expect(carried).toContainEqual(entry);
    }
  });

  it('is set to error, so it fails a lint run rather than warning', () => {
    expect(/** @type {unknown[]} */ (SHIPPED_RULE)[0]).toBe('error');
  });
});
