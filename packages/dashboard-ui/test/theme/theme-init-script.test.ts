import { runInNewContext } from 'node:vm';

import { describe, expect, it } from 'vitest';

import {
  DARK_CLASS,
  DARK_QUERY,
  DEFAULT_THEME_PREFERENCE,
  isThemePreference,
  THEME_INIT_SCRIPT,
  THEME_STORAGE_KEY,
} from '../../src/theme/theme.ts';

// THEME_INIT_SCRIPT is a flat literal, injected via dangerouslySetInnerHTML in the
// root layout. It is deliberately NOT built from the constants it embeds — string
// interpolation into a <script> body is code construction, and `JSON.stringify` does
// not escape `</script>`, so it is the wrong escape for that context.
//
// That leaves the literal free to drift from the module. These tests are what pins
// it: they run the real script against stubs and assert it reads, queries and
// toggles exactly the exported constants. Change a constant without changing the
// literal (or vice versa) and this fails.

interface Run {
  /** Classes the script left enabled on <html>. */
  classes: string[];
  /** Keys it read from localStorage. */
  readKeys: string[];
  /** Media queries it asked about. */
  queries: string[];
}

function runInitScript(opts: {
  stored?: string | null;
  systemDark?: boolean;
  throwOnRead?: boolean;
}): Run {
  const { stored = null, systemDark = false, throwOnRead = false } = opts;
  const classes = new Set<string>();
  const readKeys: string[] = [];
  const queries: string[] = [];

  const localStorageStub = {
    getItem(key: string): string | null {
      readKeys.push(key);
      if (throwOnRead) throw new Error('site data blocked');
      return key === THEME_STORAGE_KEY ? stored : null;
    },
  };
  const matchMediaStub = (query: string): { matches: boolean } => {
    queries.push(query);
    return { matches: query === DARK_QUERY && systemDark };
  };
  const documentStub = {
    documentElement: {
      classList: {
        toggle(token: string, force: boolean): void {
          if (force) classes.add(token);
          else classes.delete(token);
        },
      },
    },
  };

  // The script reads `localStorage`/`matchMedia`/`document` as bare globals, so it runs
  // in a fresh context whose globals are exactly these stubs — nothing else is reachable
  // from it, and the real page objects are untouched.
  runInNewContext(THEME_INIT_SCRIPT, {
    localStorage: localStorageStub,
    matchMedia: matchMediaStub,
    document: documentStub,
  });

  return { classes: [...classes], readKeys, queries };
}

describe('THEME_INIT_SCRIPT — the pre-paint theme script', () => {
  it('uses exactly the exported storage key, media query and class', () => {
    const run = runInitScript({ stored: 'system', systemDark: true });
    expect(run.readKeys).toEqual([THEME_STORAGE_KEY]);
    expect(run.queries).toEqual([DARK_QUERY]);
    expect(run.classes).toEqual([DARK_CLASS]);
  });

  it('applies dark for an explicit dark preference, whatever the OS says', () => {
    expect(runInitScript({ stored: 'dark', systemDark: false }).classes).toEqual([DARK_CLASS]);
  });

  it('stays light for an explicit light preference, even when the OS is dark', () => {
    expect(runInitScript({ stored: 'light', systemDark: true }).classes).toEqual([]);
  });

  it('follows the OS when the preference is "system"', () => {
    expect(runInitScript({ stored: 'system', systemDark: true }).classes).toEqual([DARK_CLASS]);
    expect(runInitScript({ stored: 'system', systemDark: false }).classes).toEqual([]);
  });

  // The script's "anything that is not light follows the OS" shape is only correct
  // while the module's fallback IS 'system'. Assert the constant rather than only
  // interpolating it into a title: a title cannot fail, so flipping the default to
  // 'light' would leave the two silently disagreeing under a name that now lies.
  it('is written against a "system" default, and says so where it can fail', () => {
    expect(DEFAULT_THEME_PREFERENCE).toBe('system');
  });

  it(`follows the OS when nothing is stored (default is "${DEFAULT_THEME_PREFERENCE}")`, () => {
    expect(runInitScript({ stored: null, systemDark: true }).classes).toEqual([DARK_CLASS]);
    expect(runInitScript({ stored: null, systemDark: false }).classes).toEqual([]);
  });

  // An unrecognized value is what a hand-edit leaves, or a preference written by a
  // later version and then rolled back. readStoredPreference runs it through
  // isThemePreference and falls back to DEFAULT_THEME_PREFERENCE, so the script has
  // to reach the same answer — otherwise the pre-paint class and the hydrated one
  // disagree and the page flashes, which is the one thing the script is for.
  it('treats an unrecognized stored value the way the module does — as the default', () => {
    for (const stored of ['blue', 'Dark', 'high-contrast', '']) {
      const resolved = isThemePreference(stored) ? stored : DEFAULT_THEME_PREFERENCE;
      expect(resolved).toBe('system');
      expect(runInitScript({ stored, systemDark: true }).classes).toEqual([DARK_CLASS]);
      expect(runInitScript({ stored, systemDark: false }).classes).toEqual([]);
    }
  });

  it('fails open to light when localStorage throws, rather than breaking the page', () => {
    expect(() => runInitScript({ throwOnRead: true, systemDark: true })).not.toThrow();
    expect(runInitScript({ throwOnRead: true, systemDark: true }).classes).toEqual([]);
  });

  // The reason the literal is flat. A `</script>` anywhere in the body would close the
  // injected element early and turn the rest into markup.
  it('carries nothing that could terminate the <script> element it is injected into', () => {
    expect(THEME_INIT_SCRIPT).not.toMatch(/<\/script/i);
    expect(THEME_INIT_SCRIPT).not.toContain('<!--');
  });
});
