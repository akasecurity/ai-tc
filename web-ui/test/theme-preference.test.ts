import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type * as ThemeModule from '../app/lib/theme.ts';

// The theme module's own surface — the half that runs for the rest of the session,
// after the pre-paint script in theme-init-script.test.ts has done its one job.
//
// It reads `window.localStorage` / `window.matchMedia` and writes
// `document.documentElement`, all lazily inside functions, so a stubbed global is
// enough and this suite stays on the package's `node` environment (no jsdom).
//
// Every test re-imports the module through vi.resetModules(): it holds two pieces
// of state — the unpersisted-choice fallback and the listener set — and a suite
// that shared them would pass on the previous test's leftovers.

interface StorageStub {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

function loadTheme(storage: StorageStub, systemDark = false) {
  vi.resetModules();
  const listeners = new Map<string, Set<(event: unknown) => void>>();
  vi.stubGlobal('window', {
    localStorage: storage,
    matchMedia: (query: string) => ({
      matches: query === '(prefers-color-scheme: dark)' && systemDark,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }),
    addEventListener: (type: string, fn: (event: unknown) => void) => {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type)?.add(fn);
    },
    removeEventListener: (type: string, fn: (event: unknown) => void) => {
      listeners.get(type)?.delete(fn);
    },
  });
  const classes = new Set<string>();
  vi.stubGlobal('document', {
    documentElement: {
      classList: {
        toggle: (token: string, force: boolean) => {
          if (force) classes.add(token);
          else classes.delete(token);
        },
      },
    },
  });
  /** Fires a `storage` event at whatever the module subscribed. */
  const fireStorage = (key: string | null): void => {
    for (const fn of listeners.get('storage') ?? []) fn({ key });
  };
  return { module: import('../app/lib/theme.ts'), classes, fireStorage };
}

/** A localStorage stub whose write can be made to fail the way a real one does. */
function storageStub(initial: string | null, opts: { failWrites?: boolean } = {}): StorageStub {
  let value = initial;
  return {
    getItem: () => value,
    setItem: (_key, next) => {
      // Blocked site data and a full quota both surface as a throw from setItem.
      if (opts.failWrites) throw new Error('QuotaExceededError');
      value = next;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('readStoredPreference', () => {
  it('returns a stored value that is a known preference', async () => {
    const { module } = loadTheme(storageStub('dark'));
    const theme = await module;
    expect(theme.readStoredPreference()).toBe('dark');
  });

  it('falls back to the default for an unrecognized stored value', async () => {
    const { module } = loadTheme(storageStub('high-contrast'));
    const theme = await module;
    expect(theme.readStoredPreference()).toBe(theme.DEFAULT_THEME_PREFERENCE);
  });

  it('falls back to the default when the read itself throws', async () => {
    const { module } = loadTheme({
      getItem: () => {
        throw new Error('site data blocked');
      },
      setItem: () => undefined,
    });
    const theme = await module;
    expect(theme.readStoredPreference()).toBe(theme.DEFAULT_THEME_PREFERENCE);
  });
});

describe('storePreference when the write fails', () => {
  // The property: an unwritable choice still applies for this page. Seeded with a
  // DIFFERENT valid value on purpose — storage stays readable and keeps returning
  // 'light', so a module that re-reads storage answers 'light' and the picker snaps
  // back. Only holding the choice in memory answers 'dark'.
  it('still reports the choice the user made', async () => {
    const { module } = loadTheme(storageStub('light', { failWrites: true }));
    const theme = await module;
    expect(theme.readStoredPreference()).toBe('light');

    theme.storePreference('dark');

    expect(theme.readStoredPreference()).toBe('dark');
  });

  it('notifies subscribers, so the picker re-reads', async () => {
    const { module } = loadTheme(storageStub('light', { failWrites: true }));
    const theme = await module;
    const onChange = vi.fn();
    theme.subscribePreference(onChange);

    theme.storePreference('dark');

    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('does not throw out of storePreference', async () => {
    const { module } = loadTheme(storageStub(null, { failWrites: true }));
    const theme = await module;
    expect(() => {
      theme.storePreference('dark');
    }).not.toThrow();
  });
});

describe('storePreference when the write succeeds', () => {
  it('reports the new choice from storage', async () => {
    const { module } = loadTheme(storageStub('light'));
    const theme = await module;
    theme.storePreference('dark');
    expect(theme.readStoredPreference()).toBe('dark');
  });

  // Without this, a single failed write would pin the value for the rest of the
  // page: the in-memory hold wins over storage, so it has to be released the moment
  // storage can carry the choice again.
  it('releases a choice held from an earlier failed write', async () => {
    let failWrites = true;
    let value: string | null = 'light';
    const { module } = loadTheme({
      getItem: () => value,
      setItem: (_key, next) => {
        if (failWrites) throw new Error('QuotaExceededError');
        value = next;
      },
    });
    const theme = await module;

    theme.storePreference('dark');
    expect(theme.readStoredPreference()).toBe('dark');

    failWrites = false;
    theme.storePreference('light');

    expect(theme.readStoredPreference()).toBe('light');
  });
});

describe('subscribePreference', () => {
  it('notifies on a cross-tab write to the theme key', async () => {
    const { module, fireStorage } = loadTheme(storageStub('light'));
    const theme = await module;
    const onChange = vi.fn();
    theme.subscribePreference(onChange);

    fireStorage(theme.THEME_STORAGE_KEY);

    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('notifies when the whole store is cleared (a null key)', async () => {
    const { module, fireStorage } = loadTheme(storageStub('light'));
    const theme = await module;
    const onChange = vi.fn();
    theme.subscribePreference(onChange);

    fireStorage(null);

    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('ignores a write to some other key in the origin', async () => {
    const { module, fireStorage } = loadTheme(storageStub('light'));
    const theme = await module;
    const onChange = vi.fn();
    theme.subscribePreference(onChange);

    fireStorage('some-other-app-key');

    expect(onChange).not.toHaveBeenCalled();
  });

  // A cross-tab write means the choice IS persisted now, so the in-memory hold from
  // this tab's earlier failure has to yield to it rather than mask it forever.
  it('drops a locally held choice when another tab persists one', async () => {
    let value: string | null = 'light';
    const { module, fireStorage } = loadTheme({
      getItem: () => value,
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
    });
    const theme = await module;
    theme.subscribePreference(() => undefined);

    theme.storePreference('dark');
    expect(theme.readStoredPreference()).toBe('dark');

    value = 'light';
    fireStorage(theme.THEME_STORAGE_KEY);

    expect(theme.readStoredPreference()).toBe('light');
  });

  it('removes its listener on unsubscribe', async () => {
    const { module, fireStorage } = loadTheme(storageStub('light'));
    const theme = await module;
    const onChange = vi.fn();
    const unsubscribe = theme.subscribePreference(onChange);

    unsubscribe();
    fireStorage(theme.THEME_STORAGE_KEY);

    expect(onChange).not.toHaveBeenCalled();
  });
});

describe('applyTheme', () => {
  let classes: Set<string>;
  let theme: typeof ThemeModule;

  beforeEach(async () => {
    const loaded = loadTheme(storageStub(null));
    classes = loaded.classes;
    theme = await loaded.module;
  });

  it('adds the dark class for dark', () => {
    theme.applyTheme('dark');
    expect([...classes]).toEqual([theme.DARK_CLASS]);
  });

  it('removes it for light, rather than leaving whatever was there', () => {
    theme.applyTheme('dark');
    theme.applyTheme('light');
    expect([...classes]).toEqual([]);
  });
});
