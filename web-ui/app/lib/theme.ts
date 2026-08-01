// Theme preference: the stored choice, and the script that applies it before paint.
//
// The dashboard is a local Next server with no account, so the preference is a
// browser-local value (localStorage), not workspace state in ~/.aka. Nothing
// server-rendered depends on it — the class is applied by the inline script below
// before React hydrates.

/** The tri-state the user picks. 'system' defers to the OS setting. */
export type ThemePreference = 'light' | 'dark' | 'system';

export const THEME_PREFERENCES: readonly ThemePreference[] = ['light', 'dark', 'system'];

export const DEFAULT_THEME_PREFERENCE: ThemePreference = 'system';

/** localStorage key holding a ThemePreference. */
export const THEME_STORAGE_KEY = 'aka-theme';

/** The class the CSS keys off, on <html>. Matches the `.dark` block in theme.css. */
export const DARK_CLASS = 'dark';

/** The media query for the OS preference. Exported so the init-script test can pin it. */
export const DARK_QUERY = '(prefers-color-scheme: dark)';

export function isThemePreference(value: unknown): value is ThemePreference {
  return typeof value === 'string' && THEME_PREFERENCES.includes(value as ThemePreference);
}

// The last choice that could NOT be written to localStorage — blocked site data, or
// a full quota. This is the whole of what makes an unpersistable choice still apply
// for the page: the picker's value comes from readStoredPreference below, so without
// somewhere to hold it, a failed write means the next read misses it and the picker
// snaps back to the default with the theme never applied. Cleared by the next
// successful write and by a cross-tab write, so persisted state always wins once
// there is any. Lost on reload — nothing pretends otherwise.
let unpersisted: ThemePreference | null = null;

/** Reads the stored preference, falling back to the default when absent or unreadable. */
export function readStoredPreference(): ThemePreference {
  if (unpersisted !== null) return unpersisted;
  try {
    const raw = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemePreference(raw) ? raw : DEFAULT_THEME_PREFERENCE;
  } catch {
    // localStorage throws when site data is blocked; the default still renders.
    return DEFAULT_THEME_PREFERENCE;
  }
}

// Same-tab writes do not fire `storage` (that event is cross-tab only), so the
// store keeps its own listener set and notifies on write. Together the two cover
// both: this tab's picker, and the same dashboard open in another tab.
const preferenceListeners = new Set<() => void>();

/** Subscribes to preference changes, in this tab and across tabs. */
export function subscribePreference(onChange: () => void): () => void {
  preferenceListeners.add(onChange);
  const onStorage = (event: StorageEvent): void => {
    // `storage` fires for every key in the origin; ignore the ones that are not ours
    // so an unrelated write neither wakes React nor discards a held-in-memory choice.
    // A null key means the whole store was cleared, which does concern us.
    if (event.key !== null && event.key !== THEME_STORAGE_KEY) return;
    // Another tab persisted a choice, so storage is authoritative again.
    unpersisted = null;
    onChange();
  };
  window.addEventListener('storage', onStorage);
  return () => {
    preferenceListeners.delete(onChange);
    window.removeEventListener('storage', onStorage);
  };
}

export function storePreference(preference: ThemePreference): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
    unpersisted = null;
  } catch {
    // Not persisting is survivable: hold the choice in memory so it still applies for
    // this page. It does not survive a reload.
    unpersisted = preference;
  }
  for (const listener of preferenceListeners) listener();
}

export function prefersDark(): boolean {
  return window.matchMedia(DARK_QUERY).matches;
}

/** Applies a resolved theme to <html>. The only place the class is written. */
export function applyTheme(theme: 'light' | 'dark'): void {
  document.documentElement.classList.toggle(DARK_CLASS, theme === 'dark');
}

/** Subscribes to OS theme changes. Returns an unsubscribe. */
export function subscribeSystemTheme(onChange: () => void): () => void {
  const query = window.matchMedia(DARK_QUERY);
  query.addEventListener('change', onChange);
  return () => {
    query.removeEventListener('change', onChange);
  };
}

// Server snapshots for useSyncExternalStore. The rendered HTML cannot know the
// browser's preference, so it assumes the default; the inline script has already
// put the right class on <html>, and React swaps to the client snapshot on hydration.
export function serverPreference(): ThemePreference {
  return DEFAULT_THEME_PREFERENCE;
}

export function serverPrefersDark(): boolean {
  return false;
}

/**
 * The blocking script injected into <head>. It runs before first paint, so the
 * correct theme is on <html> before anything renders and there is no light flash
 * on a dark-mode load.
 *
 * It is a string rather than an imported function because it has to execute ahead
 * of the bundle.
 *
 * Deliberately a FLAT LITERAL, not built from the constants above. This string is
 * injected with dangerouslySetInnerHTML, so interpolating into it is code
 * construction — and `JSON.stringify` does not escape `</script>`, which makes it
 * the wrong escape for an HTML script context however safe the inputs look today.
 * Keeping it literal removes the sink outright.
 *
 * The values below still have to match the constants above; that agreement is
 * pinned by web-ui/test/theme-init-script.test.ts rather than by construction.
 *
 * The condition is `p !== "light"`, not `p === null || p === "system"`, so an
 * unrecognized stored value resolves the same way here as it does in
 * readStoredPreference — which runs it through isThemePreference and falls back to
 * DEFAULT_THEME_PREFERENCE, i.e. follow the OS. Enumerating the two known keys
 * instead sends a garbage value (a hand-edit, or a preference written by a later
 * version and then rolled back) to light here and to the OS setting there: on an
 * OS-dark machine the page would paint light and the effect would flip it to dark,
 * which is the exact flash this script exists to prevent. That shape encodes
 * DEFAULT_THEME_PREFERENCE === 'system'; the test asserts the default, so changing
 * it cannot silently leave this line behind.
 */
export const THEME_INIT_SCRIPT =
  '(function(){try{var p=localStorage.getItem("aka-theme");var d=p==="dark"||(p!=="light"&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d);}catch(e){}})();';
