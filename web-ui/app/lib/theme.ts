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

/** Reads the stored preference, falling back to the default when absent or unreadable. */
export function readStoredPreference(): ThemePreference {
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
  window.addEventListener('storage', onChange);
  return () => {
    preferenceListeners.delete(onChange);
    window.removeEventListener('storage', onChange);
  };
}

export function storePreference(preference: ThemePreference): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, preference);
  } catch {
    // Not persisting is survivable — the choice still applies for this page.
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
 */
export const THEME_INIT_SCRIPT =
  '(function(){try{var p=localStorage.getItem("aka-theme");var d=p==="dark"||((p===null||p==="system")&&matchMedia("(prefers-color-scheme: dark)").matches);document.documentElement.classList.toggle("dark",d);}catch(e){}})();';
