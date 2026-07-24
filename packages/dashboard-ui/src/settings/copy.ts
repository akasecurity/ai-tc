// Page-level copy for the Settings page. Lives in a plain (non-client) module so
// a Server Component page can import the string, and so the settings-copy guard
// covers the page head alongside the form.
//
// The knobs on this page are stored preferences: `settings.policy` does not drive
// runtime enforcement — the per-category Policies do — so the copy must not
// promise a live effect.
export const SETTINGS_PAGE_SUB =
  'Stored workspace preferences — the same knobs as the /aka:setup wizard. ' +
  'Enforcement is set per category on the Policies page.';
