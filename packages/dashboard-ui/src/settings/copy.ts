// Page-level copy for the Settings page. Lives in a plain (non-client) module so
// a Server Component page can import the string, and so the settings-copy guard
// can assert over it alongside the form.
//
// Deliberately neutral: the page's controls behave differently (a stored default
// vs. live consent gates), so the subtitle names no behavior — each control's own
// section describes what it does. The guard only forbids resurrecting a false
// live-effect claim here.
export const SETTINGS_PAGE_SUB =
  'Workspace configuration — the same knobs as the /aka:setup wizard.';
