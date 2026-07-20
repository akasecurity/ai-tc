// First-run nudge copy for the UserPromptSubmit hook, kept in its own module
// (no main() side effect) so it is the single source of truth for the
// once-per-session "installed but not calibrated" pointer.

/**
 * The one-line pointer shown once per session on a machine that has not yet
 * completed `/aka:setup`: AKA is installed but not calibrated to this machine.
 */
export const ONBOARDING_NUDGE =
  'AKA Security is installed but not calibrated — run /aka:setup to tune notifications to this machine (about a minute).';
