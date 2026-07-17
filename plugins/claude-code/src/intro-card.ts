// Pure manifest → setup-intro-card wiring for the `/aka:setup` wizard's first
// screen. The display copy (name, tagline, one-liner) comes from the identity
// constant; the factual fields (version, repository) come from the plugin
// manifest so the card never drifts from the installed build. No I/O here — the
// intro.ts adapter reads the manifest file and this turns it into the card, so
// the wiring unit-tests without touching the filesystem.
import { NAME, ONE_LINER, TAGLINE } from './identity.ts';
import { renderSetupIntro } from './render.ts';

export interface Manifest {
  version?: string;
  homepage?: string;
}

// "https://github.com/org/repo/tree/main/..." → "github.com/org/repo", the
// compact form the card shows. Falls back to the raw value if it isn't a URL.
function repoLabel(homepage: string | undefined): string {
  if (!homepage) return '';
  const stripped = homepage.replace(/^https?:\/\//, '');
  const parts = stripped.split('/');
  return parts.length >= 3 ? parts.slice(0, 3).join('/') : stripped;
}

// Fail-open: an empty manifest (unreadable/old plugin.json) still yields a card
// with the identity copy and blank facts — onboarding never shows a stack trace.
export function buildIntroCard(manifest: Manifest): string {
  return renderSetupIntro({
    name: NAME,
    tagline: TAGLINE,
    oneLiner: ONE_LINER,
    repository: repoLabel(manifest.homepage),
    version: manifest.version ?? '',
  });
}
