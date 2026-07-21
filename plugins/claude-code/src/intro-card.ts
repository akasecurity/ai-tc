// Pure manifest → setup-intro-card wiring for the `/aka:setup` wizard's first
// screen. The display name comes from the identity constant; the factual fields
// (version, repository) come from the plugin manifest so the card never drifts
// from the installed build. No I/O here — the intro.ts adapter reads the
// manifest file and this turns it into the card, so the wiring unit-tests
// without touching the filesystem.
import { NAME } from './identity.ts';
import type { NpmRunner } from './provenance.ts';
import { verifyProvenance } from './provenance.ts';
import { renderSetupIntro } from './render.ts';

export interface Manifest {
  version?: string;
  homepage?: string;
}

// The npm package name the provenance check verifies. This is the publish
// identity from plugins/claude-code/package.json (`@akasecurity/ai-tc-claude-code`)
// — NOT the `.claude-plugin/plugin.json` `name` field ("aka"), which is the
// marketplace-display name and carries no npm provenance attestation.
export const PLUGIN_PACKAGE_NAME = '@akasecurity/ai-tc-claude-code';

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
export function buildIntroCard(manifest: Manifest, verified?: boolean): string {
  return renderSetupIntro({
    name: NAME,
    repository: repoLabel(manifest.homepage),
    version: manifest.version ?? '',
    verified: verified === true,
  });
}

// Composed builder: runs verifyProvenance() with the given runner, then builds
// the card with its result. It composes the kickoff card with a provenance
// badge when the injected verifier reports a matching attestation, and
// without the badge otherwise (fail-open). The shipped card render
// (./intro.ts, via buildIntroCard()) does not call this function.
// verifyProvenance() itself never throws (it fails open to false internally),
// but this still wraps the call — the plugin must never break the session on
// any failure mode.
export function buildVerifiedIntroCard(manifest: Manifest, runNpm?: NpmRunner): string {
  let verified: boolean;
  try {
    verified = verifyProvenance(
      { packageName: PLUGIN_PACKAGE_NAME, version: manifest.version ?? '' },
      runNpm,
    );
  } catch {
    verified = false;
  }
  return buildIntroCard(manifest, verified);
}
