/**
 * Setup-intro card — the first screen of the `/aka:setup` wizard: identity +
 * provenance on the header line, then the "what I do" body, shown before the
 * first question. Invoked by the wizard as:
 *
 *   node scripts/intro.js <path-to-.claude-plugin/plugin.json>
 *
 * The wizard passes the manifest path (it has ${CLAUDE_PLUGIN_ROOT} in the shell).
 * The card's factual fields — version, homepage — are read from that manifest so
 * it never drifts from the actually-installed plugin; the display name comes
 * from the identity constant. The manifest → card wiring lives in ./intro-card
 * so it unit-tests without touching the filesystem.
 *
 * Fail-open: an unreadable/old manifest still prints the card with the identity
 * copy and blank/placeholder facts — onboarding should never show a stack trace.
 */
import { readFileSync } from 'node:fs';

import { buildIntroCard, type Manifest } from './intro-card.ts';
import { fenced, show } from './present.ts';

const manifestPath = process.argv[2];

let manifest: Manifest = {};
try {
  manifest = JSON.parse(readFileSync(manifestPath ?? '', 'utf8')) as Manifest;
} catch {
  // Keep manifest empty; the card renders with identity copy + blank facts.
}

// Printed as a Markdown code fence so the wizard can echo it verbatim
// (space-aligned monospace collapses without the fence). Renders the version
// and repository line without a verified badge — it performs no provenance
// check or npm subprocess.
process.stdout.write(show(fenced(buildIntroCard(manifest))));

// Match the other adapter scripts (query.js, onboard.js) which hard-exit on
// completion so no stray handle can keep the process alive.
process.exit(0);
