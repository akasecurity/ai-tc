/**
 * Setup-intro cards — the first two screens of the `/aka:setup` wizard: the
 * kickoff card ("here I am") and the "what I do" card ("here's how I work"),
 * shown back-to-back before the first question. Invoked by the wizard as:
 *
 *   node scripts/intro.js <path-to-.claude-plugin/plugin.json>
 *
 * The wizard passes the manifest path (it has ${CLAUDE_PLUGIN_ROOT} in the shell).
 * The kickoff card's factual fields — version, homepage — are read from that
 * manifest so it never drifts from the actually-installed plugin; the display
 * copy (name, tagline, one-liner) comes from the identity constant. The manifest
 * → card wiring lives in ./intro-card so it unit-tests without touching the
 * filesystem. The "what I do" card is static copy from ./render.
 *
 * Fail-open: an unreadable/old manifest still prints the cards with the identity
 * copy and blank/placeholder facts — onboarding should never show a stack trace.
 */
import { readFileSync } from 'node:fs';

import { buildIntroCard, type Manifest } from './intro-card.ts';
import { fenced } from './present.ts';
import { renderWhatIDo } from './render.ts';

const manifestPath = process.argv[2];

let manifest: Manifest = {};
try {
  manifest = JSON.parse(readFileSync(manifestPath ?? '', 'utf8')) as Manifest;
} catch {
  // Keep manifest empty; the card renders with identity copy + blank facts.
}

// Each card is printed as its own Markdown code fence so the wizard can echo the
// pair verbatim (space-aligned monospace collapses without the fence). The
// kickoff card renders the version and repository line without a verified
// badge — it performs no provenance check or npm subprocess.
process.stdout.write(`${fenced(buildIntroCard(manifest))}\n\n${fenced(renderWhatIDo())}\n`);

// Match the other adapter scripts (query.js, onboard.js) which hard-exit on
// completion so no stray handle can keep the process alive.
process.exit(0);
