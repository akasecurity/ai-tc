/**
 * Setup-intro card — the first screen of the `/aka:setup` wizard (the onboarding
 * mock). Invoked by the wizard as:
 *
 *   node scripts/intro.js <path-to-.claude-plugin/plugin.json>
 *
 * The wizard passes the manifest path (it has ${CLAUDE_PLUGIN_ROOT} in the shell).
 * Factual fields —
 * version, repository, publisher — are read from that manifest so the card never
 * drifts from the actually-installed plugin; the descriptive copy (display name,
 * tagline, "what it adds") is product wording supplied here. Rendering lives in
 * ./render so it unit-tests without touching the filesystem.
 *
 * Fail-open: an unreadable/old manifest still prints the card with the product
 * copy and blank/placeholder facts — onboarding should never show a stack trace.
 */
import { readFileSync } from 'node:fs';

import { fenced } from './present.ts';
import { renderSetupIntro } from './render.ts';

// Product copy. Not in the manifest because it's marketing wording, not a fact
// about the installed build — the values below ARE read from the manifest.
const NAME = 'AKA Security';
const TAGLINE = 'Agent Harness Security for Claude Code.';
const ADDS = 'Secures your local environment to prevent secret leakage and vulnerabilities.';

interface Manifest {
  version?: string;
  homepage?: string;
  author?: { name?: string } | string;
}

// "https://github.com/org/repo/tree/main/..." → "github.com/org/repo", the
// compact form the mock shows. Falls back to the raw value if it isn't a URL.
function repoLabel(homepage: string | undefined): string {
  if (!homepage) return '';
  const stripped = homepage.replace(/^https?:\/\//, '');
  const parts = stripped.split('/');
  return parts.length >= 3 ? parts.slice(0, 3).join('/') : stripped;
}

function authorName(author: Manifest['author']): string {
  if (typeof author === 'string') return author;
  return author?.name ?? '';
}

const manifestPath = process.argv[2];

let manifest: Manifest = {};
try {
  manifest = JSON.parse(readFileSync(manifestPath ?? '', 'utf8')) as Manifest;
} catch {
  // Keep manifest empty; the card renders with product copy + blank facts.
}

process.stdout.write(
  `${fenced(
    renderSetupIntro({
      name: NAME,
      tagline: TAGLINE,
      repository: repoLabel(manifest.homepage),
      version: manifest.version ?? '',
      publisher: authorName(manifest.author),
      adds: ADDS,
    }),
  )}\n`,
);

// Match the other adapter scripts (query.js, onboard.js) which hard-exit on
// completion so no stray handle can keep the process alive.
process.exit(0);
