/**
 * Status line — the persistent AKA footer wired into Claude Code's statusLine
 * command (settings.json). The harness invokes it on each refresh with the
 * status-line context as JSON on stdin (drained but not needed):
 *
 *   node scripts/statusline.js
 *
 * Resolves the same data gateway the read commands use and prints a single line
 * (health score · unreviewed-by-severity · open findings) with no trailing
 * newline. Unlike the transcript read surfaces, statusLine DOES render ANSI, so
 * open findings show in red (see renderStatusLine). Rendering lives in ./render.
 *
 * Fail-open: any error prints nothing and exits 0 — the status line must never
 * break the user's prompt.
 */
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { readStdin } from './hooks/shared.ts';
import { renderStatusLine } from './render.ts';

try {
  await readStdin(); // drain the status-line context the harness sends; unused
  const cfg = loadConfig();
  const gateway = resolveDataGateway(cfg);
  try {
    // The status line reads entirely from the whole-store health summary (score,
    // unreviewed-by-severity tally, open-findings total), so no findings page is
    // needed — one fewer read on every status-line refresh.
    process.stdout.write(renderStatusLine(await gateway.healthSummary()));
  } finally {
    await gateway.close();
  }
} catch {
  // Fail-open: a missing/locked store prints nothing.
}

process.exit(0);
