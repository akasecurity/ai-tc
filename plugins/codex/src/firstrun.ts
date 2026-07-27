/**
 * First-run screen — the install-complete frame of the aka-setup wizard.
 *
 *   node scripts/firstrun.js
 *
 * Handling (from settings), findings (real count) and recommendations (same
 * count the aka-recommend skill renders) are read live; the Health score is
 * derived (see render.healthScore — a documented heuristic, not stored data).
 * Resolves the same data gateway the read commands use, so the numbers match
 * what aka-health and aka-findings show. Rendering lives in ./render.
 *
 * Fail-open: an unreadable store prints a friendly note.
 */
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { fenced } from './present.ts';
import { buildRecommendations, healthScore, renderFirstRun, topFindings } from './render.ts';

const HANDLING: Record<string, string> = {
  redact: 'Active redaction enabled',
  warn: 'Warn-only enabled',
};
// The read surfaces this build registers.
const COMMANDS = ['aka-health', 'aka-recommend', 'aka-findings', 'aka-audit'];

try {
  const cfg = loadConfig();
  const gateway = resolveDataGateway(cfg);
  try {
    const [summary, findings] = await Promise.all([
      gateway.healthSummary(),
      gateway.recentFindings({ limit: 500 }),
    ]);
    // "Recommendations" mirrors aka-recommend exactly — the same builder + cap
    // — so the card's count never disagrees with what that screen lists.
    const recommendations = buildRecommendations(findings).length;

    process.stdout.write(
      `${fenced(
        renderFirstRun({
          commands: COMMANDS,
          handling: HANDLING[cfg.settings.policy] ?? cfg.settings.policy,
          health: healthScore(summary),
          findings: summary.findings,
          recommendations,
          topFindings: topFindings(findings),
        }),
      )}\n`,
    );
  } finally {
    await gateway.close();
  }
} catch {
  process.stdout.write('AKA could not read your data yet. It populates as you use Codex.\n');
}

process.exit(0);
