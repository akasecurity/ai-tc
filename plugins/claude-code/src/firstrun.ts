/**
 * First-run screen — the install-complete frame of the `/aka:setup` wizard.
 *
 *   node scripts/firstrun.js
 *
 * Posture (per-category policy), findings (real count) and recommendations (same
 * count /recommend renders) are read live; the Health score is derived (see
 * render.healthScore — a documented heuristic, not stored data). Resolves the
 * same data gateway the read commands use, so the numbers match what /health
 * and /findings show. Rendering lives in ./render.
 *
 * Fail-open: an unreadable store prints a friendly note.
 */
import { openLocalDatabase } from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { readPostureBlock } from './posture.ts';
import { fenced } from './present.ts';
import { buildRecommendations, healthScore, renderFirstRun, topFindings } from './render.ts';

// The read surfaces this build registers.
const COMMANDS = ['/health', '/recommend', '/findings', '/audit'];

try {
  const cfg = loadConfig();
  const gateway = resolveDataGateway(cfg);
  try {
    const [summary, findings] = await Promise.all([
      gateway.healthSummary(),
      gateway.recentFindings({ limit: 500 }),
    ]);
    // "Recommendations" mirrors /recommend exactly — the same builder + cap — so
    // the card's count never disagrees with what that screen lists.
    const recommendations = buildRecommendations(findings).length;

    // Per-category posture — the wizard's policy write, read straight from the
    // local store so the card shows what's actually enforced, not the single
    // settings.policy string. readPostureBlock owns its own catch: a
    // policies-read fault degrades to '' so the card omits only the Posture
    // section (see renderFirstRun), rather than collapsing into the outer
    // fail-open note below.
    const postureBlock = await readPostureBlock(openLocalDatabase(cfg.dataDir));

    process.stdout.write(
      `${fenced(
        renderFirstRun({
          commands: COMMANDS,
          posture: postureBlock,
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
  process.stdout.write('AKA could not read your data yet. It populates as you use Claude Code.\n');
}

process.exit(0);
