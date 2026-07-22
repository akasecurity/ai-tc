/**
 * First-run screen — the install-complete frame of the `/aka:setup` wizard.
 * UNTESTABLE GLUE only: it wires real IO (config, data gateway, posture store,
 * stdout) into the dependency-injected core in ./firstrun-core.ts, which holds
 * the logic (and its tests).
 *
 *   node scripts/firstrun.js [--surfaced <n>] [--live-keys <n>]
 *
 * Posture (per-category policy), findings (real count) and recommendations (same
 * count /recommend renders) are read live; the Health score is derived (see
 * render.healthScore — a documented heuristic, not stored data). Resolves the
 * same data gateway the read commands use, so the numbers match what /health
 * and /findings show. Rendering lives in ./render.
 *
 * `--surfaced <n>` is the surfaced/important count from the calibration preview,
 * threaded through by the wizard orchestration into the handoff-offer payload —
 * see ./firstrun-core.ts. `--live-keys <n>` is the narrower surfaced live-key
 * secret count that gates the remediation chain-entry offer.
 *
 * Fail-open: an unreadable store prints a friendly note.
 */
import { openLocalDatabase } from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { runFirstRunFailOpen } from './firstrun-core.ts';
import { readPostureBlock } from './posture.ts';
import { show } from './present.ts';
import { STORE_UNAVAILABLE_NOTE } from './render.ts';

try {
  const cfg = loadConfig();
  const gateway = resolveDataGateway(cfg);
  try {
    await runFirstRunFailOpen({
      argv: process.argv.slice(2),
      gateway,
      readPosture: () => readPostureBlock(() => openLocalDatabase(cfg.dataDir)),
      stdout: (s) => process.stdout.write(s),
    });
  } finally {
    await gateway.close();
  }
} catch {
  // Config/gateway-resolution/close faults land here; the store-read failure inside
  // runFirstRunFailOpen already degraded to the same note above.
  process.stdout.write(show(STORE_UNAVAILABLE_NOTE));
}

process.exit(0);
