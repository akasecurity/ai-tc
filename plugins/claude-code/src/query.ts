/**
 * Read surface for the transcript screens. Invoked by the /health, /findings,
 * /recommend, /audit, and /aka:exceptions slash commands as:
 *
 *   node scripts/query.js <findings|health|recommend|audit|tokens|exceptions>
 *
 * Resolves the data gateway from config (the local SQLite store), renders its
 * plain data to monochrome terminal text, prints it, and exits.
 * Adapter-only: the gateway + data shapes live in @akasecurity/plugin-runtime /
 * @akasecurity/plugin-sdk; rendering lives in ./render. Writes go through
 * process.stdout.write because no-console is an error in the shared config.
 *
 * Fail-open: a missing/locked store prints a friendly note and exits 0 — a
 * read command should never surface a stack trace.
 */
import { openLocalDatabase } from '@akasecurity/persistence';
import { resolveDataGateway } from '@akasecurity/plugin-runtime';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { fenced } from './present.ts';
import {
  renderDetections,
  renderExceptions,
  runQuery,
  SEVERITIES,
  type Severity,
} from './render.ts';

const sub = process.argv[2] ?? '';
const args = process.argv.slice(3);

// /findings severity filter: accept `--severity <level>`, `--severity=<level>`,
// or the bare shorthands `--critical` / `--high` / `--medium` / `--low`. An
// unknown level is ignored (the command still lists everything).
function parseSeverity(argv: string[]): Severity | undefined {
  const valid = (value: string | undefined): Severity | undefined =>
    SEVERITIES.find((s) => s === value);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? '';
    if (arg === '--severity') return valid(argv[i + 1]);
    if (arg.startsWith('--severity=')) return valid(arg.slice('--severity='.length));
    const shorthand = valid(arg.replace(/^--/, ''));
    if (shorthand !== undefined) return shorthand;
  }
  return undefined;
}

try {
  const config = loadConfig();
  if (sub === 'exceptions') {
    // Detection-exception grants live in the plugin-local store (they are a
    // machine-local trust decision, not gateway data — the DataGateway port has
    // no exceptions read), so this view reads @akasecurity/persistence
    // directly: db.exceptions.list() returns the ACTIVE grants only.
    const db = openLocalDatabase(config.dataDir);
    try {
      process.stdout.write(`${fenced(renderExceptions(await db.exceptions.list()))}\n`);
    } finally {
      db.close();
    }
  } else if (sub === 'detections') {
    // The installed detection inventory + update availability are local-store
    // state (installed_packs vs the available_packs mirror), not gateway data —
    // read @akasecurity/persistence directly, like `exceptions`.
    const db = openLocalDatabase(config.dataDir);
    try {
      const { items } = await db.detections.listDetections({ filter: 'all' });
      process.stdout.write(`${fenced(renderDetections(items))}\n`);
    } finally {
      db.close();
    }
  } else {
    // Resolve the gateway at the configured data dir / connection (same config
    // the hooks use), so the read commands stay in step with the active run mode.
    const gateway = resolveDataGateway(config);
    try {
      const severity = parseSeverity(args);
      process.stdout.write(
        `${fenced(await runQuery(sub, gateway, severity !== undefined ? { severity } : {}))}\n`,
      );
    } finally {
      await gateway.close();
    }
  }
} catch {
  process.stdout.write('AKA could not read your data yet. It populates as you use Claude Code.\n');
}

process.exit(0);
