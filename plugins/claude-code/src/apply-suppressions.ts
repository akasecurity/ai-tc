/**
 * The `apply-suppressions` adapter. Invoked by the `/aka:setup`
 * wizard's FP-writeback flow. This file is UNTESTABLE GLUE only: it wires real IO
 * (stdin/file read, the ephemeral judge subprocess, the local store, the clock)
 * into the dependency-injected orchestrator in ./triage/adapter.ts, which holds
 * all the logic (and its tests).
 *
 *   Preview:  node scripts/apply-suppressions.js [--stream <path>]
 *   Confirm:  node scripts/apply-suppressions.js --confirmed --plan <path>
 *
 * Preview reads the `backfill.js --triage` stream (stdin unless --stream), runs
 * the judge, renders the human gate, and PERSISTS the resolved raw-free plan to a
 * temp file whose path it prints. Confirm reads that persisted plan back and
 * applies it VERBATIM — no re-scan, no re-judge — so the human gate is binding.
 * Without --plan the confirm path fails loud rather than re-judging.
 *
 * RUBRIC: runJudge's default rubric path (eval/prompt.md) is NOT in the shipped
 * plugin `files`, so it would throw at runtime. We inject loadRubric from a
 * SHIPPED source: scripts/triage-rubric.md, copied from eval/prompt.md at build
 * (tsup onSuccess) and shipped via the package's `files: ["scripts"]`. Falls back
 * to the source-tree eval/prompt.md when run un-built from src/ (dev only).
 */
import { existsSync, readFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { loadConfig } from '@akasecurity/plugin-sdk';

import { runApply } from './triage/adapter.ts';
import { runJudge, spawnClaude } from './triage/judge.ts';

function fail(message: string): never {
  process.stderr.write(`AKA apply-suppressions failed: ${message}\n`);
  process.exit(1);
}

// Who grants the suppression. No machine-local identity in the OSS store, so the
// OS account name is the honest source — mirrors the CLI's resolveCreatedBy.
function resolveCreatedBy(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

// The locked triage rubric from a SHIPPED source (see the RUBRIC note above).
function loadRubric(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const shipped = join(here, 'triage-rubric.md');
  if (existsSync(shipped)) return readFileSync(shipped, 'utf8');
  return readFileSync(join(here, '..', 'eval', 'prompt.md'), 'utf8');
}

async function main(): Promise<void> {
  const code = await runApply({
    argv: process.argv.slice(2),
    // fd 0 = stdin; the wizard pipes `backfill.js --triage` into this on preview.
    // Called only on the preview path — the confirm path never reads a stream.
    readStream: (streamPath) =>
      streamPath !== undefined ? readFileSync(streamPath, 'utf8') : readFileSync(0, 'utf8'),
    runJudge: (hits) => runJudge(hits, { spawn: spawnClaude, loadRubric }),
    openDb: () => {
      const db = openLocalDatabase(loadConfig().dataDir);
      return {
        policies: db.policies,
        exceptions: db.exceptions,
        // Makes the confirm write (posture overwrite + suppression inserts)
        // all-or-nothing; bound so `this` stays the LocalDatabase handle.
        transaction: (fn) => db.transaction(fn),
        close: () => {
          db.close();
        },
      };
    },
    now: () => Date.now(),
    createdBy: resolveCreatedBy,
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  });
  process.exit(code);
}

main().catch((err: unknown) => {
  fail(err instanceof Error ? err.message : 'unexpected failure');
});
