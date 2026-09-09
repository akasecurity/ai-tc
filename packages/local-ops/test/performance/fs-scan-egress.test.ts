import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { scanPathIntoStore } from '../../src/fs-scan.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// Egress extraction through the WHOLE pipeline, at the largest file the walk
// will hand it.
//
// The engine's two ReDoS gates bound `scan()`, and they bound nothing else:
// `scanPathIntoStore` runs `extractFileEgress` on the CALLING thread, before
// the guarded scan and independent of it. So a pass over file content that
// costs more than linear time is a stall nothing can interrupt — and the
// dashboard's Scan Server Action, unlike a plugin hook, has no harness timeout
// to be killed by. @akasecurity/detections holds the per-pass guards
// (test/security/egress-redos.test.ts); this one exists to prove the WIRING:
// that this pipeline really does put a MAX_BYTES file through that code.
//
// The fixture is an ordinary minified bundle — one very long line carrying many
// URLs — which is the shape that matters most, because nothing about it is
// crafted. A repository containing one is not an attack.

const cpuMs = (): number => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};

// MAX_BYTES is the walker's own cap, so a file of this size is the largest that
// can reach extraction at all. Held one unit under it: the walk SKIPS a file
// above the cap, and a skipped file would make every assertion below vacuous.
const MAX_BYTES = 1_000_000;
const UNIT = 'see https://example.com/a for details. ';
const BUNDLE = UNIT.repeat(Math.floor(MAX_BYTES / UNIT.length));

// Measured at 59.7ms of CPU for this fixture on an arm64 Mac. Before the
// per-line redaction was memoized the same file cost roughly two minutes, so
// this sits ~30x above the passing measurement and ~2,000x below the failure it
// exists to catch. CPU time rather than wall time, so a runner that lost its
// core cannot trip it — see the sibling suite in @akasecurity/detections.
const BUDGET_MS = 2_000;

describe('scanPathIntoStore extracts egress from a MAX_BYTES file in bounded time', () => {
  let root: string;
  let store: string;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'aka-egress-scale-'));
    store = mkdtempSync(join(tmpdir(), 'aka-egress-scale-db-'));
    migratedStore.seed(store);
  });

  afterEach(() => {
    removeTrees([root, store]);
  });

  it('walks a 1 MB single-line bundle without an unbounded pass', async () => {
    writeFileSync(join(root, 'bundle.js'), BUNDLE);
    const db = openLocalDatabase(store);
    let result;
    let ms: number;
    try {
      const before = cpuMs();
      result = await scanPathIntoStore(db, root, {});
      ms = cpuMs() - before;
    } finally {
      db.close();
    }

    // Positive controls first. A file skipped by the size cap, or one whose
    // endpoints were never extracted, costs nothing and would satisfy the
    // budget below while proving the opposite of what this case claims.
    expect(BUNDLE.length).toBeLessThanOrEqual(MAX_BYTES);
    expect(result.scanned).toBe(1);
    expect(result.egress.files).toHaveLength(1);
    expect(result.egress.files[0]?.endpoints.length).toBeGreaterThan(10_000);

    expect(
      ms,
      `scanPathIntoStore burned ${ms.toFixed(1)}ms of CPU on a ${String(BUNDLE.length)}-byte ` +
        `single-line bundle (budget ${String(BUDGET_MS)}ms). Egress extraction runs on this ` +
        `thread with nothing able to interrupt it, so a pass that is worse than linear in file ` +
        `length stalls the CLI and the dashboard's Scan action outright.`,
    ).toBeLessThan(BUDGET_MS);
  });
});
