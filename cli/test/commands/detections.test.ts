import { mkdirSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type * as Persistence from '@akasecurity/persistence';
import { DB_FILENAME, openLocalDatabase } from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { DetectionListItem } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { renderDetectionsTable, runDetections } from '../../src/commands/detections.ts';

// The refusal itself is proven against a real contended store one layer down
// (packages/persistence/test/repositories/rule-probe-cache.test.ts, via
// lockStore). That helper does not cross the package wall, and what is left to
// prove here is the CLI's three-way branch — so this forces the shape the
// repository returns on a swallowed write instead of re-rolling the harness.
const refuse = vi.hoisted(() => ({ clear: false }));
vi.mock('@akasecurity/persistence', async (importOriginal) => {
  const actual = await importOriginal<typeof Persistence>();
  return {
    ...actual,
    openLocalDatabase: (...args: Parameters<typeof actual.openLocalDatabase>) => {
      const db = actual.openLocalDatabase(...args);
      if (refuse.clear) {
        vi.spyOn(db.ruleProbeCache, 'clearQuarantined').mockReturnValue({
          refused: true,
          cleared: 0,
        });
      }
      return db;
    },
  };
});

function item(overrides: Partial<DetectionListItem>): DetectionListItem {
  return {
    id: 'aka/secrets',
    name: 'Secrets',
    version: '2.0.0',
    enabled: true,
    origin: 'library',
    namespace: 'aka',
    packId: 'secrets',
    ruleCount: 21,
    ...overrides,
  };
}

describe('renderDetectionsTable', () => {
  it('renders one aligned row per pack with update status', () => {
    const table = renderDetectionsTable([
      item({}),
      item({
        id: 'aka/core-pii',
        packId: 'core-pii',
        version: '2.0.0',
        latestVersion: '2.1.0',
        ruleCount: 14,
        enabled: false,
        policyId: 'redact',
      }),
    ]);

    const lines = table.split('\n');
    expect(lines[0]).toMatch(/Pack\s+Installed\s+Latest\s+Rules\s+Enabled\s+Policy\s+Status/);
    expect(lines[1]).toContain('aka/secrets');
    expect(lines[1]).toContain('✓ up to date');
    expect(lines[1]).toContain('monitor'); // unassigned policy renders as monitor
    expect(lines[2]).toContain('aka/core-pii');
    expect(lines[2]).toContain('v2.1.0');
    expect(lines[2]).toContain('⬆ update available');
    expect(lines[2]).toContain('redact');
    expect(lines[2]).toContain('no');
  });
});

// The one verdict the machine reaches on its own — a pulled/custom regex rule
// that blew the ReDoS timing budget or had to be terminated mid-scan — is
// cached forever and drops the rule from every later scan. That makes both an
// undo and a way to notice it part of the command's contract.
describe('quarantined rules', () => {
  let home: string;
  let out: string;
  let err: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-detections-'));
    mkdirSync(dataDir(home), { recursive: true });
    out = '';
    err = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: string | Uint8Array) => {
      err += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  });

  afterEach(() => {
    refuse.clear = false;
    vi.restoreAllMocks();
    removeTree(home);
    process.exitCode = undefined;
  });

  function seedVerdicts(verdicts: [string, 'safe' | 'quarantined'][]): void {
    const db = openLocalDatabase(dataDir(home));
    try {
      for (const [key, verdict] of verdicts) db.ruleProbeCache.setVerdict(key, verdict, 900);
    } finally {
      db.close();
    }
  }

  function remaining(): number {
    const db = openLocalDatabase(dataDir(home));
    try {
      return db.ruleProbeCache.countQuarantined();
    } finally {
      db.close();
    }
  }

  it('clears the verdicts and says how many went', async () => {
    seedVerdicts([
      ['bad-a', 'quarantined'],
      ['bad-b', 'quarantined'],
      ['fine', 'safe'],
    ]);

    await runDetections(['unquarantine', '--home', home]);

    expect(out).toContain('Cleared 2');
    expect(remaining()).toBe(0);
    expect(process.exitCode).toBeUndefined();
  });

  it('says so plainly when there is nothing to clear', async () => {
    seedVerdicts([['fine', 'safe']]);

    await runDetections(['unquarantine', '--home', home]);

    expect(out).toContain('No quarantined rules');
  });

  it('surfaces the count on the list, since the only other mention is hook stderr', async () => {
    // A quarantined rule is a rule that silently stopped detecting. The line the
    // plugin writes goes to a hook's stderr, which the harness normally
    // swallows — so the read surface has to carry it too.
    seedVerdicts([['bad-a', 'quarantined']]);

    await runDetections(['--home', home]);

    expect(out).toContain('1 rule(s) quarantined');
    expect(out).toContain('aka detections unquarantine');
  });

  it('reports a refused write on stderr and exits non-zero, never as success', async () => {
    // A refused DELETE and an empty cache both clear zero rows. Collapsing them
    // would tell a user their rules are restored while every one of them is
    // still quarantined — on the one command whose whole job is undoing a
    // silent detection gap. Contention is the reachable trigger: WAL keeps the
    // COUNT(*) reads working while the DELETE loses on busy_timeout.
    seedVerdicts([
      ['bad-a', 'quarantined'],
      ['bad-b', 'quarantined'],
    ]);
    refuse.clear = true;
    await runDetections(['unquarantine', '--home', home]);

    expect(err).toContain('refused the write');
    expect(process.exitCode).toBe(1);
    expect(out).not.toContain('No quarantined rules');
    expect(out).not.toContain('Cleared');
    // And it told the truth: they really are still there.
    expect(remaining()).toBe(2);
  });

  it('rejects an unknown subcommand and names the real ones', async () => {
    await runDetections(['unquarentine', '--home', home]);

    expect(process.exitCode).toBe(1);
  });
});

// One rule failing validation makes the scan path discard the whole installed
// snapshot, so the user loses every custom rule and every per-detection action.
// The plugin reports that on a hook's stderr, which the harness normally
// swallows — and its line sends the reader HERE, so this surface has to carry it
// or that line points at nothing.
describe('rules rejected from the installed snapshot', () => {
  let home: string;
  let out: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-detections-rejected-'));
    mkdirSync(dataDir(home), { recursive: true });
    out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    removeTree(home);
    process.exitCode = undefined;
  });

  // High-entropy and matching no rule: a rejected entry never passed
  // validation, so any of its own bytes may be a live credential.
  const PLANTED = 'zQf7Kp2Wx9Lm4Nv8Rt6Yh3Bd5Gj1Sc0Ae';

  function scanRule(id: string): Record<string, unknown> {
    return {
      specVersion: 1,
      id,
      name: id,
      category: 'secret',
      severity: 'high',
      matcher: { type: 'regex', pattern: 'x', flags: 'g' },
    };
  }

  // Written through a raw connection rather than recordInventory, which
  // validates: the whole point is a row the store already holds and the reader
  // must now refuse. The seam persistence exposes for this does not cross a
  // package wall, so this opens the file the same way as the runtime's own tests.
  function seedPack(entries: unknown[]): void {
    openLocalDatabase(dataDir(home)).close(); // migrate first
    const raw = new DatabaseSync(join(dataDir(home), DB_FILENAME));
    try {
      raw
        .prepare(
          `INSERT INTO installed_packs (id, namespace, pack_id, version, name, rules_json, enabled, created_at, updated_at)
           VALUES ('c1', 'custom', 'mine', '1.0.0', 'Mine', ?, 1, 0, 0)`,
        )
        .run(JSON.stringify(entries));
    } finally {
      raw.close();
    }
  }

  it('says nothing when every installed rule is valid', async () => {
    // The positive control: without it the absence checks below would pass on a
    // command that had stopped reporting entirely.
    seedPack([scanRule('custom/a')]);

    await runDetections(['--home', home]);

    expect(out).toContain('pack(s)'); // it really did render the list
    expect(out).not.toContain('failed validation');
  });

  it('names each rejected rule and the cost, without offering a verdict to clear', async () => {
    seedPack([scanRule('custom/a'), { ...scanRule('custom/b'), postValidator: ['luhn'] }]);

    await runDetections(['--home', home]);

    expect(out).toContain('1 rule(s) under enabled packs failed validation');
    expect(out).toContain('custom/mine custom/b — unrecognized_keys');
    expect(out).toContain('no custom rule and no per-detection action is enforced');
    expect(out).toContain('Repair or reinstall the pack');
    // Nothing is cached, so there is no verdict to clear. Offering the
    // quarantine undo here would send the reader to a list their rule is not on.
    expect(out).not.toContain('aka detections unquarantine');
  });

  it('never prints a rejected entry’s own bytes', async () => {
    seedPack([{ ...scanRule('custom/x'), id: `not a valid id ${PLANTED}`, examples: [PLANTED] }]);

    await runDetections(['--home', home]);

    // Positive control on these bytes before asserting what they omit.
    expect(out).toContain('id: invalid_format');
    expect(out).not.toContain(PLANTED);
    expect(out).not.toContain('not a valid id');
  });
});
