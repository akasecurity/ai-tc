import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import { dataDir } from '@akasecurity/plugin-sdk';
import type { DetectionListItem } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { renderDetectionsTable, runDetections } from '../../src/commands/detections.ts';

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

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-detections-'));
    mkdirSync(dataDir(home), { recursive: true });
    out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
      out += typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8');
      return true;
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(home, { recursive: true, force: true });
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

  it('rejects an unknown subcommand and names the real ones', async () => {
    await runDetections(['unquarentine', '--home', home]);

    expect(process.exitCode).toBe(1);
  });
});
