/**
 * scripts/start-light.js --adjust-confirm — the downgrade guard against the
 * EXISTING STORE posture. Drives the BUILT script (not the pure renderer) over
 * a throwaway ~/.aka home, so this proves the wired-up store read, not just
 * renderAdjustConfirm's own unit tests.
 *
 * The scenario this guards: a pack was hardened out of band (e.g. via
 * /aka:config) to a level stronger than the wizard's recommended floor, and
 * produced no findings this run — so it never enters the recommended
 * escalation and the adjust table's 'yours' column falls back to the plain
 * floor default. Without a store comparison, confirming the adjust fork would
 * silently lower that pack. `readExistingPosture` in src/start-light.ts closes
 * this gap by comparing the effective posture against the store via
 * detectPostureChanges before the card renders.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { openLocalDatabase } from '@akasecurity/persistence';
import { severityFloorPosture } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

const HERE = dirname(fileURLToPath(import.meta.url));
// test -> plugins/claude-code
const SCRIPT = join(HERE, '..', 'scripts', 'start-light.js');

interface Run {
  stdout: string;
  stderr: string;
  status: number;
}

// Drive the built script against a throwaway ~/.aka home. process.execPath is
// an absolute node path, so the child needs no host PATH and inherits no
// ambient environment beyond HOME/USERPROFILE.
function runAdjustConfirm(home: string, args: string[]): Run {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, '--adjust-confirm', ...args], {
      env: { HOME: home, USERPROFILE: home },
      encoding: 'utf8',
    });
    return { stdout, stderr: '', status: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { stdout: e.stdout ?? '', stderr: e.stderr ?? '', status: e.status ?? 1 };
  }
}

describe('scripts/start-light.js --adjust-confirm — downgrade guard against the store', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'aka-start-light-downgrade-'));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  it('surfaces an explicit downgrade approval for a pack hardened out of band with zero findings this run', () => {
    // Seed the store: 'secret' hardened to 'block' by some earlier, unrelated
    // session — no findings recorded for it this run.
    const db = openLocalDatabase(join(home, '.aka', 'data'));
    db.policies.upsertCategoryAction('secret', 'block');
    db.close();

    // The user's adjusted posture leaves 'secret' at the plain recommended
    // floor ('warn') — they never touched it, because it produced no findings
    // this run to escalate. Every other pack matches its recommended level too.
    const posture = severityFloorPosture();
    const run = runAdjustConfirm(home, ['--posture', JSON.stringify(posture)]);

    expect(run.status).toBe(0);
    expect(run.stderr).toBe('');
    expect(run.stdout.toLowerCase()).toContain('downgrade');
    expect(run.stdout).toContain('secret');
    // Both the hardened current level and the lower level about to be written.
    expect(run.stdout).toContain('block');
    expect(run.stdout).toMatch(/secret:\s*block\s*→\s*warn/);
  });

  it('does not warn when the chosen posture matches or strengthens the store', () => {
    const db = openLocalDatabase(join(home, '.aka', 'data'));
    db.policies.upsertCategoryAction('secret', 'block');
    db.close();

    // The user's posture keeps 'secret' at 'block' — no downgrade.
    const posture = { ...severityFloorPosture(), secret: 'block' as const };
    const run = runAdjustConfirm(home, ['--posture', JSON.stringify(posture)]);

    expect(run.status).toBe(0);
    expect(run.stdout.toLowerCase()).not.toContain('downgrade');
  });

  it('fails open (no crash, no warning) when the store is unreadable', () => {
    // Injected fault: an unreadable store (not a SQLite header), matching the
    // other fail-open store tests in this suite.
    const dataDir = join(home, '.aka', 'data');
    mkdirSync(dataDir, { recursive: true });
    writeFileSync(join(dataDir, 'aka.db'), 'not a database\n'.repeat(64));

    const posture = severityFloorPosture();
    const run = runAdjustConfirm(home, ['--posture', JSON.stringify(posture)]);

    // The setup wizard must never break: a clean exit with the card printed,
    // just without the store comparison (no downgrade text — there is nothing
    // to safely compare against).
    expect(run.status).toBe(0);
    expect(run.stderr).toBe('');
    expect(run.stdout.toLowerCase()).not.toContain('downgrade');
    expect(run.stdout).toContain('Adjust — set the packs you want, keep the rest');
  });

  it('renders the plain confirm card, with no store created as a side effect, when no store exists yet', () => {
    const posture = severityFloorPosture();
    const run = runAdjustConfirm(home, ['--posture', JSON.stringify(posture)]);

    expect(run.status).toBe(0);
    expect(run.stderr).toBe('');
    expect(run.stdout.toLowerCase()).not.toContain('downgrade');
    // A read-only confirm card must not have the side effect of seeding a
    // store that didn't already exist.
    expect(existsSync(join(home, '.aka', 'data', 'aka.db'))).toBe(false);
  });
});
