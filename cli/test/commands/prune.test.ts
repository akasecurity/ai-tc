import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { applyOnboarding, dataDir, openLocalDatabase } from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runPrune } from '../../src/commands/prune.ts';
import type { Prompter } from '../../src/lib/prompter.ts';

const DAY = 86_400_000;

let base: string;

function recorder(): Prompter & { output: () => string; errors: () => string } {
  const out: string[] = [];
  const err: string[] = [];
  const unscripted = (): Promise<string> => Promise.reject(new Error('unscripted prompt'));
  return {
    output: () => out.join(''),
    errors: () => err.join(''),
    out: (text) => {
      out.push(text);
    },
    err: (text) => {
      err.push(text);
    },
    isInteractive: true,
    ask: unscripted,
    askHidden: unscripted,
    readAllStdin: () => Promise.resolve(''),
  };
}

function seedBody(ageDays: number, bytes = 1000): void {
  const db = openLocalDatabase(dataDir(base));
  db.recordCapture(
    {
      id: `evt-${String(ageDays)}-${String(bytes)}`,
      sourceTool: 'claude-code',
      kind: 'code_change',
      occurredAt: new Date(Date.now() - ageDays * DAY).toISOString(),
      contentHash: `hash-${String(ageDays)}-${String(bytes)}`,
      content: 'x'.repeat(bytes),
      metadata: { sessionId: `sess-${String(ageDays)}`, filePath: 'src/a.ts' },
    },
    [],
  );
}

describe('aka prune', () => {
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-prune-'));
  });
  afterEach(() => {
    removeTree(base);
  });

  it('refuses to run while body expiry is off', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base], io);

    // Off by default, and this command is not a way around that.
    expect(io.output()).toContain('Body expiry is off');
  });

  it('--days runs a one-off pass even while the setting is off', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);

    expect(io.output()).toContain('Expired 1 bodies');
    expect(io.output()).toContain('1000 B');
  });

  it('--dry-run reports and changes nothing', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30', '--dry-run'], io);

    expect(io.output()).toContain('Would expire 1 bodies');

    // The body is still there — a dry run that expired anything would be the
    // worst possible defect in this command.
    const io2 = recorder();
    runPrune(['--home', base, '--days', '30', '--dry-run'], io2);
    expect(io2.output()).toContain('Would expire 1 bodies');
  });

  it('spares a body inside the horizon', () => {
    seedBody(1);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);

    expect(io.output()).toContain('Nothing to expire');
  });

  it('refuses a nonsense horizon rather than rounding it', () => {
    const io = recorder();
    runPrune(['--home', base, '--days', 'soon'], io);
    expect(io.errors()).toContain('whole number of days');

    const io2 = recorder();
    runPrune(['--home', base, '--days', '0'], io2);
    expect(io2.errors()).toContain('whole number of days');
  });

  it('respects the configured horizon once expiry is on', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const io = recorder();
    runPrune(['--home', base], io);
    expect(io.output()).toContain('Expired 1 bodies');
  });

  it('says the file does not shrink, because that is the next question', () => {
    seedBody(60);
    const io = recorder();
    runPrune(['--home', base, '--days', '30'], io);
    expect(io.output()).toContain('does not shrink');
  });
});
