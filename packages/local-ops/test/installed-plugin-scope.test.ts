// The SCOPE half of Claude Code's `installed_plugins.json` read.
//
// `installedPluginVersions` has always preferred a `user` record and fallen
// back to the first one carrying a version, so it reports a version for a
// plugin installed at any scope. `claude plugin update` defaults to
// `--scope user`. Nothing carried the scope between the two, so on a machine
// where an enterprise managed-settings drop-in put the plugin at `managed` the
// comparison read the managed record, reported an update, and the apply failed
// with `Plugin "ai-tc" is not installed at scope user` — every time.
//
// Driven against a real ledger file rather than a stub: the record selection
// and the scope projection are one walk, and a stub would pin the projection
// against a shape nothing proves the reader produces.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { installedPlugins, installedPluginScope, installedPluginVersions } from '../src/updates.ts';

const REF = 'ai-tc@akasecurity';

let claudeHome: string;

beforeEach(() => {
  claudeHome = mkdtempSync(join(tmpdir(), 'aka-claude-home-'));
});

afterEach(() => {
  rmSync(claudeHome, { recursive: true, force: true });
});

function writeLedger(plugins: Record<string, unknown[]>): void {
  const dir = join(claudeHome, 'plugins');
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'installed_plugins.json'), JSON.stringify({ plugins }), 'utf8');
}

describe('installedPluginScope', () => {
  it.each(['managed', 'project', 'local'])(
    'reports the %s scope the version was actually read from',
    (scope) => {
      writeLedger({ [REF]: [{ version: '0.9.8', scope }] });

      expect(installedPluginScope(REF, claudeHome)).toBe(scope);
      // The positive control on the same ledger: without it a reader that
      // found nothing at all would satisfy every assertion below by returning
      // undefined for the scope too.
      expect(installedPluginVersions(claudeHome).get(REF)).toBe('0.9.8');
    },
  );

  it('reports the scope of the record the version comparison chose, not the first one', () => {
    // The two must name the same record or the update targets an install the
    // comparison never looked at. The reader prefers `user`, so a ledger
    // listing `managed` first must still answer `user` on BOTH halves.
    writeLedger({
      [REF]: [
        { version: '0.9.8', scope: 'managed' },
        { version: '0.9.10', scope: 'user' },
      ],
    });

    expect(installedPluginVersions(claudeHome).get(REF)).toBe('0.9.10');
    expect(installedPluginScope(REF, claudeHome)).toBe('user');
  });

  it('says nothing when the record carries no scope', () => {
    // An older ledger, or one this build does not fully understand. The host's
    // own default then applies, which is where every caller was before.
    writeLedger({ [REF]: [{ version: '0.9.8' }] });

    expect(installedPluginScope(REF, claudeHome)).toBeUndefined();
    expect(installedPluginVersions(claudeHome).get(REF)).toBe('0.9.8');
  });

  it('says nothing for a ref the ledger does not list', () => {
    writeLedger({ 'other@marketplace': [{ version: '1.0.0', scope: 'user' }] });

    expect(installedPluginScope(REF, claudeHome)).toBeUndefined();
  });

  it.each([
    [
      'no ledger at all',
      (): void => {
        /* the temp home is created empty */
      },
    ],
    [
      'a ledger listing nothing',
      (): void => {
        writeLedger({});
      },
    ],
  ])('says nothing on %s rather than throwing', (_label, seed) => {
    seed();

    expect(installedPluginScope(REF, claudeHome)).toBeUndefined();
    expect(installedPlugins(claudeHome).size).toBe(0);
  });

  it('keeps installedPluginVersions a version-only projection', () => {
    // The comparison side takes a `Map<ref, string>` and several callers merge
    // it with the Codex reader's map. Widening it here would have been the
    // smaller diff and would have changed a shape those merges depend on.
    writeLedger({ [REF]: [{ version: '0.9.8', scope: 'managed' }] });

    expect([...installedPluginVersions(claudeHome)]).toEqual([[REF, '0.9.8']]);
    expect([...installedPlugins(claudeHome)]).toEqual([
      [REF, { version: '0.9.8', scope: 'managed' }],
    ]);
  });
});
