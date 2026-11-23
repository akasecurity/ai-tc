/**
 * The sessionStart handler, driven in-process against a real temp home.
 *
 * The handler emits nothing on every path, so each silence sits beside the row
 * it should — or should not — leave in the store.
 */
import { existsSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { loadConfig, resolveCursorProvider } from '@akasecurity/plugin-sdk';
import { HARNESS, SOURCE_TOOL } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTrees } from '../../../../test/helpers/remove-tree.ts';
import { harnessInterfaceFor, runSessionStart } from '../../src/hooks/session-start-run.ts';
import type { TempStore } from '../helpers/store.ts';
import { payload, tempStore } from '../helpers/store.ts';

let store: TempStore;
let home: string;

beforeEach(() => {
  store = tempStore('aka-cursor-session-run-');
  home = mkdtempSync(join(tmpdir(), 'aka-cursor-session-run-home-'));
});

afterEach(() => {
  store.cleanup();
  removeTrees([home]);
});

function rows(sql: string): Record<string, unknown>[] {
  const db = new DatabaseSync(join(store.akaHome, 'data', 'aka.db'));
  try {
    return db.prepare(sql).all();
  } finally {
    db.close();
  }
}

describe('runSessionStart', () => {
  it('runs against a home that spawns no detached child', () => {
    const { settings } = loadConfig(store.akaHome, resolveCursorProvider);
    expect(settings.runMode).toBe('standalone');
    expect(settings.bodyRetention.enabled).toBe(false);
  });

  it('opens the session root from the first workspace root, and emits nothing', async () => {
    const input = payload('sessionStart', { workspace_roots: [store.cwd, '/elsewhere'] });
    const output = await runSessionStart('sessionStart', JSON.stringify(input), {
      akaHome: store.akaHome,
      homeDir: home,
    });
    expect(output).toBeUndefined();

    const sessions = rows(
      "SELECT id, attributes, harness_id FROM audit_events WHERE event_type = 'session'",
    );
    expect(sessions.map((r) => r.id)).toEqual([input.session_id]);
    const attrs = JSON.parse(String(sessions[0]?.attributes)) as Record<string, unknown>;
    expect(attrs.harness).toBe(HARNESS.Cursor);
    expect(attrs.harness_interface).toBe('ide');
    expect(attrs.provider).toBe('unknown');

    const harness = rows(
      `SELECT title FROM inventory WHERE id = '${String(sessions[0]?.harness_id)}'`,
    );
    expect(harness).toEqual([{ title: SOURCE_TOOL.Cursor }]);
  });

  it('declines a payload with no workspace without opening the store', async () => {
    const input = payload('sessionStart', { workspace_roots: [] });
    const output = await runSessionStart('sessionStart', JSON.stringify(input), {
      akaHome: store.akaHome,
      homeDir: home,
    });
    expect(output).toBeUndefined();
    expect(existsSync(store.akaHome)).toBe(false);
  });

  it('declines a payload for another event', async () => {
    const input = payload('sessionStart', { workspace_roots: [store.cwd] });
    const output = await runSessionStart('sessionEnd', JSON.stringify(input), {
      akaHome: store.akaHome,
      homeDir: home,
    });
    expect(output).toBeUndefined();
    expect(existsSync(store.akaHome)).toBe(false);
  });
});

describe('harnessInterfaceFor', () => {
  it('names a background agent, and the editor otherwise', () => {
    expect(harnessInterfaceFor({ is_background_agent: true })).toBe('background-agent');
    expect(harnessInterfaceFor({ is_background_agent: false })).toBe('ide');
    expect(harnessInterfaceFor({})).toBe('ide');
  });
});
