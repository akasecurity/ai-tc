// The asset lists carry only the `meta` keys ASSET_LIST_META_KEYS names, so a
// column that reads any other key would show "—" for every row of a real list
// while passing with a fixture that carries the whole record. Every column is
// driven over a record that remembers each key it is asked for.
import type { AssetSummary, AssetType } from '@akasecurity/schema';
import { ASSET_LIST_META_KEYS, listMetaOf } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  type Column,
  ENDPOINTS_COLUMN,
  MIXED_COLUMNS,
  NAME_COLUMN,
  TYPE_COLUMNS,
} from '../../src/inventory/columns.ts';

type AssetKind = keyof typeof ASSET_LIST_META_KEYS;
const KINDS = Object.keys(ASSET_LIST_META_KEYS) as AssetKind[];
const NOW = Date.parse('2026-10-15T12:00:00.000Z');

/** A value for every key a column might read, so each read reaches a real value. */
const FULL_META: Record<string, unknown> = {
  source: 'acme/skills',
  scope: 'user',
  installedVersion: '1.0.0',
  latestVersion: '1.1.0',
  updatedAt: '2026-10-15T10:00:00.000Z',
  pluginName: 'acme',
  transport: 'http',
  url: 'https://mcp.example.test/v1',
  command: 'npx acme-mcp',
  envKeys: ['TOKEN'],
  marketplace: 'acme',
  project: 'payments-api',
  event: 'PreToolUse',
  matcher: 'Bash',
  status: 'ok',
  warnings: ['shadowed'],
  kind: 'settings',
  path: '~/.claude/settings.json',
  entryCount: 4,
  detail: 'hooks: 2',
};

function asset(type: AssetKind, meta: Record<string, unknown>): AssetSummary {
  return {
    id: `${type}-1`,
    type,
    name: `${type}-1`,
    sub: 'sub',
    flags: [],
    meta,
    machines: 3,
    variants: 2,
    ...(type === 'mcp' ? { trust: 'risky' as const } : {}),
  };
}

/**
 * The whole record, then the record without each of its keys in turn, so a
 * column that falls back to a second key when the first is missing reads both.
 */
const RECORDS: Record<string, unknown>[] = [
  FULL_META,
  ...Object.keys(FULL_META).map((left) =>
    Object.fromEntries(Object.entries(FULL_META).filter(([key]) => key !== left)),
  ),
];

/** Every key `columns` read from the asset's meta, over every record. */
function keysRead(type: AssetType, columns: Column[]): Set<string> {
  const read = new Set<string>();
  for (const record of RECORDS) {
    const meta = new Proxy(record, {
      get(target, key) {
        if (typeof key === 'string') read.add(key);
        return Reflect.get(target, key) as unknown;
      },
    });
    const row = asset(type as AssetKind, meta);
    for (const c of columns) {
      c.value(row);
      c.display?.(row, NOW);
      c.chip?.(row);
    }
  }
  return read;
}

describe('the inventory columns read only the meta a list carries', () => {
  it.each(KINDS)('every %s column reads a listed key', (type) => {
    const columns = [NAME_COLUMN, ...TYPE_COLUMNS[type], ...MIXED_COLUMNS, ENDPOINTS_COLUMN];

    for (const key of keysRead(type, columns)) {
      expect(ASSET_LIST_META_KEYS[type] as readonly string[]).toContain(key);
    }
  });

  it.each(KINDS)(
    'every %s column shows the same for a listed row as for the whole record',
    (type) => {
      for (const record of RECORDS) {
        const whole = asset(type, record);
        const listed = asset(type, listMetaOf(type, record));

        for (const c of TYPE_COLUMNS[type]) {
          expect([c.value(listed), c.display?.(listed, NOW)]).toEqual([
            c.value(whole),
            c.display?.(whole, NOW),
          ]);
        }
      }
    },
  );

  it('reads at least one meta key for every type, so the guard above is not vacuous', () => {
    for (const type of KINDS) {
      expect(keysRead(type, TYPE_COLUMNS[type]).size).toBeGreaterThan(0);
    }
  });
});
