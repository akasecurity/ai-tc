import type { FindingAction, FindingInstance, FindingStatus } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import { formatConfidence } from '../../src/findings/FindingDetailView.tsx';
import {
  ACTION_META,
  actionMeta,
  CATEGORY_ICON_FALLBACK,
  CATEGORY_LABEL,
  categoryLabel,
  categoryStyle,
  filterInstancesByStatus,
  FINDING_STATUS_META,
  FINDING_STATUSES,
  findingStatusMeta,
  SEVERITIES,
} from '../../src/findings/meta.ts';
import { KeyIcon } from '../../src/shared/icons.tsx';

// Minimal FindingInstance fixture — only `id` and `status` vary per test.
function buildInstance(id: string, status?: FindingStatus): FindingInstance {
  return {
    id,
    provider: 'claudecode',
    repo: 'acme/api',
    file: 'src/a.ts',
    action: 'allowed',
    detectedAt: '2026-01-01T00:00:00.000Z',
    confidence: 0.9,
    ...(status ? { status } : {}),
  };
}

describe('categoryStyle', () => {
  it('returns the tinted classes for a known category', () => {
    expect(categoryStyle('secret')).toBe('bg-sev-critical-fill text-sev-critical-ink');
    expect(categoryStyle('source_code')).toBe('bg-violet-fill text-violet-ink');
  });

  it('falls back to a neutral surface tone for an off-enum category', () => {
    expect(categoryStyle('not-a-category')).toBe('bg-surface-3 text-text-2');
  });

  // Regression: a category reaches here as a plain string, so it can collide with
  // an Object.prototype member. Without an Object.hasOwn guard, CATEGORY_TONE[category]
  // resolves the INHERITED member (truthy, so `?? 'neutral'` never fires), TONE_SOFT
  // has no such key, and categoryStyle returns undefined despite its `: string` type.
  // In-repo that silently drops the icon tile's tonal classes via cn(); an external
  // consumer feeding the same unguarded lookup into toneColors() throws outright.
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty', ''])(
    'resolves the off-enum category %j to the neutral fallback',
    (category) => {
      expect(categoryStyle(category)).toBe('bg-surface-3 text-text-2');
    },
  );
});

describe('CATEGORY_ICON_FALLBACK', () => {
  it('resolves a known category to its real icon', () => {
    expect(CATEGORY_ICON_FALLBACK.secret).toBe(KeyIcon);
  });

  // Regression: this table backs `CATEGORY_ICON_FALLBACK[cat] ?? KeyIcon` at
  // every findings call site (FindingsTableView, FindingsFlatTableView,
  // FindingDetailView), and the result is rendered directly as a JSX tag
  // (`<Icon />`) — so it can't be guarded behind an Object.hasOwn wrapper
  // function the way categoryStyle and categoryLabel are: a component derived
  // from a function call trips the render-created-component lint rule
  // (react-hooks/static-components), which can't see that the underlying icon
  // reference is module-level and stable either way. A plain object would
  // resolve '__proto__' to Object.prototype and 'constructor' to the Object
  // function — both truthy, so `?? KeyIcon` would never fire, and React would
  // throw "element type is invalid" on the very first render rather than
  // degrading. Built null-prototype instead, so none of these keys resolve to
  // an inherited member at all.
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty', ''])(
    'has no inherited member for %j, so the ?? KeyIcon fallback fires',
    (category) => {
      expect(CATEGORY_ICON_FALLBACK[category]).toBeUndefined();
      expect(CATEGORY_ICON_FALLBACK[category] ?? KeyIcon).toBe(KeyIcon);
    },
  );
});

describe('categoryLabel', () => {
  it('returns the label for a known category', () => {
    expect(categoryLabel('secret')).toBe('Secret');
  });

  it('echoes an off-enum category back as its own label', () => {
    expect(categoryLabel('not-a-category')).toBe('not-a-category');
  });

  // Regression: FindingDetailView used to read this table as
  // `CATEGORY_LABEL[category as keyof typeof CATEGORY_LABEL]` — a cast, not a
  // guard. '__proto__' resolves Object.prototype (truthy), so the cast's
  // `if (categoryLabel) return categoryLabel;` returned the prototype object
  // typed as `: string`, and the drawer's title — which doubles as its Radix
  // aria-labelledby accessible name — threw rendering it.
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'echoes the off-enum category %j back rather than resolving the inherited member',
    (category) => {
      expect(categoryLabel(category)).toBe(category);
    },
  );
});

describe('ACTION_META / actionMeta', () => {
  it('maps every finding action to a label, icon component, and tinted className', () => {
    const actions: FindingAction[] = [
      'blocked',
      'redacted',
      'warned',
      'allowed',
      'monitored',
      'quarantined',
    ];
    for (const a of actions) {
      const m = ACTION_META[a];
      expect(m.label).toBe(a.charAt(0).toUpperCase() + a.slice(1));
      expect(typeof m.icon).toBe('function');
      expect(m.className).toMatch(/\S/);
      // actionMeta must resolve every real action identically to the raw table.
      expect(actionMeta(a)).toBe(m);
    }
  });

  // Regression: ActionTag read ACTION_META[action] directly. An action of
  // 'constructor' resolves the Object function (truthy), so `.icon` is
  // undefined and `<Icon />` throws "element type is invalid" — the whole row
  // fails to render, not just the tile.
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'falls back to a neutral, self-labelled pill for the off-enum action %j',
    (action) => {
      const m = actionMeta(action);
      expect(m.label).toBe(action);
      expect(typeof m.icon).toBe('function');
      expect(m.className).toBe('bg-surface-3 text-text-2');
    },
  );
});

describe('FINDING_STATUS_META / findingStatusMeta', () => {
  it('resolves every real status identically to the raw table', () => {
    for (const s of FINDING_STATUSES) {
      expect(findingStatusMeta(s)).toBe(FINDING_STATUS_META[s]);
    }
  });

  // Regression: FindingsTableView, FindingsFlatTableView and
  // FindingsLocationsView all read FINDING_STATUS_META[status] directly once
  // status was known to be defined — but defined isn't the same as validated.
  // 'constructor' resolves the Object function (truthy), so `.badge` is
  // undefined and Badge receives an invalid variant.
  it.each(['__proto__', 'constructor', 'toString', 'hasOwnProperty'])(
    'falls back to the neutral "default" badge for the off-enum status %j',
    (status) => {
      expect(findingStatusMeta(status)).toEqual({ label: status, badge: 'default' });
    },
  );
});

describe('CATEGORY_LABEL / SEVERITIES / FINDING_STATUSES', () => {
  it('labels categories and orders severities critical→low', () => {
    expect(CATEGORY_LABEL.secret).toBe('Secret');
    expect(CATEGORY_LABEL.pii).toBe('PII');
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low']);
  });

  it('orders statuses open→dismissed for the Status filter', () => {
    expect(FINDING_STATUSES).toEqual(['open', 'handled', 'resolved', 'dismissed']);
  });
});

describe('formatConfidence', () => {
  it('buckets by threshold and formats the score to two decimals', () => {
    expect(formatConfidence(0.95)).toEqual({ label: 'High · 0.95', tone: 'text-ok-ink' });
    // Threshold boundaries are inclusive at 0.9 (High) and 0.7 (Medium).
    expect(formatConfidence(0.9)).toEqual({ label: 'High · 0.90', tone: 'text-ok-ink' });
    expect(formatConfidence(0.89)).toEqual({ label: 'Medium · 0.89', tone: 'text-sev-high-ink' });
    expect(formatConfidence(0.7)).toEqual({ label: 'Medium · 0.70', tone: 'text-sev-high-ink' });
    expect(formatConfidence(0.69)).toEqual({ label: 'Low · 0.69', tone: 'text-text-2' });
    expect(formatConfidence(0)).toEqual({ label: 'Low · 0.00', tone: 'text-text-2' });
  });
});

describe('filterInstancesByStatus', () => {
  const instances: FindingInstance[] = [
    buildInstance('i-open', 'open'),
    buildInstance('i-handled', 'handled'),
    buildInstance('i-resolved', 'resolved'),
    buildInstance('i-dismissed', 'dismissed'),
    buildInstance('i-legacy'), // no status (predates the resolution feature)
  ];

  it('keeps only instances whose own status is among the selected ones', () => {
    expect(filterInstancesByStatus(instances, ['open'])).toEqual([instances[0]]);
    expect(filterInstancesByStatus(instances, ['handled'])).toEqual([instances[1]]);
  });

  it('keeps the union when several statuses are selected', () => {
    expect(filterInstancesByStatus(instances, ['open', 'resolved'])).toEqual([
      instances[0],
      instances[2],
    ]);
  });

  it('excludes a legacy instance with no status when a status is selected', () => {
    const legacyOnly = instances.filter((i) => i.id === 'i-legacy');
    expect(filterInstancesByStatus(legacyOnly, ['open'])).toEqual([]);
  });

  it('returns every instance unchanged for an empty selection', () => {
    expect(filterInstancesByStatus(instances, [])).toEqual(instances);
  });

  it('returns every instance unchanged when no status filter is given', () => {
    expect(filterInstancesByStatus(instances, undefined)).toEqual(instances);
  });

  it('never empties out a group the store already deemed visible', () => {
    // foldGroupStatus only assigns a candidate status to a group when at
    // least one instance carries it — so filtering that SAME group's
    // instances by the SAME status can never yield an empty expanded list.
    const mixed = [buildInstance('i1', 'handled'), buildInstance('i2', 'dismissed')];
    expect(filterInstancesByStatus(mixed, ['handled'])).toHaveLength(1);
  });
});
