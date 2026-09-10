import { EMPTY_FILTERS } from '@akasecurity/dashboard-ui';
import { EnforcementActionKind, Severity } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  parseFile,
  parseFindingsFilters,
  parseRange,
  parseRepo,
  parseView,
} from '../../app/(app)/findings/filters';
import {
  allFindingsHref,
  enforcementHref,
  recommendationHref,
  resolvedFindingHref,
  severityHref,
  topSourceHref,
} from '../../app/(app)/security/links';

// The Security widgets' deep links. These are pure functions over a widget's own
// data, so they are testable directly — and they are where a wrong answer is
// INVISIBLE: `/findings` drops any param it does not recognise or cannot honour in
// the target view, so a broken link still renders a perfectly good findings page,
// just not the one the number promised.
//
// Every case therefore checks the string AND parses it back through the findings
// page's own parsers. String equality alone would pass for a link whose filter the
// destination silently ignores.

/** The query half of an href, read back the way the findings page reads it. */
function paramsOf(href: string): Record<string, string | string[]> {
  const sp = new URL(href, 'http://localhost').searchParams;
  const out: Record<string, string | string[]> = {};
  for (const key of new Set(sp.keys())) {
    const all = sp.getAll(key);
    out[key] = all.length > 1 ? all : (all[0] ?? '');
  }
  return out;
}

describe('enforcementHref', () => {
  it('filters by action and carries the widget window', () => {
    expect(enforcementHref('blocked', '7d')).toBe('/findings?action=blocked&view=flat&range=7d');
  });

  it('round-trips: the destination reads back the action, the view and the range', () => {
    const sp = paramsOf(enforcementHref('redacted', '30d'));
    expect(parseFindingsFilters(sp)).toEqual({ ...EMPTY_FILTERS, action: ['redacted'] });
    expect(parseView(sp)).toBe('flat');
    expect(parseRange(sp)).toBe('30d');
  });

  it('covers every enforcement kind', () => {
    // `Partial<Record<…>>` on the view's prop gives up the exhaustiveness a full
    // Record would enforce, so a kind that silently produced no link would compile.
    for (const kind of EnforcementActionKind.options) {
      const sp = paramsOf(enforcementHref(kind, '7d'));
      expect(parseFindingsFilters(sp).action).toEqual([kind]);
    }
  });
});

describe('severityHref', () => {
  it('filters by severity and carries NO range', () => {
    // `severitySummary()` is whole-store, and an absent `range` means all time on
    // the findings page — carrying the page's 7d would show fewer findings than
    // the number the user clicked.
    expect(severityHref('critical')).toBe('/findings?severity=critical&view=flat');
  });

  it('round-trips to all time', () => {
    const sp = paramsOf(severityHref('high'));
    expect(parseFindingsFilters(sp)).toEqual({ ...EMPTY_FILTERS, severity: ['high'] });
    expect(parseRange(sp)).toBeNull();
    expect(parseView(sp)).toBe('flat');
  });

  it('covers every severity', () => {
    for (const severity of Severity.options) {
      expect(parseFindingsFilters(paramsOf(severityHref(severity))).severity).toEqual([severity]);
    }
  });
});

describe('topSourceHref', () => {
  it('filters by repo under the flat view, with the widget window', () => {
    expect(topSourceHref('payments-api', '7d')).toBe(
      '/findings?view=flat&range=7d&repo=payments-api',
    );
  });

  it('round-trips: `repo` survives only because the view is flat', () => {
    // buildFindingsParams drops `repo` under any other view, so this assertion is
    // what catches a link that reads correctly and filters nothing.
    const sp = paramsOf(topSourceHref('acme/api', '30d'));
    expect(parseRepo(sp)).toBe('acme/api');
    expect(parseView(sp)).toBe('flat');
    expect(parseRange(sp)).toBe('30d');
  });

  it('encodes a slug containing a slash', () => {
    expect(topSourceHref('acme/api', '7d')).toContain('repo=acme%2Fapi');
  });
});

describe('resolvedFindingHref', () => {
  it('filters by rule, resolved status, repo and file', () => {
    expect(resolvedFindingHref('aws-key', 'acme/api', 'src/db.ts')).toBe(
      '/findings?type=aws-key&status=resolved&view=flat&repo=acme%2Fapi&file=src%2Fdb.ts',
    );
  });

  it('round-trips all four, and carries no range', () => {
    const sp = paramsOf(resolvedFindingHref('aws-key', 'acme/api', 'src/db.ts'));
    expect(parseFindingsFilters(sp)).toEqual({
      ...EMPTY_FILTERS,
      type: ['aws-key'],
      status: ['resolved'],
    });
    expect(parseFile(sp)).toBe('src/db.ts');
    expect(parseRepo(sp)).toBe('acme/api');
    // `recentlyResolved()` is whole-store, like the severity summary.
    expect(parseRange(sp)).toBeNull();
  });

  it('narrows by repo, because a stored path is relative to one', () => {
    // Without it, `.env` selects that file in EVERY repo the machine has scanned —
    // findings the clicked row does not name.
    expect(resolvedFindingHref('generic-key', 'acme/api', '.env')).toContain('repo=acme%2Fapi');
  });

  it('omits `file` and `repo` entirely when either is empty', () => {
    // An exact match on '' selects nothing — the opposite of declining to narrow.
    const noPath = resolvedFindingHref('aws-key', 'acme/api', '');
    expect(noPath).toBe('/findings?type=aws-key&status=resolved&view=flat&repo=acme%2Fapi');
    expect(parseFile(paramsOf(noPath))).toBe('');

    const noRepo = resolvedFindingHref('aws-key', '', 'src/db.ts');
    expect(noRepo).toBe('/findings?type=aws-key&status=resolved&view=flat&file=src%2Fdb.ts');
    expect(parseRepo(paramsOf(noRepo))).toBe('');
  });
});

describe('recommendationHref', () => {
  it('filters by the rule the card names, with the widget window', () => {
    expect(recommendationHref('aws-key', '7d')).toBe('/findings?type=aws-key&view=flat&range=7d');
  });

  it('round-trips: `type` survives only because the view is not grouped', () => {
    const sp = paramsOf(recommendationHref('aws-key', '7d'));
    expect(parseFindingsFilters(sp).type).toEqual(['aws-key']);
    expect(parseView(sp)).toBe('flat');
    expect(parseRange(sp)).toBe('7d');
  });

  it('carries no severity — it is constant within a rule', () => {
    expect(parseFindingsFilters(paramsOf(recommendationHref('aws-key', '7d'))).severity).toEqual(
      [],
    );
  });
});

describe('allFindingsHref', () => {
  it('carries the window and no filter', () => {
    const href = allFindingsHref('7d');
    expect(href).toBe('/findings?view=flat&range=7d');
    expect(parseFindingsFilters(paramsOf(href))).toEqual(EMPTY_FILTERS);
  });
});
