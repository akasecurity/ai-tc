import type { TimeRange } from '@akasecurity/dashboard-ui';
import type { Harness } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  buildActivityParams,
  parseExpanded,
  parseSelectedId,
} from '../../app/(app)/activity/filters';

// The full-width session inspector is URL state (`?view=full&id=<session>`)
// rather than component state, which is what makes the drill-down shareable and
// puts it in the browser's history. These pin the round trip — parse ∘ build —
// plus the ways the param can arrive without a session behind it, on BOTH sides:
// the serializer never writes that pairing, and the parser refuses it when
// something else wrote the URL.

describe('parseExpanded', () => {
  it('reads ?view=full beside an ?id as open', () => {
    expect(parseExpanded({ view: 'full', id: 'sess-1' })).toBe(true);
  });

  it('reads a missing ?view as closed', () => {
    expect(parseExpanded({ id: 'sess-1' })).toBe(false);
  });

  it('reads any other ?view value as closed', () => {
    // `view` is a shared param name across pages (findings uses `view=flat`), so
    // a value this page does not own must be inert rather than truthy.
    for (const view of ['', 'flat', '1', 'true', 'FULL']) {
      expect(parseExpanded({ view, id: 'sess-1' })).toBe(false);
    }
  });

  it('reads the first value when the param repeats', () => {
    expect(parseExpanded({ view: ['full', 'flat'], id: 'sess-1' })).toBe(true);
    expect(parseExpanded({ view: ['flat', 'full'], id: 'sess-1' })).toBe(false);
  });

  it('reads ?view=full with no session behind it as closed', () => {
    // buildActivityParams never writes this pairing, but it only constrains the
    // URLs this app writes — a hand-typed /activity?view=full reaches the parser
    // having gone nowhere near the serializer, and a panel is a view OF a
    // session. Blank and whitespace-only ids are the same case as a missing one.
    expect(parseExpanded({ view: 'full' })).toBe(false);
    expect(parseExpanded({ view: 'full', id: '' })).toBe(false);
    expect(parseExpanded({ view: 'full', id: '   ' })).toBe(false);
    expect(parseExpanded({ view: 'full', id: [] })).toBe(false);
  });
});

describe('buildActivityParams — the inspector', () => {
  const base: { q: string; harness: Harness[]; range: TimeRange } = {
    q: '',
    harness: [],
    range: '7d',
  };

  it('writes view=full next to the id it drills into', () => {
    const sp = buildActivityParams({ ...base, id: 'sess-1', expanded: true });
    expect(sp.get('view')).toBe('full');
    expect(sp.get('id')).toBe('sess-1');
  });

  it('omits view=full with no session pinned', () => {
    // An inspector over nothing: the panel is scoped to one session, so the
    // param is only ever written beside the ?id that names it.
    const sp = buildActivityParams({ ...base, expanded: true });
    expect(sp.get('view')).toBeNull();
    expect(sp.get('id')).toBeNull();
  });

  it('omits view when not expanded', () => {
    const sp = buildActivityParams({ ...base, id: 'sess-1', expanded: false });
    expect(sp.get('view')).toBeNull();
  });

  it('round-trips through the parsers', () => {
    const sp = buildActivityParams({
      ...base,
      q: 'deploy',
      id: 'sess-2',
      showEmpty: true,
      expanded: true,
    });
    const sm = Object.fromEntries(sp.entries());
    expect(parseExpanded(sm)).toBe(true);
    expect(parseSelectedId(sm)).toBe('sess-2');
  });

  it('leaves the rest of the list state alone', () => {
    // The inspector is a view of the current selection, not a filter — opening
    // it must not disturb the search/range/empty state the list is showing.
    const withPanel = buildActivityParams({
      q: 'deploy',
      harness: [],
      range: '30d',
      id: 'sess-3',
      showEmpty: true,
      expanded: true,
    });
    const withoutPanel = buildActivityParams({
      q: 'deploy',
      harness: [],
      range: '30d',
      id: 'sess-3',
      showEmpty: true,
    });
    withPanel.delete('view');
    expect(withPanel.toString()).toBe(withoutPanel.toString());
  });
});
