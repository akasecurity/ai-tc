import { EMPTY_FILTERS } from '@akasecurity/dashboard-ui';
import { describe, expect, it } from 'vitest';

import {
  buildFindingsParams,
  type FindingsSearchParams,
  parseFile,
  parseFindingsFilters,
  parseRange,
  parseRepo,
  parseTools,
  parseView,
  toGroupedQuery,
  toInstancesQuery,
  toLocationsQuery,
} from '../../app/(app)/findings/filters';

// The findings URL vocabulary. These are pure functions over search params, so
// they are the one part of the three-view page that can be tested directly —
// and they are where a wrong answer is invisible, since a param the page
// silently ignores still looks like a working filter in a shared link.

describe('parseView', () => {
  it('defaults to grouped when absent', () => {
    expect(parseView({})).toBe('grouped');
  });

  it('reads the known views', () => {
    expect(parseView({ view: 'flat' })).toBe('flat');
    expect(parseView({ view: 'files' })).toBe('files');
    expect(parseView({ view: 'grouped' })).toBe('grouped');
  });

  it('falls back to grouped for an unknown value', () => {
    // A hand-edited URL must not produce a blank page.
    expect(parseView({ view: 'nonsense' })).toBe('grouped');
    expect(parseView({ view: ['flat', 'files'] })).toBe('grouped');
  });
});

describe('parseRange', () => {
  it('is null when absent — this list has no default window', () => {
    // Applying one silently would hide findings a reader cannot know are gone.
    expect(parseRange({})).toBeNull();
  });

  it('is null for an unknown value rather than falling back to a default', () => {
    expect(parseRange({ range: '99y' })).toBeNull();
  });

  it('reads a known range', () => {
    expect(parseRange({ range: '30d' })).toBe('30d');
  });
});

describe('parseTools / parseRepo / parseFile', () => {
  it('reads repeated tool params and dedupes', () => {
    expect(parseTools({ tool: ['Bash', 'Read', 'Bash'] })).toEqual(['Bash', 'Read']);
    expect(parseTools({ tool: 'Bash' })).toEqual(['Bash']);
    expect(parseTools({})).toEqual([]);
  });

  it('reads repo and file as trimmed single values', () => {
    expect(parseRepo({ repo: ' acme/api ' })).toBe('acme/api');
    expect(parseFile({ file: 'src/a.ts' })).toBe('src/a.ts');
    expect(parseRepo({})).toBe('');
    expect(parseFile({})).toBe('');
  });
});

describe('buildFindingsParams', () => {
  const filters = { ...EMPTY_FILTERS, severity: ['critical'] };

  it('writes no view param for the default view', () => {
    const sp = buildFindingsParams(filters, '', '', { view: 'grouped' });
    expect(sp.has('view')).toBe(false);
    expect(sp.getAll('severity')).toEqual(['critical']);
  });

  it('writes the view param for the non-default views', () => {
    expect(buildFindingsParams(filters, '', '', { view: 'flat' }).get('view')).toBe('flat');
    expect(buildFindingsParams(filters, '', '', { view: 'files' }).get('view')).toBe('files');
  });

  it('drops tool/repo/file under the grouped view', () => {
    // The grouped read cannot honor per-instance filters, and writing a param
    // the page ignores leaves a link that reads as a filter which stopped
    // working.
    const sp = buildFindingsParams(filters, '', '', {
      view: 'grouped',
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(sp.has('tool')).toBe(false);
    expect(sp.has('repo')).toBe(false);
    expect(sp.has('file')).toBe(false);
  });

  it('keeps tool but drops repo/file under the locations view', () => {
    // The locations view IS the repo/file breakdown, so narrowing it to one
    // would leave a tree of exactly one node.
    const sp = buildFindingsParams(filters, '', '', {
      view: 'files',
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(sp.getAll('tool')).toEqual(['Bash']);
    expect(sp.has('repo')).toBe(false);
    expect(sp.has('file')).toBe(false);
  });

  it('keeps every instance filter under the flat view', () => {
    const sp = buildFindingsParams(filters, '', '', {
      view: 'flat',
      tools: ['Bash', 'Read'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(sp.getAll('tool')).toEqual(['Bash', 'Read']);
    expect(sp.get('repo')).toBe('acme/api');
    expect(sp.get('file')).toBe('a.ts');
  });

  it('round-trips the flat view through the parsers', () => {
    const sp = buildFindingsParams({ ...EMPTY_FILTERS, status: ['open'] }, ' leak ', 'sess-1', {
      view: 'flat',
      range: '30d',
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    // Back to the shape Next hands a page: a repeated key arrives as an array,
    // a single one as a string.
    const parsed: FindingsSearchParams = Object.fromEntries(
      [...new Set(sp.keys())].map((k) => {
        const all = sp.getAll(k);
        return [k, all.length > 1 ? all : all[0]];
      }),
    );

    expect(parseView(parsed)).toBe('flat');
    expect(parseRange(parsed)).toBe('30d');
    expect(parseTools(parsed)).toEqual(['Bash']);
    expect(parseRepo(parsed)).toBe('acme/api');
    expect(parseFile(parsed)).toBe('a.ts');
    expect(parseFindingsFilters(parsed).status).toEqual(['open']);
  });
});

describe('query builders', () => {
  const filters = { ...EMPTY_FILTERS, severity: ['critical'], status: ['open'] };

  it('grouped carries the time bound but no per-instance filter', () => {
    const q = toGroupedQuery(filters, 'leak', 'sess-1', {
      from: '2026-01-01T00:00:00.000Z',
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(q.from).toBe('2026-01-01T00:00:00.000Z');
    expect(q.sessionId).toBe('sess-1');
    expect(q.severity).toEqual(['critical']);
    // A group spans instances, so these have no meaning at this grain.
    expect('tool' in q).toBe(false);
    expect('repo' in q).toBe(false);
    expect('file' in q).toBe(false);
  });

  it('instances carries every filter', () => {
    const q = toInstancesQuery(filters, 'leak', 'sess-1', {
      from: '2026-01-01T00:00:00.000Z',
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(q.tool).toEqual(['Bash']);
    expect(q.repo).toBe('acme/api');
    expect(q.file).toBe('a.ts');
    expect(q.status).toEqual(['open']);
    expect(q.q).toBe('leak');
  });

  it('locations carries tool but not repo/file', () => {
    const q = toLocationsQuery(filters, '', '', {
      tools: ['Bash'],
      repo: 'acme/api',
      file: 'a.ts',
    });
    expect(q.tool).toEqual(['Bash']);
    expect('repo' in q).toBe(false);
    expect('file' in q).toBe(false);
  });

  it('omits every absent field rather than sending an empty one', () => {
    // exactOptionalPropertyTypes aside, an empty array reaching the store would
    // read as "filter to nothing" in a predicate built from `.length`.
    expect(toGroupedQuery(EMPTY_FILTERS, '', '')).toEqual({});
    expect(toInstancesQuery(EMPTY_FILTERS, '', '')).toEqual({});
    expect(toLocationsQuery(EMPTY_FILTERS, '', '')).toEqual({});
  });
});
