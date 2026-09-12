import { describe, expect, it } from 'vitest';

import type { FindingTypeSummary } from '../../src/zod/index.ts';
import {
  addToLocation,
  compareCodePoints,
  compareFindingGroupOrder,
  compareLocationOrder,
  createInstanceFacetAccumulator,
  encodeLocationId,
  type FacetTuple,
  type FlatFindingRow,
  foldFacetTuples,
  foldGroupStatus,
  matchesInstanceFilters,
  newLocationAccumulator,
  rowFromTuple,
  Severity,
  SEVERITY_RANK,
  sortFindingTypes,
  toInstanceDetail,
} from '../../src/zod/index.ts';

function row(over: Partial<FlatFindingRow> = {}): FlatFindingRow {
  return {
    id: 'f1',
    ruleId: 'aws-key',
    category: 'secret',
    severity: 'critical',
    maskedMatch: 'AKIA****',
    actionTaken: 'block',
    confidence: 0.9,
    occurredAt: '2026-01-02T00:00:00.000Z',
    sourceTool: 'claude-code',
    repo: 'acme/api',
    file: 'a.ts',
    eventId: 'e1',
    status: 'handled',
    ...over,
  };
}

describe('SEVERITY_RANK', () => {
  it('derives rank from Severity.options order', () => {
    expect(Severity.options.map((s) => SEVERITY_RANK[s])).toEqual([0, 1, 2, 3]);
  });
});

// SQLite's BINARY collation compares UTF-8 bytes, which for a well-formed
// string is the same order as comparing Unicode CODE POINTS — not the same as
// comparing UTF-16 code units, which is what JavaScript's `<` does.
describe('compareCodePoints', () => {
  // JavaScript's own comparison, behind a function so the contrast below is a
  // runtime check rather than something the compiler folds away.
  const utf16Less = (a: string, b: string): boolean => a < b;

  it('compares by Unicode code point rather than UTF-16 code unit', () => {
    // JavaScript's `<` compares UTF-16 code units: the astral character's
    // leading surrogate (U+D83D) is numerically BELOW the fullwidth
    // exclamation mark (U+FF01), so `<` puts the astral string first — the
    // opposite of code-point order, where U+1F600 > U+FF01.
    const astral = 'a\u{1F600}';
    const bmp = 'a！';
    expect(utf16Less(astral, bmp)).toBe(true); // the UTF-16 answer, for contrast
    expect(compareCodePoints(astral, bmp)).toBeGreaterThan(0);
  });

  it('returns 0 for identical strings and is antisymmetric', () => {
    expect(compareCodePoints('abc', 'abc')).toBe(0);
    expect(compareCodePoints('abc', 'abd')).toBeLessThan(0);
    expect(compareCodePoints('abd', 'abc')).toBeGreaterThan(0);
  });
});

describe('matchesInstanceFilters', () => {
  it('passes a row when no filter is set', () => {
    expect(matchesInstanceFilters(row(), {})).toBe(true);
  });

  it('matches severity, subtype, action and status on the row itself', () => {
    expect(matchesInstanceFilters(row(), { severity: ['critical'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { severity: ['low'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { subtype: ['aws-key'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { subtype: ['email'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { actions: ['blocked'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { actions: ['warned'] })).toBe(false);
    expect(matchesInstanceFilters(row(), { statuses: ['handled'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { statuses: ['open'] })).toBe(false);
  });

  it('maps the source tool through the shared provider mapper', () => {
    expect(matchesInstanceFilters(row(), { providers: ['claudecode'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { providers: ['cursor'] })).toBe(false);
  });

  it('treats provider api as the unknown-tool catch-all', () => {
    // 'api' is what an unmapped tool reads as, so it cannot be expressed as a
    // list of known tools — the case a SQL IN-predicate would get wrong.
    const unknown = row({ sourceTool: 'some-unmapped-tool' });
    expect(matchesInstanceFilters(unknown, { providers: ['api'] })).toBe(true);
    expect(matchesInstanceFilters(row(), { providers: ['api'] })).toBe(false);
  });

  it('matches tool, repo and file exactly', () => {
    const withTool = row({ toolName: 'Bash' });
    expect(matchesInstanceFilters(withTool, { tools: ['Bash'] })).toBe(true);
    expect(matchesInstanceFilters(withTool, { tools: ['Read'] })).toBe(false);
    // A row with no tool matches no tool filter.
    expect(matchesInstanceFilters(row(), { tools: ['Bash'] })).toBe(false);

    expect(matchesInstanceFilters(row(), { repo: 'acme/api' })).toBe(true);
    expect(matchesInstanceFilters(row(), { repo: 'acme/web' })).toBe(false);
    expect(matchesInstanceFilters(row(), { file: 'a.ts' })).toBe(true);
    expect(matchesInstanceFilters(row(), { file: 'b.ts' })).toBe(false);
  });

  it('treats an EMPTY repo or file filter as a filter, and only `undefined` as unset', () => {
    // This is the inversion of what the predicate used to do, and the reason is
    // that the no-repo/no-file bucket is a real location — usually the largest
    // one in a store — that the locations view has to be able to select.
    //
    // The claim the old behaviour rested on ("a URL cannot tell an absent param
    // from an empty one") is false: `?repo=` parses to '' where an absent one
    // parses to undefined. What collapsed them was our own parser, and the
    // selection rides its own `?loc=` param now precisely so a filter and a
    // selection are not the same key.
    //
    // Read as unset, an empty value dropped BOTH predicates, so the bucket's
    // panel returned the whole scope: a row saying 3 findings beside a panel
    // listing every finding in the store.
    expect(matchesInstanceFilters(row({ repo: 'acme/api' }), { repo: '' })).toBe(false);
    expect(matchesInstanceFilters(row({ repo: '' }), { repo: '' })).toBe(true);
    expect(matchesInstanceFilters(row({ file: 'a.ts' }), { file: '' })).toBe(false);
    expect(matchesInstanceFilters(row({ file: '' }), { file: '' })).toBe(true);

    // Unset is `undefined` alone, which is what every call site passes when it
    // means "every row" — the spread guards omit the key rather than emptying it.
    expect(matchesInstanceFilters(row({ repo: 'acme/api' }), { repo: undefined })).toBe(true);
    expect(matchesInstanceFilters(row({ file: 'a.ts' }), {})).toBe(true);
  });

  it('matches q over the rendered via-tool label, not the bare name', () => {
    const withTool = row({ toolName: 'Bash' });
    expect(matchesInstanceFilters(withTool, { q: 'via bash' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'AKIA' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'acme/api' })).toBe(true);
    expect(matchesInstanceFilters(withTool, { q: 'nothing-here' })).toBe(false);
  });

  it('matches q against the attributed user label', () => {
    const attributed = row({ user: { id: 'u1', name: 'Alice@example.com' } });
    expect(matchesInstanceFilters(attributed, { q: 'alice@' })).toBe(true);
    expect(matchesInstanceFilters(row(), { q: 'alice@' })).toBe(false);
  });

  it('ignores the named dimension when one is excepted', () => {
    const opts = { severity: ['low'], subtype: ['aws-key'] };
    expect(matchesInstanceFilters(row(), opts)).toBe(false);
    // Excepting the failing dimension passes, since the other still matches.
    expect(matchesInstanceFilters(row(), opts, 'severity')).toBe(true);
    // Excepting a different one does not rescue it.
    expect(matchesInstanceFilters(row(), opts, 'subtype')).toBe(false);
  });
});

describe('createInstanceFacetAccumulator', () => {
  it('counts instances per dimension', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', severity: 'critical' }));
    acc.add(row({ id: 'b', severity: 'low' }));
    acc.add(row({ id: 'c', severity: 'low' }));

    const facets = acc.facets();
    expect(Object.fromEntries(facets.severity.map((f) => [f.value, f.count]))).toEqual({
      critical: 1,
      low: 2,
    });
  });

  it('excludes each dimension own filter', () => {
    const acc = createInstanceFacetAccumulator({ severity: ['critical'] });
    acc.add(row({ id: 'a', severity: 'critical', sourceTool: 'claude-code' }));
    acc.add(row({ id: 'b', severity: 'low', sourceTool: 'cursor' }));

    const facets = acc.facets();
    // Severity ignores its own filter, so the low row is still counted —
    // that is what keeps "how many if I also pick low?" answerable.
    expect(Object.fromEntries(facets.severity.map((f) => [f.value, f.count]))).toEqual({
      critical: 1,
      low: 1,
    });
    // Every other dimension honors it, so the low row's provider is not.
    expect(Object.fromEntries(facets.provider.map((f) => [f.value, f.count]))).toEqual({
      claudecode: 1,
    });
  });

  it('counts no tool bucket for a row carrying none', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', toolName: 'Bash' }));
    acc.add(row({ id: 'b' }));
    expect(acc.facets().tool).toEqual([{ value: 'Bash', count: 1 }]);
  });

  it('orders each dimension by count, then value', () => {
    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', ruleId: 'b-rule' }));
    acc.add(row({ id: 'b', ruleId: 'a-rule' }));
    acc.add(row({ id: 'c', ruleId: 'a-rule' }));
    expect(acc.facets().subtype).toEqual([
      { value: 'a-rule', count: 2 },
      { value: 'b-rule', count: 1 },
    ]);
  });

  // localeCompare reports canonically-equivalent strings as equal, so a
  // count-tied pair of an NFC and an NFD spelling has no defined order under
  // it — which would differ between a streaming scan and a grouped SQL query.
  // compareCodePoints is a required fallback for a deterministic order.
  it('breaks a count tie between canonically-equivalent values by code point', () => {
    const nfc = 'café-rule'; // precomposed é
    const nfd = 'café-rule'; // decomposed e + combining acute accent
    // The control: they ARE different strings, and localeCompare alone
    // reports them equal — without compareCodePoints as a fallback, the tie
    // is unresolved and the order depends on Map iteration/insertion order.
    expect(nfc).not.toBe(nfd);
    expect(nfc.localeCompare(nfd)).toBe(0);

    const acc = createInstanceFacetAccumulator({});
    acc.add(row({ id: 'a', ruleId: nfc }));
    acc.add(row({ id: 'b', ruleId: nfd }));
    expect(acc.facets().subtype.map((f) => f.value)).toEqual([nfd, nfc]);
  });
});

describe('foldFacetTuples', () => {
  // Grouped tuples and the rows they stand for must produce identical numbers.
  // The oracle is the real row accumulator: expand every tuple back into its
  // rows, feed those through createInstanceFacetAccumulator, and count the
  // matching ones by hand. If the two ever disagree, a store that groups before
  // it counts would report different facets from one that counts row by row.
  const TUPLES: FacetTuple[] = [
    {
      severity: 'critical',
      ruleId: 'aws-key',
      sourceTool: 'claude-code',
      actionTaken: 'block',
      status: 'open',
      toolName: 'Bash',
      count: 3,
    },
    {
      severity: 'critical',
      ruleId: 'aws-key',
      sourceTool: 'cli',
      actionTaken: 'log',
      status: 'handled',
      count: 2,
    },
    {
      severity: 'low',
      ruleId: 'pii-email',
      sourceTool: 'codex',
      actionTaken: 'warn',
      status: 'open',
      toolName: 'Read',
      count: 5,
    },
    {
      severity: 'high',
      ruleId: 'pii-email',
      sourceTool: 'unknown-tool',
      actionTaken: 'redact',
      status: 'resolved',
      count: 1,
    },
  ];

  function oracle(tuples: readonly FacetTuple[], opts: Parameters<typeof foldFacetTuples>[1]) {
    const accumulator = createInstanceFacetAccumulator(opts);
    let total = 0;
    for (const tuple of tuples) {
      for (let i = 0; i < tuple.count; i += 1) {
        const expanded = rowFromTuple(tuple);
        accumulator.add(expanded);
        if (matchesInstanceFilters(expanded, opts)) total += 1;
      }
    }
    return { total, facets: accumulator.facets() };
  }

  it.each([
    ['no filters', {}],
    ['severity', { severity: ['critical'] }],
    ['provider, including the unmapped-tool bucket', { providers: ['api'] }],
    ['status', { statuses: ['open'] }],
    ['tool', { tools: ['Bash'] }],
    ['subtype', { subtype: ['pii-email'] }],
    [
      'three dimensions at once, so every facet excludes a live filter',
      { severity: ['critical'], providers: ['claudecode'], statuses: ['open'] },
    ],
    ['a filter nothing matches', { severity: ['medium'] }],
  ])('equals the row accumulator: %s', (_label, opts) => {
    expect(foldFacetTuples(TUPLES, opts)).toEqual(oracle(TUPLES, opts));
  });

  it('counts no tool bucket for a tuple carrying none', () => {
    const { facets } = foldFacetTuples(TUPLES, {});
    // 'unknown-tool' and 'cli' rows carry no toolName, so only Bash and Read
    // are counted — 3 and 5 — and the absent ones contribute to nothing.
    expect(facets.tool).toEqual([
      { value: 'Read', count: 5 },
      { value: 'Bash', count: 3 },
    ]);
  });

  it('maps raw source tools through the shared provider mapper before counting', () => {
    const { facets } = foldFacetTuples(TUPLES, {});
    // 'cli' and 'unknown-tool' are both unmapped, so they collapse into the one
    // miss bucket rather than appearing as two raw values.
    const api = facets.provider.find((f) => f.value === 'api');
    expect(api).toEqual({ value: 'api', count: 3 });
    expect(facets.provider.map((f) => f.value)).not.toContain('cli');
  });

  it('ignores repo, file and q, which a grouping caller applies before grouping', () => {
    // A tuple carries none of those fields, so a matcher that honoured them
    // would reject every tuple and report zero.
    const scoped = foldFacetTuples(TUPLES, { repo: 'acme/api', file: 'a.ts', q: 'nothing' });
    expect(scoped.total).toBe(11);
  });
});

describe('toInstanceDetail', () => {
  it('translates DB values through the shared mappers', () => {
    const detail = toInstanceDetail(row({ actionTaken: 'log', sourceTool: 'cursor' }));

    expect(detail.action).toBe('monitored');
    expect(detail.provider).toBe('cursor');
    expect(detail.groupId).toBe('aws-key');
    expect(detail.subtype).toBe('aws-key');
    expect(detail.match).toEqual({ maskedValue: 'AKIA****', contextPrefix: '' });
    // No pack names in the local store, and the policy is synthesized from the
    // category — the same shape the grouped path produces.
    expect(detail.detection).toEqual({ id: 'aws-key', name: null });
    expect(detail.policy).toEqual({ id: 'category:secret', name: 'secret' });
  });

  it('carries the event linkage and omits an absent session', () => {
    expect(toInstanceDetail(row({ sessionId: 's1' })).sessionId).toBe('s1');
    expect(toInstanceDetail(row()).sessionId).toBeUndefined();
    expect(toInstanceDetail(row()).eventId).toBe('e1');
  });

  it('carries the attributed user and omits an absent one', () => {
    const user = { id: 'u1', name: 'alice@example.com' };
    expect(toInstanceDetail(row({ user })).user).toEqual(user);
    expect(toInstanceDetail(row())).not.toHaveProperty('user');
  });
});

describe('compareFindingGroupOrder', () => {
  const group = (
    over: Partial<FindingTypeSummary>,
  ): Pick<FindingTypeSummary, 'severity' | 'latestDetectedAt' | 'id'> => ({
    severity: 'critical',
    latestDetectedAt: '2026-01-01T00:00:00.000Z',
    id: 'a',
    ...over,
  });

  it('orders by severity, then recency', () => {
    expect(
      compareFindingGroupOrder(group({ severity: 'critical' }), group({ severity: 'low' })),
    ).toBeLessThan(0);
    expect(
      compareFindingGroupOrder(
        group({ latestDetectedAt: '2026-01-02T00:00:00.000Z' }),
        group({ latestDetectedAt: '2026-01-01T00:00:00.000Z' }),
      ),
    ).toBeLessThan(0);
  });

  it('breaks a full tie on id, making the order total', () => {
    // Without this a cursor cannot resume: "everything after this group" is
    // ambiguous when two groups compare equal.
    expect(compareFindingGroupOrder(group({ id: 'a' }), group({ id: 'b' }))).toBeLessThan(0);
    expect(compareFindingGroupOrder(group({ id: 'b' }), group({ id: 'a' }))).toBeGreaterThan(0);
    expect(compareFindingGroupOrder(group({ id: 'a' }), group({ id: 'a' }))).toBe(0);
  });

  it('ranks an unknown severity below every known one', () => {
    // A garbage cursor decodes to this and therefore sorts before the list,
    // degrading to a restart from the top rather than skipping rows.
    expect(
      compareFindingGroupOrder(
        group({ severity: 'bogus' as FindingTypeSummary['severity'] }),
        group({ severity: 'low' }),
      ),
    ).toBeLessThan(0);
  });

  it('is the comparator sortFindingTypes uses', () => {
    const groups = [
      { severity: 'low', latestDetectedAt: '2026-01-03T00:00:00.000Z', id: 'x' },
      { severity: 'critical', latestDetectedAt: '2026-01-01T00:00:00.000Z', id: 'z' },
      { severity: 'critical', latestDetectedAt: '2026-01-01T00:00:00.000Z', id: 'y' },
    ] as FindingTypeSummary[];
    expect(sortFindingTypes(groups).map((g) => g.id)).toEqual(['y', 'z', 'x']);
  });
});

describe('location accumulator', () => {
  it('folds count, worst severity, latest time and rule ids', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ severity: 'low', occurredAt: '2026-01-01T00:00:00.000Z' }));
    addToLocation(
      acc,
      row({ severity: 'critical', occurredAt: '2026-01-03T00:00:00.000Z', ruleId: 'email' }),
    );

    expect(acc.instanceCount).toBe(2);
    expect(acc.maxSeverity).toBe('critical');
    expect(acc.latestDetectedAt).toBe('2026-01-03T00:00:00.000Z');
    expect([...acc.ruleIds]).toEqual(['aws-key', 'email']);
  });

  it('folds status with the same precedence a group uses', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ status: 'resolved' }));
    addToLocation(acc, row({ status: 'open' }));
    // open dominates — see foldGroupStatus.
    expect(foldGroupStatus(acc.statuses)).toBe('open');
  });

  it('does not let an unknown severity pin the location', () => {
    const acc = newLocationAccumulator();
    addToLocation(acc, row({ severity: 'not-a-severity' }));
    addToLocation(acc, row({ severity: 'high' }));
    expect(acc.maxSeverity).toBe('high');
  });
});

// The locations list is keyset-paged, so its order has to be TOTAL: a cursor
// resumes at "the first row strictly after this one", and two rows the
// comparator calls equal are two rows it can never get between.
describe('compareLocationOrder', () => {
  const loc = (over: Partial<Parameters<typeof compareLocationOrder>[0]> = {}) => ({
    maxSeverity: 'high',
    latestDetectedAt: '2026-01-02T00:00:00.000Z',
    repo: 'acme/api',
    file: 'a.ts',
    ...over,
  });

  it('puts the worst severity first, then the most recent', () => {
    expect(compareLocationOrder(loc({ maxSeverity: 'critical' }), loc())).toBeLessThan(0);
    expect(compareLocationOrder(loc({ maxSeverity: 'low' }), loc())).toBeGreaterThan(0);
    expect(
      compareLocationOrder(loc({ latestDetectedAt: '2026-01-03T00:00:00.000Z' }), loc()),
    ).toBeLessThan(0);
  });

  // The whole reason the pair is a sort key. Severity and instant genuinely
  // collide — two files touched by one capture share both — and with only those
  // two keys the comparator returns 0, which is what makes a page of tied rows
  // unreachable. Asserting `not.toBe(0)` is the property; the ordering below is
  // the consequence.
  it('never calls two DIFFERENT locations equal, however they tie', () => {
    const tied = { maxSeverity: 'critical', latestDetectedAt: '2026-01-01T00:00:00.000Z' };
    const a = loc({ ...tied, repo: 'acme/api', file: 'a.ts' });
    const b = loc({ ...tied, repo: 'acme/api', file: 'b.ts' });
    const c = loc({ ...tied, repo: 'acme/web', file: 'a.ts' });

    expect(compareLocationOrder(a, b)).not.toBe(0);
    expect(compareLocationOrder(a, c)).not.toBe(0);
    // repo is the third key and file the fourth, so a same-repo pair orders on
    // the file and a different-repo pair orders on the repo whatever the files.
    expect(compareLocationOrder(a, b)).toBeLessThan(0);
    expect(compareLocationOrder(a, c)).toBeLessThan(0);
    expect(compareLocationOrder(c, b)).toBeGreaterThan(0);

    // The identical location still compares 0 — a total order, not a strict one.
    expect(compareLocationOrder(a, loc({ ...tied, repo: 'acme/api', file: 'a.ts' }))).toBe(0);
  });

  // localeCompare is NOT interchangeable with `<` here, and this is the case
  // that shows it: ICU reports canonically-equivalent strings as equal, so a
  // precomposed and a decomposed 'café.ts' compare 0 and the tie is back. macOS
  // stores NFD where event metadata arrives NFC, so both spellings reach a real
  // store.
  it('separates canonically-equivalent paths, which a locale comparison would not', () => {
    const precomposed = 'caf\u00e9.ts';
    const decomposed = 'cafe\u0301.ts';
    // The control: the two ARE different strings, and a locale comparison would
    // still call them equal. Without this the case could pass on a runtime that
    // simply lacks ICU.
    expect(precomposed).not.toBe(decomposed);
    expect(precomposed.localeCompare(decomposed)).toBe(0);

    expect(compareLocationOrder(loc({ file: precomposed }), loc({ file: decomposed }))).not.toBe(0);
    expect(compareLocationOrder(loc({ repo: precomposed }), loc({ repo: decomposed }))).not.toBe(0);
  });

  // compareLocationOrder orders repo/file by compareCodePoints (matching
  // SQLite's BINARY collation over UTF-8), not by UTF-16 code-unit `<`. An
  // astral character's surrogate pair sorts BELOW U+E000–U+FFFF under `<`,
  // which is the wrong order for a store that will produce this ordering in
  // SQL.
  it('orders an astral file AFTER a BMP one tied on severity and instant, matching code-point order', () => {
    const tied = { maxSeverity: 'high', latestDetectedAt: '2026-01-01T00:00:00.000Z' };
    const astral = loc({ ...tied, repo: 'acme/api', file: 'a\u{1F600}' });
    const bmp = loc({ ...tied, repo: 'acme/api', file: 'a！' });
    // The UTF-16 code-unit comparison this replaces gets it backwards.
    expect(astral.file < bmp.file).toBe(true);
    expect(compareLocationOrder(astral, bmp)).toBeGreaterThan(0);
  });

  // The same property on the REPO half. It needs its own case: the pair above
  // shares a repo, so it exercises only the file comparison and a repo half
  // left on `<` would keep passing it.
  it('orders an astral repo AFTER a BMP one, matching code-point order', () => {
    const tied = { maxSeverity: 'high', latestDetectedAt: '2026-01-01T00:00:00.000Z' };
    const astral = loc({ ...tied, repo: 'acme/a\u{1F600}', file: 'a.ts' });
    const bmp = loc({ ...tied, repo: 'acme/a！', file: 'a.ts' });
    expect(astral.repo < bmp.repo).toBe(true);
    expect(compareLocationOrder(astral, bmp)).toBeGreaterThan(0);
  });

  // What makes an undecodable or hand-edited cursor degrade to a restart from
  // the top rather than to an empty page: every real row sorts AFTER a cursor
  // carrying an unknown severity, so the search for "the first row past it"
  // lands on index 0.
  it('ranks an unknown severity before every known one', () => {
    for (const known of ['critical', 'high', 'medium', 'low']) {
      expect(
        compareLocationOrder(loc({ maxSeverity: 'not-a-severity' }), loc({ maxSeverity: known })),
      ).toBeLessThan(0);
    }
  });
});

describe('encodeLocationId', () => {
  it('is stable, and distinct for every distinct pair', () => {
    expect(encodeLocationId('acme/api', 'a.ts')).toBe(encodeLocationId('acme/api', 'a.ts'));
    expect(encodeLocationId('acme/api', 'a.ts')).not.toBe(encodeLocationId('acme/api', 'b.ts'));
    expect(encodeLocationId('acme/api', 'a.ts')).not.toBe(encodeLocationId('acme/web', 'a.ts'));
  });

  // The pair is folded into one token, so the separator has to be unambiguous —
  // and both halves routinely CONTAIN it. Encoding each half is what keeps
  // ('a/b', 'c') and ('a', 'b/c') apart; concatenating them raw maps both to
  // 'a/b/c' and silently makes two locations one.
  it('keeps a slash inside either half from colliding with the separator', () => {
    expect(encodeLocationId('a/b', 'c')).not.toBe(encodeLocationId('a', 'b/c'));
  });

  // encodeURIComponent RAISES on a lone surrogate, and event metadata arrives as
  // JSON, where a `\uD800` escape parses into exactly that. Unhandled, one such
  // path takes out the whole locations read while it projects — not that row,
  // the entire page under every filter.
  it('survives a path carrying a lone surrogate, and keeps real astral characters', () => {
    const loneHigh = 'a\uD800b';
    const loneLow = 'a\uDC00b';
    // The control: these are the inputs the platform refuses, so a version that
    // stopped sanitising would throw here rather than quietly differing.
    expect(() => encodeURIComponent(loneHigh)).toThrow();
    expect(() => encodeURIComponent(loneLow)).toThrow();

    expect(() => encodeLocationId(loneHigh, 'c.ts')).not.toThrow();
    expect(() => encodeLocationId('acme/api', loneLow)).not.toThrow();

    // Sanitising is lossy only for the broken input. A VALID surrogate pair is a
    // real character and has to survive, or every emoji-bearing path would
    // collapse onto one id.
    expect(encodeLocationId('a😀b', 'c.ts')).not.toBe(encodeLocationId('a🚀b', 'c.ts'));
    expect(encodeLocationId('acme/api', 'c.ts')).toBe('acme%2Fapi/c.ts');
  });

  // The no-repo/no-file bucket is a real location and often the largest, so its
  // token has to be a token: something a URL carries and a reader can tell from
  // an absent param.
  it('mints a non-empty token for the empty pair', () => {
    const empty = encodeLocationId('', '');
    expect(empty).not.toBe('');
    expect(empty).not.toBe(encodeLocationId('', 'a.ts'));
    expect(empty).not.toBe(encodeLocationId('acme/api', ''));
  });
});
